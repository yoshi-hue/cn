"""Collection-layer tests.

The counter-diffing tests matter more than they look: a flow-statistics counter
is cumulative, so a subtraction bug here would silently multiply every packet
rate the detectors see, and every threshold in the project would then be tuned
around a wrong number.
"""

from lantern.features import FlowStatsDiffer, WindowAggregator
from tests.conftest import TCP_SYN, record


class TestFlowStatsDiffer:
    def test_first_observation_is_its_own_delta(self):
        differ = FlowStatsDiffer()
        assert differ.diff(1, "flow-a", packets=10, bytes_=640) == (10, 640)

    def test_subsequent_observations_are_differenced(self):
        differ = FlowStatsDiffer()
        differ.diff(1, "flow-a", packets=10, bytes_=640, duration=1.0)
        assert differ.diff(1, "flow-a", packets=25, bytes_=1600, duration=2.0) == (
            15,
            960,
        )

    def test_evicted_and_recreated_entry_does_not_go_negative(self):
        """An idle-timed-out entry that reappears restarts its counters at zero.

        A naive subtraction would report a large negative delta here, which
        would then be silently discarded and lose real traffic.
        """
        differ = FlowStatsDiffer()
        differ.diff(1, "flow-a", packets=100, bytes_=6400, duration=30.0)
        delta = differ.diff(1, "flow-a", packets=5, bytes_=320, duration=0.5)
        assert delta == (5, 320)

    def test_entries_are_keyed_per_switch(self):
        differ = FlowStatsDiffer()
        differ.diff(1, "flow-a", packets=10, bytes_=640)
        assert differ.diff(2, "flow-a", packets=7, bytes_=448) == (7, 448)

    def test_forget_drops_the_remembered_counter(self):
        differ = FlowStatsDiffer()
        differ.diff(1, "flow-a", packets=10, bytes_=640)
        differ.forget(1, "flow-a")
        assert differ.diff(1, "flow-a", packets=3, bytes_=192) == (3, 192)


class TestWindowAggregator:
    def test_records_are_bucketed_by_absolute_time(self):
        aggregator = WindowAggregator(window_seconds=10.0, epoch=0.0)
        aggregator.add(record("10.0.0.1", "10.0.0.2", ts=1.0))
        aggregator.add(record("10.0.0.1", "10.0.0.2", ts=11.0))
        closed = aggregator.close_due(now=25.0)
        assert [w.index for w in closed] == [0, 1]

    def test_open_window_is_not_closed_early(self):
        aggregator = WindowAggregator(window_seconds=10.0, epoch=0.0)
        aggregator.add(record("10.0.0.1", "10.0.0.2", ts=5.0))
        assert aggregator.close_due(now=9.0) == []

    def test_late_record_for_a_closed_window_is_rejected(self):
        """A record arriving after its window was scored must not be counted.

        Counting it would silently change a result that has already been
        reported, which is worse than losing the record.
        """
        aggregator = WindowAggregator(window_seconds=10.0, epoch=0.0)
        aggregator.add(record("10.0.0.1", "10.0.0.2", ts=1.0))
        aggregator.close_due(now=15.0)
        assert aggregator.add(record("10.0.0.1", "10.0.0.2", ts=2.0)) is False

    def test_pair_and_host_stats_accumulate(self, make_window):
        window = make_window(
            [
                record("10.0.0.4", "10.0.0.1", ts=1.0, port=22, packets=3, bytes_=200),
                record("10.0.0.4", "10.0.0.1", ts=2.0, port=80, packets=2, bytes_=100),
                record("10.0.0.4", "10.0.0.2", ts=3.0, port=443, packets=1, bytes_=60),
            ]
        )
        host = window.hosts["10.0.0.4"]
        assert host.packets == 6
        assert host.bytes == 360
        assert host.dst_hosts == {"10.0.0.1", "10.0.0.2"}
        assert host.dst_ports == {22, 80, 443}

        pair = window.pairs[("10.0.0.4", "10.0.0.1")]
        assert pair.packets == 5
        assert pair.dst_ports == {22, 80}

    def test_active_hosts_includes_destinations(self, make_window):
        window = make_window([record("10.0.0.4", "10.0.0.9", ts=1.0)])
        assert window.active_hosts() == {"10.0.0.4", "10.0.0.9"}

    def test_syns_to_auth_ports_are_counted(self, make_window):
        window = make_window(
            [
                record(
                    "10.0.0.4",
                    "10.0.0.5",
                    ts=float(i) * 0.1,
                    port=22,
                    flags=TCP_SYN,
                    src_port=40000 + i,
                )
                for i in range(30)
            ]
        )
        assert window.hosts["10.0.0.4"].auth_attempts["10.0.0.5"] == 30
