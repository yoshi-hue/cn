"""Detector tests, including the one that states the project's hypothesis.

`test_lateral_movement_is_invisible_to_the_baseline` and its graph counterpart
are the pair that matter: together they assert, in a form that runs in
milliseconds, exactly the claim the whole semester's experiment is built to
test. If the baseline ever starts catching the lateral pattern, this test fails
and tells you the scenario has become too loud -- which is a scenario bug, not
a detector success.
"""

from lantern import config
from lantern.alerts import CLASS_BRUTEFORCE, CLASS_DOS, CLASS_LATERAL, CLASS_PORTSCAN
from lantern.detector_baseline import BaselineDetector
from lantern.detector_graph import GraphDetector
from lantern.graph_builder import GraphBuilder
from tests.conftest import TCP_SYN, build_window, record

WORKSTATION = "10.0.0.1"
ATTACKER = "10.0.0.4"
AUTH = "10.0.0.5"
SERVER = "10.0.0.10"


def classes(alerts):
    return {alert.attack_class for alert in alerts}


# ----------------------------------------------------------------------
# Baseline detector
# ----------------------------------------------------------------------


class TestBaselineDetector:
    def test_normal_traffic_raises_nothing(self):
        window = build_window(
            [
                record(WORKSTATION, SERVER, ts=1.0, port=80, packets=5),
                record(WORKSTATION, SERVER, ts=3.0, port=443, packets=4),
            ]
        )
        assert BaselineDetector().detect(window) == []

    def test_port_scan_over_many_ports_is_caught(self):
        window = build_window(
            [
                record(ATTACKER, SERVER, ts=i * 0.1, port=1000 + i, flags=TCP_SYN)
                for i in range(config.PORTSCAN_PORTS + 5)
            ]
        )
        alerts = BaselineDetector().detect(window)
        assert CLASS_PORTSCAN in classes(alerts)

    def test_dos_requires_sustained_rate_not_a_single_burst(self):
        """One busy window is a transfer; several in a row is an attack."""
        detector = BaselineDetector()
        packets = int(config.DOS_PPS * 20)

        first = build_window([record(ATTACKER, SERVER, ts=1.0, packets=packets)])
        assert classes(detector.detect(first)) == set()

        second = build_window([record(ATTACKER, SERVER, ts=1.0, packets=packets)])
        assert CLASS_DOS in classes(detector.detect(second))

    def test_dos_streak_resets_when_the_pair_goes_quiet(self):
        detector = BaselineDetector()
        loud = int(config.DOS_PPS * 20)

        detector.detect(build_window([record(ATTACKER, SERVER, ts=1.0, packets=loud)]))
        # A window in which the pair sends nothing at all.
        detector.detect(build_window([record(WORKSTATION, SERVER, ts=1.0, packets=2)]))
        alerts = detector.detect(
            build_window([record(ATTACKER, SERVER, ts=1.0, packets=loud)])
        )
        assert CLASS_DOS not in classes(alerts)

    def test_brute_force_on_an_auth_port_is_caught(self):
        window = build_window(
            [
                record(
                    ATTACKER,
                    AUTH,
                    ts=i * 0.05,
                    port=22,
                    flags=TCP_SYN,
                    src_port=40000 + i,
                )
                for i in range(config.BRUTEFORCE_ATTEMPTS + 10)
            ]
        )
        alerts = BaselineDetector().detect(window)
        assert CLASS_BRUTEFORCE in classes(alerts)

    def test_repeated_connections_to_a_non_auth_port_are_not_brute_force(self):
        window = build_window(
            [
                record(
                    WORKSTATION,
                    SERVER,
                    ts=i * 0.05,
                    port=80,
                    flags=TCP_SYN,
                    src_port=40000 + i,
                )
                for i in range(config.BRUTEFORCE_ATTEMPTS + 10)
            ]
        )
        assert CLASS_BRUTEFORCE not in classes(BaselineDetector().detect(window))


# ----------------------------------------------------------------------
# Graph detector
# ----------------------------------------------------------------------


def warm_up(detector, windows=None, ts_base=0.0):
    """Feed the detector a stable normal pattern until its profiles are ready.

    Normal here is deliberately narrow: each workstation talks only to the
    server, on its usual ports. That is what makes a host suddenly fanning out
    across its peers a departure from *its own* history.
    """
    windows = windows or config.PROFILE_WARMUP_WINDOWS + 4
    for index in range(windows):
        ts = ts_base + index * 0.5
        detector.detect(
            build_window(
                [
                    record(WORKSTATION, SERVER, ts=ts, port=80, packets=4),
                    record("10.0.0.2", SERVER, ts=ts + 0.1, port=443, packets=3),
                    record("10.0.0.3", SERVER, ts=ts + 0.2, port=80, packets=5),
                    record(ATTACKER, SERVER, ts=ts + 0.3, port=443, packets=3),
                ]
            )
        )


def lateral_window(ts=1.0):
    """Lateral movement: quiet, ordinary connections to unfamiliar hosts.

    Every individual flow here is unremarkable -- a couple of packets to a
    normal service port. Only the pattern across them is abnormal.
    """
    targets = [(WORKSTATION, 22), ("10.0.0.2", 445), ("10.0.0.3", 3389), (AUTH, 22)]
    return build_window(
        [
            record(ATTACKER, host, ts=ts + i * 0.4, port=port, packets=2, bytes_=140)
            for i, (host, port) in enumerate(targets)
        ]
    )


class TestGraphDetector:
    def test_nothing_is_scored_during_warmup(self):
        detector = GraphDetector(GraphBuilder())
        alerts = detector.detect(lateral_window())
        assert alerts == [], "scoring before a profile exists would alert on everything"

    def test_steady_normal_traffic_raises_nothing(self):
        detector = GraphDetector(GraphBuilder())
        warm_up(detector)
        alerts = detector.detect(
            build_window(
                [
                    record(WORKSTATION, SERVER, ts=1.0, port=80, packets=4),
                    record("10.0.0.2", SERVER, ts=1.2, port=443, packets=3),
                ]
            )
        )
        assert alerts == []

    def test_lateral_movement_is_detected(self):
        detector = GraphDetector(GraphBuilder())
        warm_up(detector)
        alerts = detector.detect(lateral_window())

        assert CLASS_LATERAL in classes(alerts)
        alert = next(a for a in alerts if a.attack_class == CLASS_LATERAL)
        assert alert.src_ip == ATTACKER
        assert alert.evidence["new_neighbour_ratio"] > 0.5
        assert alert.reason, "an alert an analyst cannot read cannot be acted on"

    def test_lateral_movement_is_invisible_to_the_baseline(self):
        """The hypothesis, stated as a test.

        The same traffic the graph detector flags above must pass the per-flow
        baseline untouched. If this ever fails, the lateral scenario has become
        too loud and the comparison is no longer testing what it claims to.
        """
        assert BaselineDetector().detect(lateral_window()) == []

    def test_a_host_is_scored_against_its_own_normal_not_a_global_threshold(self):
        """A server legitimately talks to everyone; that must not be an alert.

        This is the reason profiles are per-host. A global degree threshold
        would flag the busiest and most important machine in the network
        continuously, and an IDS that cries wolf about its own file server is
        not deployable.
        """
        detector = GraphDetector(GraphBuilder())
        for index in range(config.PROFILE_WARMUP_WINDOWS + 6):
            ts = index * 0.5
            detector.detect(
                build_window(
                    [
                        record(host, SERVER, ts=ts + i * 0.1, port=80, packets=4)
                        for i, host in enumerate(
                            [WORKSTATION, "10.0.0.2", "10.0.0.3", ATTACKER, AUTH]
                        )
                    ]
                )
            )
        alerts = detector.detect(
            build_window(
                [
                    record(host, SERVER, ts=i * 0.1, port=80, packets=4)
                    for i, host in enumerate(
                        [WORKSTATION, "10.0.0.2", "10.0.0.3", ATTACKER, AUTH]
                    )
                ]
            )
        )
        assert [a for a in alerts if a.src_ip == SERVER] == []

    def test_profile_is_committed_after_scoring_not_before(self):
        """An attack must not train the profile that is meant to catch it."""
        builder = GraphBuilder()
        detector = GraphDetector(builder)
        warm_up(detector)

        before = builder.profile_for(ATTACKER).seen_neighbours.copy()
        detector.detect(lateral_window())
        after = builder.profile_for(ATTACKER).seen_neighbours

        assert WORKSTATION not in before
        assert WORKSTATION in after, "the window should be folded in after scoring"


class TestBaselineIgnoresReplyTraffic:
    """A server answering many clients must not look like a scanner.

    Each reply is addressed to a different ephemeral client port, so counting
    reply traffic would flag the busiest and most important host in the network
    in every single window -- which is exactly what happened before the
    initiation distinction existed.
    """

    def test_a_server_replying_to_many_clients_is_not_a_port_scan(self):
        clients = ["10.0.0.%d" % n for n in range(1, 6)]
        replies = [
            record(
                SERVER, client, ts=i * 0.2, port=40000 + i * 137, is_initiation=False
            )
            for i, client in enumerate(clients * 6)
        ]
        window = build_window(replies)

        alerts = BaselineDetector().detect(window)
        assert [a for a in alerts if a.src_ip == SERVER] == []

    def test_a_real_scan_is_still_caught_alongside_reply_traffic(self):
        """The fix must not blunt the rule it protects."""
        scan = [
            record(ATTACKER, SERVER, ts=i * 0.05, port=1000 + i, flags=TCP_SYN)
            for i in range(config.PORTSCAN_PORTS + 5)
        ]
        replies = [
            record(SERVER, ATTACKER, ts=i * 0.05, port=40000 + i, is_initiation=False)
            for i in range(config.PORTSCAN_PORTS + 5)
        ]
        alerts = BaselineDetector().detect(build_window(scan + replies))

        flagged = {a.src_ip for a in alerts if a.attack_class == CLASS_PORTSCAN}
        assert ATTACKER in flagged
        assert SERVER not in flagged


class TestGraphDetectorDoesNotBlameVictims:
    """Being attacked must not make a host look like an attacker.

    The communication graph is undirected, so when an attacker contacts four
    machines, each of those machines also gains an unfamiliar neighbour. If the
    detector scored undirected neighbours, every victim would alert alongside
    the attacker -- and because mitigation blocks the host an alert names, the
    system would respond to an intrusion by cutting off the machines that were
    broken into. Hence the directional features.
    """

    def test_only_the_initiating_host_is_flagged(self):
        detector = GraphDetector(GraphBuilder())
        warm_up(detector)
        alerts = detector.detect(lateral_window())

        flagged = {a.src_ip for a in alerts}
        assert ATTACKER in flagged
        assert flagged == {
            ATTACKER
        }, "only the host that reached out should be flagged, got %s" % sorted(flagged)

    def test_a_host_that_only_receives_traffic_is_never_scored_up(self):
        detector = GraphDetector(GraphBuilder())
        warm_up(detector)
        detector.detect(lateral_window())

        # The victims' scores should stay far below the attacker's.
        attacker_score = detector.last_scores.get(ATTACKER, 0.0)
        for victim in (WORKSTATION, "10.0.0.2", "10.0.0.3", AUTH):
            assert detector.last_scores.get(victim, 0.0) < attacker_score


class TestClassificationIsStable:
    """The same evidence must always produce the same label.

    The classifier once keyed off whichever feature contributed most to the
    score. When two features were both pinned at the z-score clamp -- which is
    exactly what happens during lateral movement, where degree and port
    diversity both saturate -- the winner was arbitrary, and identical attacks
    were labelled inconsistently across runs. Since severity and the label
    together decide whether a host is blocked or just logged, that arbitrariness
    reached all the way to what the system does.
    """

    def test_lateral_movement_is_labelled_consistently_across_runs(self):
        labels = set()
        for _ in range(5):
            detector = GraphDetector(GraphBuilder())
            warm_up(detector)
            alerts = detector.detect(lateral_window())
            labels.update(a.attack_class for a in alerts if a.src_ip == ATTACKER)

        assert labels == {
            CLASS_LATERAL
        }, "identical evidence produced varying labels: %s" % sorted(labels)

    def test_an_anomaly_with_no_new_neighbours_is_not_called_lateral(self):
        """A host going loud against machines it always talks to has not moved."""
        detector = GraphDetector(GraphBuilder())
        warm_up(detector)

        # Same peer as always (the server), but a sudden burst of many ports.
        scan = build_window(
            [
                record(ATTACKER, SERVER, ts=i * 0.05, port=1000 + i, flags=TCP_SYN)
                for i in range(60)
            ]
        )
        alerts = [a for a in detector.detect(scan) if a.src_ip == ATTACKER]
        assert alerts, "a large structural change should still raise something"
        assert all(a.attack_class != CLASS_LATERAL for a in alerts)
