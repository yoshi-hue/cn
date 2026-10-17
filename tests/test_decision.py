"""Decision-manager tests.

The actuation-gating tests guard the experiment's validity rather than the
code's correctness: if both detectors could install drop rules during a
comparison run, the faster one would delete the evidence the other needed and
the whole baseline-versus-graph result would be an artefact.
"""

import pytest

from lantern import config
from lantern.alerts import (
    CLASS_BRUTEFORCE,
    CLASS_LATERAL,
    CLASS_PORTSCAN,
    DETECTOR_BASELINE,
    DETECTOR_GRAPH,
    Alert,
)
from lantern.decision import (
    ACTION_DROP_PAIR,
    ACTION_DROP_SOURCE,
    AlertManager,
)


def alert(
    detector=DETECTOR_BASELINE,
    attack_class=CLASS_PORTSCAN,
    src="10.0.0.4",
    dst=None,
    ts=0.0,
    port=None,
    protocol=None,
):
    return Alert(
        detector=detector,
        attack_class=attack_class,
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        protocol=protocol,
        ts=ts,
        window_index=int(ts // config.WINDOW_SECONDS),
    )


class TestActuationGating:
    @pytest.mark.parametrize(
        "mode,detector,expected",
        [
            ("none", DETECTOR_BASELINE, False),
            ("none", DETECTOR_GRAPH, False),
            ("both", DETECTOR_BASELINE, True),
            ("both", DETECTOR_GRAPH, True),
            ("graph", DETECTOR_GRAPH, True),
            ("graph", DETECTOR_BASELINE, False),
            ("baseline", DETECTOR_BASELINE, True),
            ("baseline", DETECTOR_GRAPH, False),
        ],
    )
    def test_only_the_nominated_detector_actuates(self, mode, detector, expected):
        manager = AlertManager(mitigator=mode)
        assert manager.may_actuate(detector) is expected

    def test_comparison_runs_still_record_every_alert(self):
        """Mode "none" must suppress *actuation*, never detection.

        The comparison depends on both detectors' alerts being recorded in full
        while neither is allowed to change the traffic.
        """
        manager = AlertManager(mitigator="none")
        decisions = manager.submit(
            [
                alert(detector=DETECTOR_BASELINE, ts=1.0),
                alert(detector=DETECTOR_GRAPH, attack_class=CLASS_LATERAL, ts=1.0),
            ]
        )
        assert len(decisions) == 2
        assert all(d.actuate is False for d in decisions)

    def test_an_unknown_mode_is_rejected_loudly(self):
        with pytest.raises(ValueError):
            AlertManager(mitigator="whatever")


class TestCooldown:
    def test_a_continuing_event_produces_one_alert_not_many(self):
        manager = AlertManager(mitigator="none")
        first = manager.submit([alert(ts=0.0)])
        second = manager.submit([alert(ts=config.ALERT_COOLDOWN_SECONDS / 2)])

        assert len(first) == 1
        assert second == []
        assert manager.suppressed_count == 1

    def test_the_event_can_alert_again_once_the_cooldown_lapses(self):
        manager = AlertManager(mitigator="none")
        manager.submit([alert(ts=0.0)])
        later = manager.submit([alert(ts=config.ALERT_COOLDOWN_SECONDS + 1)])
        assert len(later) == 1

    def test_cooldown_is_per_detector_and_per_class(self):
        """Two detectors seeing the same host must both be recorded.

        Sharing a cooldown across detectors would let whichever fired first
        silence the other, which is the same confounder as shared actuation.
        """
        manager = AlertManager(mitigator="none")
        decisions = manager.submit(
            [
                alert(detector=DETECTOR_BASELINE, attack_class=CLASS_PORTSCAN, ts=0.0),
                alert(detector=DETECTOR_GRAPH, attack_class=CLASS_LATERAL, ts=0.0),
                alert(
                    detector=DETECTOR_BASELINE,
                    attack_class=CLASS_BRUTEFORCE,
                    dst="10.0.0.5",
                    ts=0.0,
                ),
            ]
        )
        assert len(decisions) == 3

    def test_different_sources_do_not_share_a_cooldown(self):
        manager = AlertManager(mitigator="none")
        decisions = manager.submit(
            [alert(src="10.0.0.4", ts=0.0), alert(src="10.0.0.7", ts=0.0)]
        )
        assert len(decisions) == 2


class TestActionChoice:
    def test_source_implicating_behaviour_blocks_the_source(self):
        manager = AlertManager(mitigator="baseline")
        decision = manager.submit([alert(attack_class=CLASS_PORTSCAN, ts=0.0)])[0]
        assert decision.action == ACTION_DROP_SOURCE

    def test_lateral_movement_blocks_the_source(self):
        manager = AlertManager(mitigator="graph")
        decision = manager.submit(
            [alert(detector=DETECTOR_GRAPH, attack_class=CLASS_LATERAL, ts=0.0)]
        )[0]
        assert decision.action == ACTION_DROP_SOURCE
        assert decision.actuate is True

    def test_an_attack_naming_a_victim_blocks_only_that_pair(self):
        """Containment should be proportionate.

        Blocking the source outright for a brute-force attempt would also cut
        off every legitimate service that host uses, which is exactly what the
        legitimate-traffic disruption metric penalises.
        """
        manager = AlertManager(mitigator="baseline")
        decision = manager.submit(
            [
                alert(
                    attack_class=CLASS_BRUTEFORCE,
                    dst="10.0.0.5",
                    port=22,
                    protocol=6,
                    ts=0.0,
                )
            ]
        )[0]
        assert decision.action == ACTION_DROP_PAIR
