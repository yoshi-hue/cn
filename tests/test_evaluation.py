"""Regression tests for measurement validity rather than favorable outcomes."""

import json
from pathlib import Path
from types import SimpleNamespace
import networkx as nx
import pytest
from experiments.analyze import (
    coverage_rows,
    decision_timings,
    match_alert,
    score_run,
    wilson,
)
from experiments.campaign import container_command, ROOT
from experiments.run_all import plan
from experiments.run_case import reserve_run, monitor
from experiments.validation import validate_run
from lantern.detector_graph import GraphDetector
from lantern import config
from lantern.mitigation import MitigationEngine
from lantern.decision import Decision, ACTION_REDIRECT
from lantern.alerts import Alert


def test_matrix_and_paired_seeds():
    runs = plan()
    assert len(runs) == 95
    assert sum(r["phase"] == "mitigation" for r in runs) == 50
    for trial in range(1, 6):
        assert len({r["seed"] for r in runs if r["trial"] == trial}) == 1
    assert len({r["seed"] for r in runs}) == 5
    assert any(r["case"] == "C6" and r["mitigator"] == "graph" for r in runs)


def test_command_propagates_seed_warmup_and_config():
    cmd = container_command(
        dict(case="C1", warmup=145, seed=72),
        ROOT / "results/test",
        ROOT / "results/frozen.json",
    )
    assert cmd[cmd.index("--seed") + 1] == "72"
    assert cmd[cmd.index("--warmup") + 1] == "145"
    assert "LANTERN_CONFIG=results/frozen.json" in cmd


def test_reservation_preserves_existing_run(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RESULTS_RAW_DIR", str(tmp_path))
    reserve_run("C5", 1)
    with pytest.raises(FileExistsError):
        reserve_run("C5", 1)


def test_community_membership_is_label_independent():
    left = nx.Graph([("a", "b"), ("c", "d")])
    right = nx.Graph([("d", "c"), ("b", "a")])
    assert GraphDetector._communities(left) == GraphDetector._communities(right)
    assert GraphDetector._communities(left)["a"] == frozenset({"b"})


def test_ambiguous_window_is_not_credited():
    truths = [dict(src="a", t_start=10, t_end=12), dict(src="a", t_start=13, t_end=15)]
    alert = dict(src_ip="a", window_start_wall=10, window_end_wall=20)
    assert match_alert(alert, truths) is None
    assert match_alert(dict(alert, window_end_wall=13), truths) is truths[0]


def test_mitigation_and_invalid_runs_never_enter_headline():
    attack = dict(
        case="C5",
        attack_class="lateral",
        baseline_detected=False,
        graph_detected=True,
        baseline_class_exact=False,
        graph_class_exact=True,
        baseline_mttd=None,
        graph_mttd=1,
    )

    def result(mode, valid):
        return dict(
            identity=dict(phase="detection", mitigator=mode),
            validity=dict(valid=valid),
            attacks=[attack],
        )

    rows = coverage_rows(
        [result("none", True), result("graph", True), result("none", False)]
    )
    assert all(r["instances"] == 1 for r in rows)


def test_barrier_requires_correct_decision_and_all_switches():
    events = [
        dict(
            kind="mitigation_decided",
            decision_id="d",
            alert_id="a",
            detector="graph",
            action="drop_source",
            actuate=True,
            created_mono=1,
            decided_mono=2,
        ),
        dict(kind="mitigation_targeted", decision_id="d", switches=[1, 2]),
        dict(kind="barrier_reply", decision_id="other", dpid=2, mono=3, wall=30),
        dict(kind="barrier_reply", decision_id="d", dpid=1, mono=4, wall=40),
    ]
    assert decision_timings(events)[0]["decision_to_confirmation"] is None
    events.append(dict(kind="barrier_reply", decision_id="d", dpid=2, mono=5, wall=50))
    row = decision_timings(events)[0]
    assert row["decision_to_confirmation"] == 3
    assert row["alert_to_decision"] == 1


def test_missing_legacy_timestamps_stay_unavailable():
    events = [
        dict(
            kind="mitigation_decided",
            detector="graph",
            action="drop_source",
            actuate=True,
        )
    ]
    assert decision_timings(events)[0]["alert_to_decision"] is None


def test_redirect_cannot_silently_drop():
    engine = MitigationEngine(None, lambda: 0)
    alert = Alert("graph", "lateral", "a", 0, 0)
    with pytest.raises(ValueError, match="redirect"):
        engine.apply(Decision(alert, ACTION_REDIRECT, "test", True))


def test_expiry_removes_active_match():
    engine = MitigationEngine(None, lambda: 0)
    rule = SimpleNamespace(
        dpid=1, cookie=42, active=True, decision_id="d", to_dict=lambda: {"cookie": 42}
    )
    engine.installed = [rule]
    assert engine.blocked_matches()
    engine.handle_flow_removed(
        SimpleNamespace(datapath=SimpleNamespace(id=1), cookie=42)
    )
    assert engine.blocked_matches() == []


def test_monitor_fails_on_controller_exit():
    with pytest.raises(RuntimeError, match="controller"):
        monitor(1, SimpleNamespace(process=SimpleNamespace(poll=lambda: 1)), None)


def test_invalid_run_cannot_be_scored_as_detector_miss(tmp_path):
    path = tmp_path / "C1_trial01.jsonl"
    path.write_text(
        json.dumps(dict(kind="run_start", schema_version=2, mitigator="none")) + "\n"
    )
    assert not validate_run(path)["valid"]
    assert not score_run(
        dict(log=str(path), truth=str(tmp_path / "absent"), case="C1", trial=1)
    )["validity"]["valid"]


def test_false_positive_denominator_uses_unique_benign_host_windows(tmp_path):
    path = tmp_path / "C1_trial01.jsonl"
    events = [
        dict(kind="run_start", schema_version=2, mitigator="none"),
        dict(
            kind="detector_timing",
            warming_up=False,
            wall=20,
            window_index=1,
            window_start_wall=10,
            window_end_wall=20,
            eligible_hosts=["a", "b"],
        ),
    ]
    events += [
        dict(
            kind="detector_candidate",
            detector="graph",
            src_ip="a",
            window_index=1,
            attack_class="graph_anomaly",
            window_start_wall=10,
            window_end_wall=20,
            wall=20,
        )
        for _ in range(2)
    ]
    path.write_text("".join(json.dumps(e) + "\n" for e in events))
    path.with_suffix(".validity.json").write_text('{"valid":true,"reasons":[]}')
    result = score_run(
        dict(log=str(path), truth=str(tmp_path / "absent"), case="C1", trial=1)
    )
    graph = next(r for r in result["detections"] if r["detector"] == "graph")
    assert graph["false_positive_host_windows"] == 1
    assert graph["benign_host_windows"] == 2
    assert graph["false_positive_rate"] == 0.5


def test_wilson_does_not_imply_certainty_for_small_perfect_sample():
    low, high = wilson(5, 5)
    assert 0.5 < low < 0.6 and high == 1


def test_background_process_failure_is_fatal():
    from experiments.runner import Workload

    workload = Workload(None, "C1", 1)
    workload.processes = [SimpleNamespace(poll=lambda: 1, returncode=1)]
    with pytest.raises(RuntimeError, match="background"):
        workload.assert_alive()


def test_normal_workload_is_indefinite_and_carries_variation_arguments(
    tmp_path, monkeypatch
):
    from experiments.runner import Workload

    commands = []
    host = SimpleNamespace(popen=lambda command, **kwargs: commands.append(command))
    net = SimpleNamespace(get=lambda _: host)
    monkeypatch.setattr(config, "RESULTS_RAW_DIR", str(tmp_path))
    workload = Workload(net, "C1", 1)
    workload.start_normal(
        0, hosts=["h1"], seed=31, peer_after=135, rate_switch_after=435
    )
    command = commands[0]
    assert command[command.index("--duration") + 1] == "0"
    assert command[command.index("--peer-after") + 1] == "135"
    assert command[command.index("--rate-switch-after") + 1] == "435"
    for handle in workload._log_handles:
        handle.close()


def test_attack_error_is_returned_to_run_validity():
    from experiments.runner import Workload

    process = SimpleNamespace(
        poll=lambda: 7, communicate=lambda: (b"failed", b""), returncode=7
    )
    net = SimpleNamespace(get=lambda _: SimpleNamespace(popen=lambda *a, **kw: process))
    assert Workload(net, "C5", 1).run_attack("traffic/attacks/lateral.py") == 7


def test_analysis_handles_empty_campaign_without_plot_failure(tmp_path):
    from experiments.analyze import analyze

    assert analyze(tmp_path / "missing", tmp_path / "tables") == []
    assert (tmp_path / "tables" / "validity.csv").exists()


def test_curation_source_verification_needs_no_docker(tmp_path, monkeypatch):
    from experiments import campaign

    (tmp_path / "manifest.json").write_text(
        json.dumps({"source_hash": campaign.source_hash(), "image_id": "unused"})
    )

    def unexpected(*args, **kwargs):
        raise AssertionError("offline evidence curation must not call Docker")

    monkeypatch.setattr(campaign, "command_output", unexpected)
    campaign.verify_source(tmp_path, check_image=False)


def test_aborted_truth_is_reported_without_crashing(tmp_path):
    path = tmp_path / "C5_trial01.jsonl"
    path.write_text(json.dumps({"kind": "run_end"}) + "\n")
    path.with_name(path.stem + "_truth.jsonl").write_text(
        json.dumps({"aborted": True, "first_send": None}) + "\n"
    )
    result = validate_run(path, expected_attacks=1)
    assert not result["valid"]
    assert "missing, empty, or aborted attack truth" in result["reasons"]


def test_mitigation_inactivity_before_second_attack_is_not_failed_profiling(tmp_path):
    path = tmp_path / "C6_trial01.jsonl"
    source = config.HOST_TO_IP[config.ATTACKER]
    events = [
        {"kind": "run_end"},
        {"kind": "switch_connected", "dpid": 1},
        {"kind": "switch_connected", "dpid": 2},
        {
            "kind": "detector_timing",
            "wall": 10,
            "warming_up": False,
            "eligible_hosts": [source],
        },
        {
            "kind": "detector_timing",
            "wall": 30,
            "warming_up": False,
            "eligible_hosts": [],
        },
    ]
    path.write_text("".join(json.dumps(e) + "\n" for e in events))
    truths = [
        {"src": source, "first_send": 11, "last_send": 20},
        {"src": source, "first_send": 31, "last_send": 40},
    ]
    path.with_name(path.stem + "_truth.jsonl").write_text(
        "".join(json.dumps(t) + "\n" for t in truths)
    )
    for name in list(config.WORKSTATIONS) + [config.ATTACKER]:
        path.with_name(path.stem + "_probe_" + name + ".jsonl").write_text(
            '{"success":true}\n'
        )
    for name in config.HOSTS:
        path.with_name(path.stem + "_receiver_" + name + ".jsonl").write_text("{}\n")
    assert validate_run(path, expected_attacks=2)["valid"]
