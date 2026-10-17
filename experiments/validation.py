"""Run integrity checks independent of detector accuracy."""

import json
from pathlib import Path
from lantern import config


def read_events(path):
    with open(path) as handle:
        return [json.loads(line) for line in handle if line.strip()]


def receiver_healthy(observations):
    return any(e.get("ready") and e.get("iface")
               and sum(e.get("health_counts", {}).values()) == 5
               for e in observations)


def validate_run(log, expected_attacks=0):
    reasons = []
    path = Path(log)
    try:
        events = read_events(path)
        truth_path = path.with_name(path.stem + "_truth.jsonl")
        truths = read_events(truth_path) if truth_path.exists() else []
    except (OSError, ValueError) as exc:
        return {"valid": False, "reasons": ["unreadable event log: " + str(exc)]}
    if not any(e["kind"] == "run_end" for e in events):
        reasons.append("missing controller shutdown record")
    switches = {e["dpid"] for e in events if e["kind"] == "switch_connected"}
    if len(switches) != len(config.SWITCHES):
        reasons.append("incomplete switch connections")
    if len(truths) != expected_attacks or any(
        t.get("aborted") or not t.get("first_send") for t in truths
    ):
        reasons.append("missing, empty, or aborted attack truth")
    timings = [
        e for e in events if e["kind"] == "detector_timing" and not e.get("warming_up")
    ]
    if not timings:
        reasons.append("no post-warmup scoring windows")
    if truths:
        # Later attacks may be stopped by a prior block. Inactivity after that
        # block is not failure to learn the source's initial normal profile.
        checked_sources = set()
        for t in sorted(
            truths, key=lambda item: item.get("first_send") or float("inf")
        ):
            if not t.get("first_send") or t.get("src") in checked_sources:
                continue
            checked_sources.add(t.get("src"))
            prior = [e for e in timings if e["wall"] <= t["first_send"]]
            if not prior or t["src"] not in prior[-1].get("eligible_hosts", []):
                reasons.append("attacker profile not ready before attack")
    for name in list(config.WORKSTATIONS) + [config.ATTACKER]:
        probes = path.with_name(path.stem + "_probe_" + name + ".jsonl")
        if not probes.exists() or not any(
            p.get("success") for p in read_events(probes)
        ):
            reasons.append("no successful service probe from " + name)
    meta_path = path.with_suffix(".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    for name in config.HOSTS:
        receiver = path.with_name(path.stem + "_receiver_" + name + ".jsonl")
        if not receiver.exists() or not read_events(receiver):
            reasons.append("missing receiver observations for " + name)
        elif meta.get("measurement_protocol_version", 1) >= 2:
            rows = read_events(receiver)
            if not receiver_healthy(rows) or any(
                not e.get("ready") or e.get("iface") != name + "-eth0" for e in rows
            ):
                reasons.append("unhealthy receiver capture for " + name)
    return {
        "valid": not reasons,
        "reasons": reasons,
        "expected_attacks": expected_attacks,
        "observed_attacks": len(truths),
        "scoring_windows": len(timings),
    }
