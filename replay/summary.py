"""Headline aggregates computed directly from the published submission tables.

Shared by the replay overview and the supplementary PDF report so both show
identical numbers. Nothing here is re-measured or re-tuned.
"""

import statistics

ATTACKS = ["portscan", "dos", "bruteforce", "lateral"]
DETECTORS = ["baseline", "graph"]
NAMES = {"portscan": "Port scan", "dos": "DoS", "bruteforce": "SYN retry",
         "lateral": "Sequential contact"}


def _row(rows, **match):
    return next(r for r in rows if all(r.get(k) == v for k, v in match.items()))


def _float(value):
    return float(value) if value not in ("", None) else None


def _stats(values):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return {"n": len(values), "mean": statistics.mean(values),
            "median": statistics.median(values), "min": min(values), "max": max(values)}


def overview(tables, thresholds=None):
    coverage = tables["coverage"]
    primary = {}
    for attack in ATTACKS:
        for det in DETECTORS:
            r = _row(coverage, phase="detection", cohort="primary", attack_class=attack, detector=det)
            primary["%s|%s" % (attack, det)] = {
                "detected": int(r["detected"]), "instances": int(r["instances"]),
                "class_exact": int(r["class_exact"]),
                "wilson_low": float(r["wilson_low"]), "wilson_high": float(r["wilson_high"]),
                "mttd_mean": _float(r["mttd_mean"])}

    false_positives = {}
    for phase in ("detection", "benign", "order"):
        for det in DETECTORS:
            rows = [r for r in tables["detections"] if r["phase"] == phase and r["detector"] == det]
            total = lambda key: sum(int(r[key]) for r in rows)
            false_positives["%s|%s" % (phase, det)] = {
                "flagged": total("false_positive_host_windows"),
                "eligible": total("benign_host_windows"),
                "candidates": total("candidate_alerts"), "alerts": total("operational_alerts"),
                "matched": total("matched_candidates"), "ambiguous": total("ambiguous_candidates"),
                "unmatched": total("unmatched_candidates")}

    mitigation = {}
    for det in DETECTORS:
        rows = [r for r in tables["containment"] if r["phase"] == "mitigation" and r["mitigator"] == det]
        delays = [_float(r["rule_confirmation_delay"]) for r in rows]
        mitigation[det] = {"records": len(rows), "runs": len({r["run"] for r in rows}),
                           "confirmed": sum(d is not None for d in delays),
                           "verified": sum(r["observed_blocking"] == "verified" and r.get("measurement_protocol_version") == "2" for r in rows),
                           "testable": sum(r.get("testable") == "True" for r in rows),
                           "outcomes": {outcome: sum(r.get("blocking_outcome") == outcome for r in rows)
                                        for outcome in sorted({r.get("blocking_outcome") for r in rows if r.get("blocking_outcome")})},
                           "legacy_counter_evidence": sum(r["observed_blocking"] == "verified" and r.get("measurement_protocol_version") != "2" for r in rows),
                           "receiver_evidence_available": bool(rows) and all(r.get("receiver_evidence_available") == "True" for r in rows),
                           "delay": _stats(delays)}

    # Per attack type: every record stays in the denominator; outcomes come from the published table.
    blocking = {}
    for det in DETECTORS:
        for attack in ATTACKS + ["all"]:
            rows = [r for r in tables["containment"] if r["phase"] == "mitigation" and r["mitigator"] == det
                    and (attack == "all" or r["attack_class"] == attack)]
            outcome = lambda name: sum(r.get("blocking_outcome") == name for r in rows)
            blocking["%s|%s" % (det, attack)] = {
                "records": len(rows), "testable": sum(r.get("testable") == "True" for r in rows),
                "verified": sum(r["observed_blocking"] == "verified" and r.get("measurement_protocol_version") == "2" for r in rows),
                "leakage": outcome("observed_leakage"), "no_confirmation": outcome("no_confirmation"),
                "insufficient_drops": outcome("insufficient_drop_evidence")}

    order = {}
    for r in coverage:
        if r["phase"] == "order":
            order["%s|%s" % (r["attack_class"], r["detector"])] = {
                "detected": int(r["detected"]), "instances": int(r["instances"]), "class_exact": int(r["class_exact"])}

    delivery = {}
    for det in DETECTORS:
        for group in ("innocent", "compromised"):
            for period in ("attack", "recovery"):
                rows = [r for r in tables["disruption"] if r["phase"] == "mitigation"
                        and r["mitigator"] == det and r["group"] == group and r["period"] == period]
                delivery["%s|%s|%s" % (det, group, period)] = {
                    "attempts": sum(int(r["attempts"]) for r in rows),
                    "successes": sum(int(r["successes"]) for r in rows)}

    rows = [r for r in tables["overhead"] if r["phase"] == "detection" and r["period"] == "evaluation"]
    per_run = lambda key, scale=1: _stats([_float(r[key]) * scale if r[key] else None for r in rows])
    cost = {"cpu_percent": per_run("cpu_percent_mean"),
            "rss_mib": per_run("rss_bytes_mean", 1 / 1048576),
            "baseline_ms": per_run("baseline_seconds_mean", 1000),
            "graph_ms": per_run("graph_total_seconds_mean", 1000),
            "graph_build_ms": per_run("graph_build_seconds_mean", 1000),
            "betweenness_ms": per_run("betweenness_seconds_mean", 1000),
            "peak_entries": _stats([float(r["peak_total_entries"]) for r in rows])}

    timing = {}
    for r in tables["timing_summary"]:
        if r["phase"] == "mitigation" and r["case"] in ("C3", "C5"):
            timing["%s|%s|%s" % (r["case"], r["mitigator"], r["metric"])] = {
                "n": int(r["n"]), "mean_ms": None if r["n"] == "0" else float(r["mean"]) * 1000}

    validity = tables["validity"]
    return {"names": NAMES, "attacks": ATTACKS, "primary": primary,
            "false_positives": false_positives, "mitigation": mitigation,
            "blocking": blocking, "order": order,
            "delivery": delivery, "cost": cost, "timing": timing,
            "thresholds": thresholds or {},
            "validity": {"valid": sum(r["valid"] == "True" for r in validity),
                         "runs": len(validity)}}
