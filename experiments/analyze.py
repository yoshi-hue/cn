"""Derive evaluation tables from immutable logs; never mix experimental phases."""

import argparse
from collections import defaultdict
import csv
import json
import math
from pathlib import Path
import statistics
from experiments.validation import read_events
from lantern import config

DETECTORS = ("baseline", "graph")


def load_events(path):
    return read_events(path)


def discover_runs(directory):
    runs = []
    for path in sorted(Path(directory).rglob("*_trial*.jsonl")):
        tail = path.stem.split("_trial")[-1]
        if not tail.isdigit():
            continue
        case = path.stem.split("_trial")[0]
        runs.append(
            dict(
                case=case,
                run_id=str(path.relative_to(directory).with_suffix("")),
                trial=int(tail),
                log=str(path),
                truth=str(path.with_name(path.stem + "_truth.jsonl")),
            )
        )
    return runs


def wilson(hits, total):
    if not total:
        return None, None
    z = 1.959963984540054
    p = hits / total
    center = (p + z * z / (2 * total)) / (1 + z * z / total)
    half = (
        z
        * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
        / (1 + z * z / total)
    )
    return max(0, center - half), min(1, center + half)


def stats(values):
    values = [v for v in values if v is not None]
    return dict(
        n=len(values),
        mean=statistics.mean(values) if values else None,
        median=statistics.median(values) if values else None,
        minimum=min(values) if values else None,
        maximum=max(values) if values else None,
    )


def attack_interval(truth):
    return (
        truth.get("first_send") or truth["t_start"],
        truth.get("last_send") or truth["t_end"],
    )


def matching_truths(alert, truths):
    """Source and observed-window overlap; ambiguity is retained, never guessed."""
    src = alert.get("src_ip")
    start, end = alert.get("window_start_wall"), alert.get("window_end_wall")
    if start is None or end is None:
        # Legacy events cannot provide window attribution. Retain old timestamp
        # matching for exploratory evidence only and label the schema legacy.
        wall = alert.get("wall", 0)
        return [
            t
            for t in truths
            if t.get("src") == src
            and t["t_start"] <= wall <= t["t_end"] + config.WINDOW_SECONDS
        ]
    return [
        t
        for t in truths
        if t.get("src") == src
        and start <= attack_interval(t)[1]
        and end > attack_interval(t)[0]
    ]


def match_alert(alert, truths, class_exact=False):
    matches = matching_truths(alert, truths)
    if len(matches) != 1:
        return None
    match = matches[0]
    return (
        match
        if not class_exact or match["attack_class"] == alert["attack_class"]
        else None
    )


def decision_timings(events):
    targeted = {
        e["decision_id"]: e for e in events if e["kind"] == "mitigation_targeted"
    }
    barriers = defaultdict(dict)
    for e in events:
        if e["kind"] == "barrier_reply" and e.get("decision_id"):
            barriers[e["decision_id"]][e["dpid"]] = e
    rows = []
    for e in events:
        if e["kind"] != "mitigation_decided":
            continue
        key = e.get("decision_id")
        required = targeted.get(key, {}).get("switches", [])
        replies = barriers.get(key, {})
        complete = bool(required) and all(s in replies for s in required)
        confirmed = (
            max((replies[s]["mono"] for s in required), default=None)
            if complete
            else None
        )
        confirmed_wall = (
            max((replies[s]["wall"] for s in required), default=None)
            if complete
            else None
        )
        rows.append(
            dict(
                decision_id=key,
                alert_id=e.get("alert_id"),
                detector=e["detector"],
                action=e["action"],
                actuate=e["actuate"],
                src=e.get("src_ip"),
                alert_to_decision=(
                    (e["decided_mono"] - e["created_mono"])
                    if "decided_mono" in e and "created_mono" in e
                    else None
                ),
                decision_to_confirmation=(
                    (confirmed - e["decided_mono"]) if confirmed is not None else None
                ),
                all_switches_confirmed=complete,
                confirmation_wall=confirmed_wall,
                confirmed_switches=len(replies),
                required_switches=len(required),
            )
        )
    return rows


def blocking_assessment(truth, confirm, cookies, events, receivers):
    """Protocol 2 verdict; legacy campaign CSVs retain their original analysis."""
    from experiments.validation import receiver_healthy

    targets = truth.get("targets", [])
    healthy = bool(targets) and all(
        receiver_healthy([e for e in receivers if e.get("dst") == target])
        for target in targets
    )
    end = attack_interval(truth)[1]
    remaining = end - confirm if confirm is not None else None
    result = dict(receiver_evidence_available=healthy,
                  post_confirmation_seconds=remaining, testable=False,
                  drop_counter_increased=False, blocking_outcome="no_confirmation")
    if confirm is None:
        return result
    if remaining < 3:
        result["blocking_outcome"] = "insufficient_post_confirmation_traffic"
        return result
    if not healthy:
        result["blocking_outcome"] = "unavailable_receiver_evidence"
        return result
    observations = [[e for e in receivers if e.get("dst") == target
                     and confirm + 1 <= e["wall"] <= end]
                    for target in targets]
    if any(len(rows) < 2 for rows in observations):
        result["blocking_outcome"] = "unavailable_receiver_evidence"
        return result
    result["testable"] = True
    counters = {}
    increased = False
    for event in sorted(events, key=lambda e: e.get("wall", 0)):
        if event.get("kind") != "resource_sample" or event["wall"] > end:
            continue
        for dpid, table in event.get("flow_tables", {}).items():
            for drop in table.get("drops", []):
                if drop["cookie"] not in cookies:
                    continue
                key = (dpid, drop["cookie"])
                count = drop["packets"]
                if event["wall"] >= confirm and count > counters.get(key, 0):
                    increased = True
                counters[key] = count
    result["drop_counter_increased"] = increased
    leaking = any(
        max(e["counts"].get(truth["src"], 0) for e in rows)
        != min(e["counts"].get(truth["src"], 0) for e in rows)
        for rows in observations
    )
    result["blocking_outcome"] = (
        "observed_leakage" if leaking else "verified" if increased
        else "insufficient_drop_evidence"
    )
    return result


def score_run(run):
    path = Path(run["log"])
    events = read_events(path)
    truth_path = Path(run["truth"])
    truths = read_events(truth_path) if truth_path.exists() else []
    meta_path = path.with_suffix(".meta.json")
    validity_path = path.with_suffix(".validity.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    validity = (
        json.loads(validity_path.read_text())
        if validity_path.exists()
        else {
            "valid": True,
            "reasons": ["legacy: integrity not independently validated"],
        }
    )
    start = next((e for e in events if e["kind"] == "run_start"), {})
    legacy = start.get("schema_version", 1) < 2
    if not legacy and not validity_path.exists():
        validity = {"valid": False, "reasons": ["missing validity report"]}
    phase = meta.get(
        "phase", "detection" if start.get("mitigator") == "none" else "mitigation"
    )
    identity = dict(
        case=meta.get("case", run["case"]),
        trial=run["trial"],
        phase=phase,
        mitigator=start.get("mitigator", "unknown"),
        run=run.get("run_id", path.stem),
    )
    candidates = [
        e for e in events if e["kind"] == ("alert" if legacy else "detector_candidate")
    ]
    timings = [
        e
        for e in events
        if e["kind"] == "detector_timing"
        and not e.get("warming_up")
        and e.get("complete_window", True)
        and (not meta or e["wall"] >= meta.get("evaluation_start", float("inf")))
    ]
    eligible_indices = {e["window_index"] for e in timings if "window_index" in e}
    if not legacy:
        candidates = [
            e
            for e in candidates
            if not e.get("warming_up") and e["window_index"] in eligible_indices
        ]
    attacks = []
    for index, truth in enumerate(truths):
        row = dict(
            identity,
            attack_id=truth.get("attack_id", str(index)),
            attack_class=truth["attack_class"],
            src=truth["src"],
        )
        for detector in DETECTORS:
            hits = [
                a
                for a in candidates
                if a["detector"] == detector and match_alert(a, truths) is truth
            ]
            first = (
                min(hits, key=lambda a: a.get("created_wall", a["wall"]))
                if hits
                else None
            )
            row[detector + "_detected"] = bool(hits)
            row[detector + "_class_exact"] = any(
                a["attack_class"] == truth["attack_class"] for a in hits
            )
            row[detector + "_mttd"] = (
                max(
                    0,
                    first.get("created_wall", first["wall"])
                    - attack_interval(truth)[0],
                )
                if first
                else None
            )
        attacks.append(row)
    detections = []
    for detector in DETECTORS:
        alerts = [a for a in candidates if a["detector"] == detector]
        matched = sum(len(matching_truths(a, truths)) == 1 for a in alerts)
        ambiguous = sum(len(matching_truths(a, truths)) > 1 for a in alerts)
        benign = set()
        if not legacy:
            for w in timings:
                for host in w.get("eligible_hosts", []):
                    event = dict(
                        src_ip=host,
                        window_start_wall=w["window_start_wall"],
                        window_end_wall=w["window_end_wall"],
                    )
                    if not matching_truths(event, truths):
                        benign.add((host, w["window_index"]))
        fp = {
            (a["src_ip"], a["window_index"])
            for a in alerts
            if (a["src_ip"], a["window_index"]) in benign
        }
        detections.append(
            dict(
                identity,
                detector=detector,
                attacks=len(truths),
                detected=sum(a[detector + "_detected"] for a in attacks),
                class_exact=sum(a[detector + "_class_exact"] for a in attacks),
                candidate_alerts=len(alerts),
                matched_candidates=matched,
                ambiguous_candidates=ambiguous,
                unmatched_candidates=len(alerts) - matched - ambiguous,
                candidate_precision=(
                    matched / (len(alerts) - ambiguous)
                    if len(alerts) > ambiguous
                    else None
                ),
                operational_alerts=sum(
                    e["kind"] == "alert" and e.get("detector") == detector
                    for e in events
                ),
                benign_host_windows=len(benign) if not legacy else None,
                false_positive_host_windows=len(fp) if not legacy else None,
                false_positive_rate=len(fp) / len(benign) if benign else None,
            )
        )
    probes = []
    for probe_path in path.parent.glob(path.stem + "_probe_*.jsonl"):
        probes += read_events(probe_path)
    disruption = []
    for group in ["innocent", "compromised"]:
        for period in [
            "pre_attack",
            "attack",
            "between_attacks",
            "observation",
            "recovery",
        ]:
            selected = []
            for p in probes:
                g = (
                    "compromised"
                    if p["src"] == config.HOST_TO_IP[config.ATTACKER]
                    else "innocent"
                )
                active = any(
                    attack_interval(t)[0] <= p["wall"] <= attack_interval(t)[1]
                    for t in truths
                )
                first_attack = min(
                    (attack_interval(t)[0] for t in truths),
                    default=meta.get("evaluation_start", 0),
                )
                if active:
                    per = "attack"
                elif p["wall"] >= meta.get("recovery_start", float("inf")):
                    per = "recovery"
                elif p["wall"] < first_attack:
                    per = "pre_attack"
                else:
                    per = "between_attacks" if truths else "observation"
                # Restrict pre-attack to final 30 seconds before evaluation.
                if p["wall"] < meta.get("evaluation_start", 0) - 30:
                    continue
                if g == group and per == period:
                    selected.append(p)
            successes = sum(p["success"] for p in selected)
            disruption.append(
                dict(
                    identity,
                    group=group,
                    period=period,
                    attempts=len(selected),
                    successes=successes,
                    failure_rate=1 - successes / len(selected) if selected else None,
                    mean_success_latency=stats(
                        [p["latency"] for p in selected if p["success"]]
                    )["mean"],
                )
            )
    timing_rows = [dict(identity, **r) for r in decision_timings(events)]
    receivers = []
    for receiver_path in path.parent.glob(path.stem + "_receiver_*.jsonl"):
        receivers += read_events(receiver_path)
    containment = []
    for truth in truths:
        matching_alert_ids = {
            a.get("alert_id") for a in candidates if match_alert(a, truths) is truth
        }
        confirmations = [
            r
            for r in timing_rows
            if r["alert_id"] in matching_alert_ids and r["all_switches_confirmed"]
        ]
        confirm = min((r["confirmation_wall"] for r in confirmations), default=None)
        # Require >=3s of ongoing malicious sends after confirmation, receiver
        # silence over >=2 samples, and a positive matching rule drop count.
        verified = False
        if confirm and attack_interval(truth)[1] - confirm >= 3:
            cookies = {
                e["cookie"]
                for e in events
                if e["kind"] == "flowmod_sent"
                and e.get("alert_id") in matching_alert_ids
            }
            samples = [
                e
                for e in events
                if e["kind"] == "resource_sample"
                and confirm <= e["wall"] <= attack_interval(truth)[1]
            ]
            dropped = any(
                d["cookie"] in cookies and d["packets"] > 0
                for e in samples
                for table in e.get("flow_tables", {}).values()
                for d in table.get("drops", [])
            )
            quiet = True
            for target in truth.get("targets", []):
                observations = sorted(
                    [
                        e
                        for e in receivers
                        if e["dst"] == target
                        and confirm + 1 <= e["wall"] <= attack_interval(truth)[1]
                    ],
                    key=lambda e: e["wall"],
                )
                if len(observations) < 2 or observations[-1]["counts"].get(
                    truth["src"], 0
                ) != observations[0]["counts"].get(truth["src"], 0):
                    quiet = False
            verified = dropped and quiet
        containment.append(
            dict(
                identity,
                attack_id=truth.get("attack_id"),
                attack_class=truth["attack_class"],
                rule_confirmation_delay=(
                    confirm - attack_interval(truth)[0] if confirm else None
                ),
                observed_blocking="verified" if verified else "unverified",
            )
        )
        if meta.get("measurement_protocol_version", 1) >= 2:
            cookies = {e["cookie"] for e in events if e["kind"] == "flowmod_sent"
                       and e.get("alert_id") in matching_alert_ids}
            assessment = blocking_assessment(truth, confirm, cookies, events, receivers)
            containment[-1]["observed_blocking"] = (
                "verified" if assessment["blocking_outcome"] == "verified" else "unverified"
            )
            containment[-1].update(assessment)
            containment[-1]["measurement_protocol_version"] = 2
    resources = [e for e in events if e["kind"] == "resource_sample"]
    overhead = []
    for period in ["warmup", "evaluation"]:
        selected = [
            e
            for e in resources
            if (e["wall"] < meta.get("evaluation_start", 0)) == (period == "warmup")
        ]
        ts = [
            e
            for e in events
            if e["kind"] == "detector_timing"
            and bool(e.get("warming_up")) == (period == "warmup")
        ]
        row = dict(identity, period=period)
        for key in [
            "cpu_percent",
            "rss_bytes",
            "packet_in_count",
            "flow_stats_requests",
            "flow_stats_replies",
        ]:
            for metric, value in stats([e.get(key) for e in selected]).items():
                row[key + "_" + metric] = value
        for key in [
            "baseline_seconds",
            "graph_total_seconds",
            "graph_build_seconds",
            "betweenness_seconds",
        ]:
            for metric, value in stats([e.get(key) for e in ts]).items():
                row[key + "_" + metric] = value
        for key in ["total", "forwarding", "mitigation"]:
            row["peak_" + key + "_entries"] = max(
                [
                    sum(t[key] for t in e.get("flow_tables", {}).values())
                    for e in selected
                ]
                or [0]
            )
        baseline_mean = row.get("baseline_seconds_mean")
        graph_mean = row.get("graph_total_seconds_mean")
        row["graph_cost_ratio"] = graph_mean / baseline_mean if baseline_mean else None
        overhead.append(row)
    return dict(
        identity=identity,
        validity=validity,
        legacy=legacy,
        attacks=attacks,
        detections=detections,
        disruption=disruption,
        timing=timing_rows,
        containment=containment,
        overhead=overhead,
        installation=[
            dict(
                identity,
                dpid=e["dpid"],
                cookie=e["cookie"],
                flowmod_to_confirmation=e.get("install_latency"),
            )
            for e in events
            if e["kind"] == "barrier_reply"
        ],
    )


def write_csv(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def coverage_rows(results):
    groups = defaultdict(list)
    for r in results:
        if not r["validity"]["valid"] or r["identity"]["mitigator"] != "none":
            continue
        phase = r["identity"]["phase"]
        if phase not in ("detection", "order"):
            continue
        for attack in r["attacks"]:
            cohort = (
                "primary" if attack["case"] in ("C2", "C3", "C4", "C5") else "mixed"
            )
            groups[(phase, cohort, attack["attack_class"])].append(attack)
            if phase == "detection":
                groups[(phase, "pooled", attack["attack_class"])].append(attack)
    rows = []
    for (phase, cohort, attack_class), attacks in sorted(groups.items()):
        for detector in DETECTORS:
            hits = sum(a[detector + "_detected"] for a in attacks)
            low, high = wilson(hits, len(attacks))
            row = dict(
                phase=phase,
                cohort=cohort,
                attack_class=attack_class,
                detector=detector,
                detected=hits,
                instances=len(attacks),
                coverage=hits / len(attacks),
                wilson_low=low,
                wilson_high=high,
                class_exact=sum(a[detector + "_class_exact"] for a in attacks),
            )
            row.update(
                {
                    "mttd_" + k: v
                    for k, v in stats([a[detector + "_mttd"] for a in attacks]).items()
                }
            )
            rows.append(row)
    return rows


def analyze(raw, output):
    results = [score_run(r) for r in discover_runs(raw)]
    output = Path(output)
    write_csv(
        output / "validity.csv",
        [
            dict(
                r["identity"],
                valid=r["validity"]["valid"],
                legacy=r["legacy"],
                reasons="; ".join(r["validity"]["reasons"]),
            )
            for r in results
        ],
    )
    valid = [r for r in results if r["validity"]["valid"]]
    for key in [
        "attacks",
        "detections",
        "disruption",
        "timing",
        "installation",
        "containment",
        "overhead",
    ]:
        write_csv(output / (key + ".csv"), [row for r in valid for row in r[key]])
    measured = [row for r in valid for row in r["containment"]
                if row.get("measurement_protocol_version") == 2 and row["phase"] == "mitigation"]
    if measured:
        groups = defaultdict(list)
        for row in measured:
            groups[(row["mitigator"], row["attack_class"])].append(row)
            groups[(row["mitigator"], "all")].append(row)
        write_csv(output / "blocking_summary.csv", [
            dict(mitigator=key[0], attack_class=key[1], records=len(rows),
                 testable=sum(r["testable"] for r in rows),
                 verified=sum(r["blocking_outcome"] == "verified" for r in rows),
                 observed_leakage=sum(r["blocking_outcome"] == "observed_leakage" for r in rows),
                 no_confirmation=sum(r["blocking_outcome"] == "no_confirmation" for r in rows),
                 insufficient_post_confirmation_traffic=sum(r["blocking_outcome"] == "insufficient_post_confirmation_traffic" for r in rows),
                 unavailable_receiver_evidence=sum(r["blocking_outcome"] == "unavailable_receiver_evidence" for r in rows),
                 insufficient_drop_evidence=sum(r["blocking_outcome"] == "insufficient_drop_evidence" for r in rows))
            for key, rows in sorted(groups.items())
        ])
    coverage = coverage_rows(valid)
    write_csv(output / "coverage.csv", coverage)
    evidence = [
        dict(
            result_table="coverage.csv",
            phase=row["phase"],
            cohort=row["cohort"],
            attack_class=row["attack_class"],
            detector=row["detector"],
            runs=";".join(
                sorted(
                    {
                        a["run"]
                        for r in valid
                        for a in r["attacks"]
                        if a["phase"] == row["phase"]
                        and a["mitigator"] == "none"
                        and a["attack_class"] == row["attack_class"]
                        and (
                            row["cohort"] == "pooled"
                            or (a["case"] in ("C2", "C3", "C4", "C5"))
                            == (row["cohort"] == "primary")
                        )
                    }
                )
            ),
        )
        for row in coverage
    ]
    write_csv(output / "evidence_map.csv", evidence)
    # Each run-level table retains its run ID; aggregate timing with per-trial
    # means so frequent alerts do not give a trial disproportionate weight.
    summary = []
    for key, metric in [
        ("timing", "alert_to_decision"),
        ("timing", "decision_to_confirmation"),
        ("installation", "flowmod_to_confirmation"),
    ]:
        groups = defaultdict(list)
        for r in valid:
            mean = stats([row.get(metric) for row in r[key]])["mean"]
            identity = r["identity"]
            groups[(identity["phase"], identity["case"], identity["mitigator"])].append(
                mean
            )
        for group, values in groups.items():
            summary.append(
                dict(
                    phase=group[0],
                    case=group[1],
                    mitigator=group[2],
                    metric=metric,
                    **stats(values),
                )
            )
    write_csv(output / "timing_summary.csv", summary)
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        primary = [r for r in coverage if r["cohort"] == "primary"]
        fig, ax = plt.subplots(figsize=(8, 4))
        classes = sorted({r["attack_class"] for r in primary})
        for i, detector in enumerate(DETECTORS):
            values = [
                next(
                    (
                        r["coverage"]
                        for r in primary
                        if r["attack_class"] == c and r["detector"] == detector
                    ),
                    0,
                )
                for c in classes
            ]
            ax.bar(
                [x + (i - 0.5) * 0.35 for x in range(len(classes))],
                values,
                width=0.35,
                label=detector,
            )
        ax.set_xticks(range(len(classes)))
        ax.set_xticklabels(classes)
        ax.set_ylabel("Attacker identification coverage")
        ax.set_ylim(0, 1.05)
        if classes:
            ax.legend()
        fig.tight_layout()
        fig.savefig(output / "coverage.png", dpi=150)
        plt.close(fig)
        costs = [
            r
            for result in valid
            for r in result["overhead"]
            if r["period"] == "evaluation"
        ]
        values = [
            [r[key] * 1000 for r in costs if r.get(key) is not None]
            for key in ["baseline_seconds_mean", "graph_total_seconds_mean"]
        ]
        if all(values):
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.boxplot(values, labels=DETECTORS)
            ax.set_yscale("log")
            ax.set_ylabel("Per-run mean detector time (ms)")
            fig.tight_layout()
            fig.savefig(output / "detector_cost.png", dpi=150)
            plt.close(fig)
    except ImportError:
        pass
    return results


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--raw", default=config.RESULTS_RAW_DIR)
    parser.add_argument("--output", default="results/analysis")
    args = parser.parse_args()
    results = analyze(args.raw, args.output)
    print(
        json.dumps(
            dict(runs=len(results), valid=sum(r["validity"]["valid"] for r in results))
        )
    )


if __name__ == "__main__":
    main()
