"""Deterministic evidence conversion. Never reconstruct unrecorded traffic."""

import csv
import hashlib
import json
import math
from pathlib import Path
import shutil

from .summary import overview

ASSETS = Path(__file__).parent / "assets"
TOPOLOGY = {
    "hosts": [
        {"id": "h1", "ip": "10.0.0.1", "switch": "s1", "role": "workstation"},
        {"id": "h2", "ip": "10.0.0.2", "switch": "s1", "role": "workstation"},
        {"id": "h3", "ip": "10.0.0.3", "switch": "s1", "role": "workstation"},
        {"id": "h4", "ip": "10.0.0.4", "switch": "s2", "role": "attack source"},
        {"id": "h5", "ip": "10.0.0.5", "switch": "s2", "role": "auth service host"},
        {"id": "server", "ip": "10.0.0.10", "switch": "s2", "role": "HTTP service"},
    ],
    "switches": ["s1", "s2"],
    "links": [["s1", "s2"]],
}
# Default evidence: the repaired campaign (working receivers). The historical
# 2026-09-22 campaign stays in submission/ and can be replayed with --submission.
DEFAULT_SUBMISSION = "submission-repaired-20261012"
# (title, phase, case, actuator, trial). Graph mitigation uses trial 2: trial 1
# is the one lateral record whose graph block came late and was not verified.
CHAPTERS = [
    ("Source versus class", "detection", "C5", "none", 1),
    ("Baseline mitigation", "mitigation", "C5", "baseline", 1),
    ("Graph mitigation", "mitigation", "C5", "graph", 2),
    ("Legitimate change", "benign", "C1", "none", 1),
    ("Attack order", "order", "C7", "none", 1),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_file(root, relative):
    root = root.resolve()
    path = root / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("Unsafe evidence path")
    if path.is_symlink() or root not in path.resolve().parents or not path.is_file():
        raise ValueError("Missing or unsafe evidence file: " + relative)
    return path


def verify_evidence(root):
    root = Path(root).resolve()
    expected = json.loads((root / "checksums.json").read_text())
    actual = {str(p.relative_to(root)) for p in root.rglob("*")
              if p.is_file() and p != root / "checksums.json"}
    if actual != set(expected):
        raise ValueError("Curated evidence inventory does not match checksums")
    for name, checksum in sorted(expected.items()):
        if digest(safe_file(root, name)) != checksum:
            raise ValueError("Curated checksum mismatch: " + name)
    return expected


def read_jsonl(path):
    rows = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise ValueError("Malformed evidence: %s:%d" % (path.name, number)) from exc
        if not isinstance(row, dict):
            raise ValueError("Expected event object: " + path.name)
        rows.append((number, row))
    return rows


def number(value):
    if value is None or value == "":
        return None
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (ValueError, TypeError):
        return None


def relative(wall, start):
    n = number(wall)
    return None if n is None else round(n - start, 6)


def truth_matches(event, truths):
    start = number(event.get("window_start_wall"))
    end = number(event.get("window_end_wall"))
    if start is None or end is None:
        return None  # No legacy timestamp inference in this viewer.
    return [t.get("attack_id") for t in truths
            if event.get("src_ip") == t.get("src")
            and number(t.get("first_send")) is not None
            and number(t.get("last_send")) is not None
            and start <= t["last_send"] and end > t["first_send"]]


def complete_confirmations(events):
    """Only the relevant decision's complete targeted switch set counts."""
    targets = {e.get("decision_id"): set(e.get("switches", []))
               for e in events if e.get("kind") == "mitigation_targeted"}
    actuating = {e.get("decision_id") for e in events
                 if e.get("kind") == "mitigation_decided" and e.get("actuate")}
    replies = {}
    complete = {}
    for e in events:
        if e.get("kind") != "barrier_reply":
            continue
        decision = e.get("decision_id")
        required = targets.get(decision, set())
        if decision not in actuating or not required or e.get("dpid") not in required:
            continue
        replies.setdefault(decision, {})[e["dpid"]] = e
        if decision not in complete and required <= replies[decision].keys():
            selected = [replies[decision][s] for s in required]
            walls = [number(r.get("wall")) for r in selected]
            if all(w is not None for w in walls):
                complete[decision] = {"kind": "all_switches_confirmed",
                    "wall": max(walls), "decision_id": decision,
                    "alert_id": e.get("alert_id"), "switches": sorted(required)}
    return list(complete.values())


def convert_run(root, log, tables):
    root = Path(root)
    stem = log.stem
    meta_path = log.with_suffix(".meta.json")
    validity_path = log.with_suffix(".validity.json")
    meta = json.loads(meta_path.read_text())
    validity = json.loads(validity_path.read_text())
    if not validity.get("valid"):
        raise ValueError("Invalid run cannot be replayed: " + stem)
    records = read_jsonl(log)
    raw = [r for _, r in records]
    starts = [r for r in raw if r.get("kind") == "run_start"]
    ends = [r for r in raw if r.get("kind") == "run_end"]
    if len(starts) != 1 or len(ends) != 1 or number(starts[0].get("wall")) is None:
        raise ValueError("Incomplete run: " + stem)
    start = starts[0]["wall"]
    duration = relative(ends[0].get("wall"), start)
    if duration is None or duration <= 0:
        raise ValueError("Missing run end timestamp: " + stem)
    run = str(log.relative_to(root / "evidence").with_suffix(""))
    truth_path = log.with_name(stem + "_truth.jsonl")
    if not truth_path.exists() and validity.get("expected_attacks", 0):
        raise ValueError("Missing truth record: " + stem)
    truth_records = read_jsonl(truth_path) if truth_path.exists() else []
    truths = [t for _, t in truth_records]
    summary = {name: [r for r in rows if r.get("run") == run]
               for name, rows in tables.items() if any(r.get("run") == run for r in rows)}
    events = []
    refs = set()

    def append(row, source, line=None):
        kind = row.get("kind", "unknown")
        wall, clock = row.get("wall"), "recorded event time"
        if kind in ("detector_candidate", "alert") and number(row.get("created_wall")) is not None:
            wall, clock = row["created_wall"], "actual alert creation"
        elif kind == "mitigation_decided" and number(row.get("decided_wall")) is not None:
            wall, clock = row["decided_wall"], "actual decision time"
        ref = str(source.relative_to(root))
        refs.add(ref)
        event = {"kind": kind, "time": relative(wall, start), "clock": clock,
                 "source": ref, "line": line, "data": row}
        if kind in ("detector_candidate", "alert"):
            matches = truth_matches(row, truths)
            event["attribution"] = ("unavailable" if matches is None else
                "ambiguous" if len(matches) > 1 else "matched" if matches else "unmatched")
            event["attack_ids"] = matches
        events.append(event)

    for line, row in records:
        append(row, log, line)
    for row in complete_confirmations(raw):
        append(row, log)
        events[-1]["clock"] = "derived from correlated switch replies"
    for line, truth in truth_records:
        for label, field in [("attack_started", "first_send"), ("attack_ended", "last_send")]:
            append(dict(truth, kind=label, wall=truth.get(field)), truth_path, line)
    for path in sorted(log.parent.glob(stem + "_*.jsonl")):
        if path == truth_path:
            continue
        if "_probe_" in path.name or "_receiver_" in path.name:
            for line, row in read_jsonl(path):
                append(row, path, line)
    for row in summary.get("containment", []):
        append({"kind": "blocking_assessment", "wall": ends[0]["wall"],
                **row, "blocking_outcome": row.get("blocking_outcome", "unavailable_receiver_evidence")}, root / "tables" / "containment.csv")
        events[-1]["clock"] = "published retrospective assessment at run end"
    events.sort(key=lambda e: (e["time"] is None, e["time"] or 0,
                                e["source"], e["line"] if e["line"] is not None else 10**9,
                                e["kind"]))
    for i, e in enumerate(events):
        e["id"] = i
    for path in (meta_path, validity_path, truth_path):
        if path.exists():
            refs.add(str(path.relative_to(root)))
    refs.add("manifest.json")
    refs.add("thresholds.json")
    for name in summary:
        refs.add("tables/" + name + ".csv")
    return {"schema_version": 1, "run": run, "metadata": meta, "validity": validity,
            "start_wall": start, "duration": duration,
            "evaluation_start": relative(meta.get("evaluation_start"), start),
            "recovery_start": relative(meta.get("recovery_start"), start),
            "events": events, "truths": truths, "summary": summary,
            "evidence": sorted(refs)}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":"),
                               allow_nan=False) + "\n")


def prepare(submission, destination):
    submission, destination = Path(submission).resolve(), Path(destination).resolve()
    # Prevent callers from writing into evidence or source directories.
    if destination == submission or submission in destination.parents or destination in submission.parents:
        raise ValueError("Replay output must be separate from curated evidence")
    checksums = verify_evidence(submission)
    tables = {}
    for path in sorted((submission / "tables").glob("*.csv")):
        with path.open() as stream:
            tables[path.stem] = list(csv.DictReader(stream))
    converted = []
    for path in sorted((submission / "evidence").rglob("*_trial*.jsonl")):
        if path.stem.split("_trial")[-1].isdigit():
            converted.append(convert_run(submission, path, tables))
    expected = json.loads((submission / "manifest.json").read_text())["matrix"]
    identities = [(r["metadata"]["phase"], r["metadata"]["case"],
                   r["metadata"]["mitigator"], r["metadata"]["trial"]) for r in converted]
    if len(identities) != len(set(identities)):
        raise ValueError("Duplicate run identity")
    for r in expected:
        if (r["phase"], r["case"], r["mitigator"], r["trial"]) not in identities:
            raise ValueError("Evaluation matrix is incomplete")
    destination.mkdir(parents=True, exist_ok=True)
    catalog = []
    refs = set()
    for i, run in enumerate(converted):
        run["id"] = "run-%03d" % i
        filename = "data/" + run["id"] + ".json"
        write_json(destination / filename, run)
        catalog.append({"id": run["id"], "run": run["run"],
                        "metadata": run["metadata"], "duration": run["duration"], "file": filename})
        refs.update(run["evidence"])
    chapters = []
    for title, phase, case, mitigator, trial in CHAPTERS:
        match = next(r for r in catalog if r["metadata"]["phase"] == phase
                     and r["metadata"]["case"] == case and r["metadata"]["mitigator"] == mitigator
                     and r["metadata"]["trial"] == trial)
        chapters.append({"title": title, "id": match["id"], "trial": trial})
    write_json(destination / "data/index.json", {"schema_version": 1,
        "runs": catalog, "chapters": chapters, "topology": TOPOLOGY,
        "source_checksums_sha256": digest(submission / "checksums.json"),
        "coverage": tables.get("coverage", []),
        "overview": overview(tables, json.loads((submission / "thresholds.json").read_text()))})
    for name in sorted(refs):
        source = safe_file(submission, name)
        target = destination / "evidence" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for source in sorted(ASSETS.glob("*")):
        shutil.copyfile(source, destination / source.name)
    # Standalone server is also the portable export's launch command.
    shutil.copyfile(Path(__file__).with_name("server.py"), destination / "serve.py")
    (destination / "README.txt").write_text(
        "Lantern recorded experiment replay\n\n"
        "Run: python3 serve.py --port 8000\nOpen: http://localhost:8000\n"
        "Python 3 only; no network experiments or internet required.\n"
        "Examples use trial 1, not averages. Evidence is sampled, not packet capture.\n"
        "Checksums are checked by the server before startup.\n")
    inventory = {str(p.relative_to(destination)): digest(p)
                 for p in sorted(destination.rglob("*"))
                 if p.is_file() and p.name != "checksums.json"}
    # Include copied original checksums if ever added; only the root checksum is excluded.
    write_json(destination / "checksums.json", inventory)
    return catalog
