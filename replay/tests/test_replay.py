"""Run with python3 -m unittest discover -s replay/tests -v."""

import csv
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

from replay.data import (complete_confirmations, convert_run, digest, prepare,
                         read_jsonl, relative, truth_matches, verify_evidence, write_json)
from replay.server import make_handler, verified_inventory

ROOT = Path(__file__).resolve().parents[2]
SUBMISSION = ROOT / "submission"


class TimingTests(unittest.TestCase):
    def test_missing_or_nonfinite_timestamps_are_unavailable(self):
        for value in (None, "", float("nan"), float("inf"), "broken"):
            self.assertIsNone(relative(value, 100))
        self.assertEqual(relative(102.25, 100), 2.25)

    def test_ambiguous_attribution_is_not_arbitrarily_credited(self):
        event = {"src_ip": "source", "window_start_wall": 100, "window_end_wall": 110}
        truths = [{"src": "source", "first_send": 101, "last_send": 105, "attack_id": "a"},
                  {"src": "source", "first_send": 106, "last_send": 109, "attack_id": "b"}]
        self.assertEqual(truth_matches(event, truths), ["a", "b"])
        self.assertIsNone(truth_matches({"src_ip": "source"}, truths))
        self.assertEqual(truth_matches(dict(event, src_ip="innocent"), truths), [])

    def test_every_target_must_confirm_the_same_actuating_decision(self):
        events = [{"kind": "mitigation_decided", "decision_id": "a", "actuate": True},
                  {"kind": "mitigation_targeted", "decision_id": "a", "switches": [1, 2]},
                  {"kind": "barrier_reply", "decision_id": "a", "dpid": 1, "wall": 10},
                  {"kind": "barrier_reply", "decision_id": "other", "dpid": 2, "wall": 11}]
        self.assertEqual(complete_confirmations(events), [])
        events.append({"kind": "barrier_reply", "decision_id": "a", "dpid": 2, "wall": 12})
        self.assertEqual(complete_confirmations(events)[0]["wall"], 12)
        events[0]["actuate"] = False
        self.assertEqual(complete_confirmations(events), [])

    def test_unknown_confirmation_time_does_not_imply_completion(self):
        events = [{"kind": "mitigation_decided", "decision_id": "a", "actuate": True},
                  {"kind": "mitigation_targeted", "decision_id": "a", "switches": [1]},
                  {"kind": "barrier_reply", "decision_id": "a", "dpid": 1}]
        self.assertEqual(complete_confirmations(events), [])


class CuratedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.output = Path(cls.tmp.name) / "viewer"
        cls.before = digest(SUBMISSION / "checksums.json")
        cls.catalog = prepare(SUBMISSION, cls.output)
        cls.runs = [json.loads((cls.output / r["file"]).read_text()) for r in cls.catalog]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def selected(self, phase, case, mitigator="none"):
        return next(r for r in self.runs if r["metadata"]["phase"] == phase
                    and r["metadata"]["case"] == case and r["metadata"]["mitigator"] == mitigator
                    and r["metadata"]["trial"] == 1)

    def test_all_evaluation_and_supplementary_runs_load(self):
        counts = {}
        for r in self.runs:
            phase = r["metadata"]["phase"]
            counts[phase] = counts.get(phase, 0) + 1
        self.assertEqual(counts, {"benign": 5, "calibration": 3, "detection": 35,
                                 "mitigation": 50, "order": 5, "pilot": 1})

    def test_every_published_trial_row_is_preserved_exactly(self):
        for name in ("detections", "attacks", "containment", "disruption", "timing", "overhead"):
            with (SUBMISSION / "tables" / (name + ".csv")).open() as stream:
                rows = list(csv.DictReader(stream))
            for run in self.runs:
                self.assertEqual(run["summary"].get(name, []),
                                 [r for r in rows if r.get("run") == run["run"]])

    def test_conversion_is_deterministic_and_chronological(self):
        run = self.selected("detection", "C5")
        log = SUBMISSION / "evidence" / (run["run"] + ".jsonl")
        tables = {name: rows for name, rows in run["summary"].items()}
        first = convert_run(SUBMISSION, log, tables)
        second = convert_run(SUBMISSION, log, tables)
        self.assertEqual(first, second)
        times = [e["time"] for e in first["events"] if e["time"] is not None]
        self.assertEqual(times, sorted(times))

    def test_candidates_and_alerts_remain_distinct(self):
        run = self.selected("benign", "C1")
        self.assertGreater(sum(e["kind"] == "detector_candidate" for e in run["events"]),
                           sum(e["kind"] == "alert" for e in run["events"]))

    def test_actual_alert_and_decision_times_are_preserved(self):
        run = self.selected("mitigation", "C5", "graph")
        for e in run["events"]:
            if e["kind"] in ("alert", "detector_candidate"):
                self.assertEqual(e["time"], relative(e["data"]["created_wall"], run["start_wall"]))
            if e["kind"] == "mitigation_decided":
                self.assertEqual(e["time"], relative(e["data"]["decided_wall"], run["start_wall"]))

    def test_blocking_is_not_inferred_from_rule_confirmation(self):
        baseline = self.selected("mitigation", "C5", "baseline")
        graph = self.selected("mitigation", "C5", "graph")
        self.assertTrue(any(e["kind"] == "all_switches_confirmed" for e in baseline["events"]))
        self.assertEqual(baseline["summary"]["containment"][0]["observed_blocking"], "unverified")
        self.assertEqual(graph["summary"]["containment"][0]["observed_blocking"], "verified")
        self.assertTrue(any(e["kind"] == "mitigation_expired" for e in graph["events"]))

    def test_complete_confirmation_follows_its_final_reply(self):
        run = self.selected("mitigation", "C5", "graph")
        complete = next(e for e in run["events"] if e["kind"] == "all_switches_confirmed")
        replies = [e for e in run["events"] if e["kind"] == "barrier_reply"
                   and e["data"]["decision_id"] == complete["data"]["decision_id"]]
        self.assertTrue(all(e["id"] < complete["id"] for e in replies))

    def test_invalid_and_incomplete_runs_are_rejected(self):
        run = self.selected("detection", "C5")
        log = SUBMISSION / "evidence" / (run["run"] + ".jsonl")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "evidence" / log.name
            target.parent.mkdir()
            target.write_bytes(log.read_bytes())
            target.with_suffix(".meta.json").write_text(json.dumps(run["metadata"]))
            target.with_suffix(".validity.json").write_text('{"valid":false}')
            with self.assertRaisesRegex(ValueError, "Invalid run"):
                convert_run(root, target, {})
            target.with_suffix(".validity.json").write_text('{"valid":true,"expected_attacks":1}')
            with self.assertRaisesRegex(ValueError, "Missing truth"):
                convert_run(root, target, {})
            target.write_text(json.dumps({"kind": "run_start", "wall": 1}) + "\n")
            with self.assertRaisesRegex(ValueError, "Incomplete run"):
                convert_run(root, target, {})

    def test_historical_source_provenance_and_evidence_are_preserved(self):
        self.assertEqual(self.before, digest(SUBMISSION / "checksums.json"))
        verify_evidence(SUBMISSION)
        manifest = json.loads((SUBMISSION / "manifest.json").read_text())
        self.assertEqual(manifest["source_hash"], (SUBMISSION / "source.sha256").read_text().strip())

    def test_overview_matches_published_headline_figures(self):
        o = json.loads((self.output / "data/index.json").read_text())["overview"]
        self.assertEqual(o["primary"]["lateral|graph"]["class_exact"], 5)
        self.assertEqual(o["primary"]["lateral|baseline"]["class_exact"], 0)
        self.assertEqual(o["primary"]["dos|graph"]["detected"], 0)
        fp = o["false_positives"]
        self.assertEqual((fp["benign|baseline"]["flagged"], fp["benign|baseline"]["eligible"]), (30, 273))
        self.assertEqual((fp["benign|graph"]["flagged"], fp["benign|graph"]["eligible"]), (14, 273))
        m = o["mitigation"]
        self.assertEqual((m["baseline"]["confirmed"], m["baseline"]["verified"], m["baseline"]["records"]), (25, 0, 30))
        self.assertEqual((m["graph"]["confirmed"], m["graph"]["verified"], m["graph"]["records"]), (10, 0, 30))
        self.assertEqual(m["graph"]["legacy_counter_evidence"], 10)
        self.assertFalse(m["graph"]["receiver_evidence_available"])
        self.assertEqual(o["delivery"]["graph|innocent|recovery"], {"attempts": 1683, "successes": 1683})
        self.assertEqual(o["validity"], {"valid": 99, "runs": 99})
        self.assertAlmostEqual(o["cost"]["graph_ms"]["mean"], 1.37, places=2)

    def test_export_inventory_verifies_and_all_sources_exist(self):
        allowed = verified_inventory(self.output)
        for run in self.runs:
            for ref in run["evidence"]:
                self.assertIn("evidence/" + ref, allowed)


class RepairedEvidenceTests(unittest.TestCase):
    """The default replay and the reports read the repaired campaign."""

    @classmethod
    def setUpClass(cls):
        from replay.data import DEFAULT_SUBMISSION
        cls.tmp = tempfile.TemporaryDirectory()
        cls.output = Path(cls.tmp.name) / "viewer"
        prepare(ROOT / DEFAULT_SUBMISSION, cls.output)
        cls.index = json.loads((cls.output / "data/index.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_blocking_headline_figures(self):
        b = self.index["overview"]["blocking"]
        self.assertEqual((b["baseline|lateral"]["leakage"], b["baseline|lateral"]["records"]), (10, 10))
        self.assertEqual((b["graph|lateral"]["verified"], b["graph|lateral"]["leakage"]), (9, 0))
        self.assertEqual((b["baseline|all"]["verified"], b["graph|all"]["verified"]), (15, 9))

    def test_graph_mitigation_chapter_uses_typical_trial(self):
        chapter = next(c for c in self.index["chapters"] if c["title"] == "Graph mitigation")
        run = next(r for r in self.index["runs"] if r["id"] == chapter["id"])
        self.assertEqual((run["metadata"]["case"], run["metadata"]["mitigator"], run["metadata"]["trial"]), ("C5", "graph", 2))


class ServerTests(unittest.TestCase):
    def test_only_allowlisted_files_are_served(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text("viewer")
            (root / "private.txt").write_text("not in allowlist")
            write_json(root / "checksums.json", {"index.html": digest(root / "index.html")})
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = "http://127.0.0.1:%d" % server.server_port
            try:
                with urlopen(base + "/") as response:
                    self.assertEqual(response.read(), b"viewer")
                    self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                for path in ("/private.txt", "/../private.txt", "/%2e%2e/private.txt", "/evidence/"):
                    with self.assertRaises(HTTPError) as failure:
                        urlopen(base + path)
                    self.assertEqual(failure.exception.code, 404)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_checksum_tampering_blocks_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text("original")
            write_json(root / "checksums.json", {"index.html": digest(root / "index.html")})
            (root / "index.html").write_text("modified")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verified_inventory(root)


if __name__ == "__main__":
    unittest.main()
