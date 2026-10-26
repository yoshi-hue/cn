"""Hybrid detector combining threshold evidence with graph classification."""

import time

from lantern.alerts import DETECTOR_HYBRID


class HybridDetector:
    """Run both detectors on the same window and expose one auditable stream."""

    name = DETECTOR_HYBRID

    def __init__(self, baseline, graph):
        self.baseline = baseline
        self.graph = graph
        self.last_compute_seconds = 0.0

    def detect(self, window):
        started = time.perf_counter()
        threshold_alerts = self.baseline.detect(window)
        graph_alerts = self.graph.detect(window)
        corroboration = {(a.src_ip, a.attack_class): a for a in threshold_alerts}
        combined = []
        for alert in threshold_alerts + graph_alerts:
            alert.detector = self.name
            match = corroboration.get((alert.src_ip, alert.attack_class))
            if match is not None and alert is not match:
                alert.evidence = dict(alert.evidence)
                alert.evidence["threshold_corroborated"] = True
                alert.evidence["threshold_score"] = match.score
            combined.append(alert)
        self.last_compute_seconds = time.perf_counter() - started
        return combined

    def timing_snapshot(self):
        snapshot = self.graph.timing_snapshot()
        snapshot["hybrid_total_seconds"] = round(self.last_compute_seconds, 6)
        return snapshot
