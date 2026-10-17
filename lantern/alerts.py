"""The Alert type shared by every detector.

Kept in its own module so that the detectors and the decision manager can both
depend on it without depending on each other. Adding a third alert source later
(the optional Suricata integration in the report's extension tier) means
emitting this type and nothing more.
"""

from dataclasses import dataclass, field
import time
import uuid

# Attack classes. These strings are the join key between an alert and the
# ground-truth marker an attack script writes, so they must not drift.
CLASS_PORTSCAN = "portscan"
CLASS_DOS = "dos"
CLASS_BRUTEFORCE = "bruteforce"
CLASS_LATERAL = "lateral"

# The graph detector's honest label for "this host's communication structure
# changed sharply, but not in the shape lateral movement makes". It fires on,
# for example, a host whose port diversity explodes while it still talks only
# to machines it always talks to -- which is a scan, not lateral movement.
# Reporting that as lateral movement would put a wrong word in front of an
# analyst, and an alert an analyst cannot trust is worse than no alert.
CLASS_GRAPH_ANOMALY = "graph_anomaly"

ATTACK_CLASSES = (
    CLASS_PORTSCAN,
    CLASS_DOS,
    CLASS_BRUTEFORCE,
    CLASS_LATERAL,
    CLASS_GRAPH_ANOMALY,
)

# Which detector produced an alert. Every alert carries this so the analysis
# can score the two detectors separately on identical traffic.
DETECTOR_BASELINE = "baseline"
DETECTOR_GRAPH = "graph"

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"


@dataclass
class Alert:
    detector: str
    attack_class: str
    src_ip: str
    ts: float
    window_index: int
    dst_ip: str = None
    dst_port: int = None
    protocol: int = None
    severity: str = SEVERITY_MEDIUM
    score: float = 0.0
    reason: str = ""
    evidence: dict = field(default_factory=dict)

    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_mono: float = field(default_factory=time.monotonic)
    created_wall: float = field(default_factory=time.time)
    window_start_wall: float = None
    window_end_wall: float = None

    @property
    def dedupe_key(self):
        """Alerts sharing this key are the same ongoing event, not new ones."""
        return (self.detector, self.attack_class, self.src_ip)

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "created_mono": self.created_mono,
            "created_wall": self.created_wall,
            "window_start_wall": self.window_start_wall,
            "window_end_wall": self.window_end_wall,
            "detector": self.detector,
            "attack_class": self.attack_class,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "ts": self.ts,
            "window_index": self.window_index,
            "severity": self.severity,
            "score": round(self.score, 4),
            "reason": self.reason,
            "evidence": self.evidence,
        }
