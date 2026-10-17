"""The seven experimental cases (report Table 3).

Each case declares what traffic runs and why, so that the reason a case exists
is recorded next to the code that runs it rather than only in the report.
"""

from lantern import config

PORTSCAN = "traffic/attacks/portscan.py"
DOS = "traffic/attacks/dos.py"
BRUTEFORCE = "traffic/attacks/bruteforce.py"
LATERAL = "traffic/attacks/lateral.py"


class Case:
    def __init__(
        self, name, purpose, attacks=(), attack_duration=30.0, normal_rate=1.5, notes=""
    ):
        self.name = name
        self.purpose = purpose
        self.attacks = list(attacks)  # (module, extra_args) pairs
        self.attack_duration = attack_duration
        self.normal_rate = normal_rate
        self.notes = notes


CASES = {
    "C1": Case(
        "C1",
        purpose="Measure the false-positive rate",
        attacks=(),
        notes=(
            "Normal traffic only. This is the run that sets the graph score "
            "threshold and the baseline thresholds: both detectors are tuned so "
            "that this case produces no alerts, and neither is ever tuned "
            "against attack traffic."
        ),
    ),
    "C2": Case(
        "C2",
        purpose="Test scanning detection",
        attacks=[(PORTSCAN, ["--delay", "0.05", "--repeat-for", "40"])],
        notes=(
            "A loud TCP SYN sweep. The per-flow baseline should catch this "
            "easily -- that is the point. A comparison the baseline loses "
            "everywhere would suggest it had been built to lose."
        ),
    ),
    "C3": Case(
        "C3",
        purpose="Test high-rate anomaly detection",
        attacks=[(DOS, ["--duration", "40", "--pps", "1500"])],
        notes="Volumetric flooding: the attack family nine of the ten recent "
        "surveyed papers target.",
    ),
    "C4": Case(
        "C4",
        purpose="Test repeated failed-connection detection",
        attacks=[(BRUTEFORCE, ["--attempts", "60", "--repeat-for", "40"])],
        notes="Repeated SYN attempts to an authentication port; no passwords or sessions.",
    ),
    "C5": Case(
        "C5",
        purpose="Test graph-based detection specifically",
        attacks=[(LATERAL, ["--dwell", "4.0"])],
        notes=(
            "The case the project exists for. Each connection is individually "
            "synthetic; either detector may identify the source. Correct lateral "
            "classification is assessed separately from source detection."
        ),
    ),
    "C6": Case(
        "C6",
        purpose="Test legitimate-traffic disruption under realistic conditions",
        attacks=[
            (LATERAL, ["--dwell", "4.0"]),
            (PORTSCAN, ["--delay", "0.08", "--repeat-for", "40"]),
        ],
        normal_rate=3.0,
        notes=(
            "Heavier normal traffic running throughout the attacks. Measures "
            "what the mitigation costs innocent hosts -- an IDS that contains "
            "an attack by cutting off the network is not a useful system."
        ),
    ),
    "C7": Case(
        "C7",
        purpose="Directly compare the two detection approaches",
        # Lateral movement runs FIRST, and the order is not arbitrary.
        #
        # The graph detector scores each host against its own rolling profile,
        # and that profile keeps learning. A port scan run first would fold a
        # window in which the attacker touched ~80 ports into its own baseline,
        # inflating the mean and variance of its port-diversity feature, and
        # every host it contacted would be added to its seen-neighbours set.
        # The lateral movement that followed would then be scored as normal for
        # that host -- the loud attack would have trained away the signal for
        # the quiet one.
        #
        # This is a real property of any profile-based detector and it is worth
        # stating rather than hiding. Here the quiet attack goes first so the
        # comparison is not decided by attack ordering; the per-class cases
        # (C2-C5) each run one attack against a clean profile, and remain the
        # primary evidence.
        attacks=[
            (LATERAL, ["--dwell", "4.0"]),
            (PORTSCAN, ["--delay", "0.05", "--repeat-for", "40"]),
            (BRUTEFORCE, ["--attempts", "60", "--repeat-for", "40"]),
        ],
        notes=(
            "Lateral movement, port scan, and SYN retry simulation in one run, with mitigation disabled so that "
            "neither detector can destroy the traffic the other still needs to "
            "see. Attack order matters here -- see the comment above."
        ),
    ),
}

# C7 must never actuate: it is the controlled comparison.
FORCED_MITIGATOR = {"C7": "none"}

ORDER = ["C1", "C2", "C3", "C4", "C5", "C6", "C7"]
