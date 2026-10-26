"""Single source of truth for topology, thresholds, and detector tuning.

Every threshold and weight in this file is a *starting point* to be tuned
empirically against normal traffic only (experimental case C1), never against
attack traffic. Tuning on attack traffic would make the baseline-vs-graph
comparison meaningless, because each detector would have been fitted to the
very attacks it is then scored on.
"""

import os as _os

# --------------------------------------------------------------------------
# Topology (report section 5.8)
# --------------------------------------------------------------------------
# Two OpenFlow switches, six hosts. Kept deliberately small: it is easier to
# debug, instrument and explain, and the scalability question (Research Gap 5)
# is explicitly out of scope for this semester.

SUBNET = "10.0.0.0/24"

HOSTS = {
    # name:     (ip,           mac,                 switch, role)
    "h1": ("10.0.0.1", "00:00:00:00:00:01", "s1", "workstation"),
    "h2": ("10.0.0.2", "00:00:00:00:00:02", "s1", "workstation"),
    "h3": ("10.0.0.3", "00:00:00:00:00:03", "s1", "workstation"),
    "h4": ("10.0.0.4", "00:00:00:00:00:04", "s2", "attacker"),
    "h5": ("10.0.0.5", "00:00:00:00:00:05", "s2", "auth_server"),
    "server": ("10.0.0.10", "00:00:00:00:00:10", "s2", "app_server"),
}

# The original six-host topology remains the default for backwards
# compatibility.  Larger campaigns opt in with LANTERN_TOPOLOGY_SIZE; hosts
# are generated deterministically so the same source can be replayed in the
# controller, Mininet topology, normal workload, and attack scripts.
_TOPOLOGY_SIZE = int(_os.environ.get("LANTERN_TOPOLOGY_SIZE", "6"))
if _TOPOLOGY_SIZE < 6:
    raise ValueError("LANTERN_TOPOLOGY_SIZE must be at least 6")
if _TOPOLOGY_SIZE > 6:
    for _number in range(6, _TOPOLOGY_SIZE):
        _switch = "s1" if _number % 2 == 0 else "s2"
        HOSTS["h%d" % _number] = (
            "10.0.0.%d" % _number,
            "00:00:00:00:00:%02x" % _number,
            _switch,
            "workstation",
        )


def configure_topology(size):
    """Rebuild topology globals for an in-process experiment runner."""
    global HOSTS, IP_TO_HOST, HOST_TO_IP, WORKSTATIONS
    if size < 6:
        raise ValueError("topology size must be at least 6")
    base = {
        "h1": ("10.0.0.1", "00:00:00:00:00:01", "s1", "workstation"),
        "h2": ("10.0.0.2", "00:00:00:00:00:02", "s1", "workstation"),
        "h3": ("10.0.0.3", "00:00:00:00:00:03", "s1", "workstation"),
        "h4": ("10.0.0.4", "00:00:00:00:00:04", "s2", "attacker"),
        "h5": ("10.0.0.5", "00:00:00:00:00:05", "s2", "auth_server"),
        "server": ("10.0.0.10", "00:00:00:00:00:10", "s2", "app_server"),
    }
    for number in range(6, size):
        base["h%d" % number] = (
            "10.0.0.%d" % number, "00:00:00:00:00:%02x" % number,
            "s1" if number % 2 == 0 else "s2", "workstation",
        )
    HOSTS = base
    IP_TO_HOST = {ip: name for name, (ip, _, _, _) in HOSTS.items()}
    HOST_TO_IP = {name: ip for name, (ip, _, _, _) in HOSTS.items()}
    WORKSTATIONS = [name for name, value in HOSTS.items() if value[3] == "workstation"]

SWITCHES = ["s1", "s2"]
SWITCH_LINKS = [("s1", "s2")]

ATTACKER = "h4"
AUTH_SERVER = "h5"
APP_SERVER = "server"
WORKSTATIONS = [name for name, value in HOSTS.items()
                if value[3] == "workstation"]

IP_TO_HOST = {ip: name for name, (ip, _, _, _) in HOSTS.items()}
HOST_TO_IP = {name: ip for name, (ip, _, _, _) in HOSTS.items()}

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653

# --------------------------------------------------------------------------
# Collection (Algorithm A)
# --------------------------------------------------------------------------

# Length of the fixed time window over which both detectors score. The report
# suggests ten seconds; short enough that lateral movement is caught while it is
# still unfolding, long enough that a host's normal degree is stable.
WINDOW_SECONDS = float(_os.environ.get("LANTERN_WINDOW_SECONDS", "10.0"))

# How often the controller asks every switch for flow statistics. This bounds
# how stale the byte/packet counters can be. PacketIn events are handled
# independently and immediately, so new-edge detection is not floored by this.
POLL_INTERVAL_SECONDS = 5.0

# Ports treated as authentication services for the brute-force rule.
AUTH_PORTS = {22, 21, 23, 3389, 5900}

# --------------------------------------------------------------------------
# Baseline detector thresholds (Algorithm B, report section 5.3)
# --------------------------------------------------------------------------

# Port scan: distinct destination ports, or distinct destination hosts, that a
# single source contacts within one window.
PORTSCAN_PORTS = 15
PORTSCAN_HOSTS = 4

# Denial of service: packets per second from one source to one destination,
# sustained across consecutive windows (a single spike is not a DoS).
DOS_PPS = 500.0
DOS_SUSTAINED_WINDOWS = 2

# Brute force: failed or repeated connection attempts to an auth port.
BRUTEFORCE_ATTEMPTS = 20

# --------------------------------------------------------------------------
# Graph detector (Algorithm C, report section 5.4)
# --------------------------------------------------------------------------

# Windows of normal traffic observed before any host may be scored. Hosts are
# scored against their *own* established normal, so there must be a normal to
# compare against first. 12 windows x 10s = 2 minutes of warmup.
PROFILE_WARMUP_WINDOWS = 12

# A host needs at least this many observations before its profile is trusted.
MIN_PROFILE_WINDOWS = 6

# EWMA smoothing for the rolling per-host profile. Lower = longer memory.
PROFILE_ALPHA = float(_os.environ.get("LANTERN_PROFILE_ALPHA", "0.2"))

# A host whose behaviour is perfectly constant has sigma = 0, which would send
# every z-score to infinity on the first deviation, making the detector alert
# on a single extra packet. Standard deviations are therefore floored.
#
# The floor is in each feature's own units, so one global value would not be
# fair across features: degree is counted in hosts (range 0-6 here) while
# new-neighbour ratio is a fraction (range 0-1). A floor of 0.5 caps a full
# 0-to-1 swing in the ratio at z = 2, quietly suppressing the single feature
# that most directly expresses lateral movement, while barely constraining
# degree at all.
MIN_SIGMA_DEFAULT = 0.5
MIN_SIGMA_BY_FEATURE = {
    "degree": 0.5,  # whole hosts
    "weighted_degree": 5.0,  # packet counts; naturally noisy
    "new_neighbour_ratio": 0.1,  # a fraction in [0, 1]
    "port_diversity": 0.5,  # whole ports
    "betweenness": 0.05,  # normalised centrality, typically << 1
}


def min_sigma(feature):
    return MIN_SIGMA_BY_FEATURE.get(feature, MIN_SIGMA_DEFAULT)


# z-scores are clamped so that one wild feature cannot single-handedly dominate
# the aggregate score S(h,t).
Z_CLAMP = 6.0

# Feature weights w_i for S(h,t) = sum_i w_i * z_i(h,t).
#
# New-neighbour ratio is weighted highest because it is the feature that most
# directly expresses lateral movement: a host talking to machines it has never
# talked to before. Betweenness is weighted lowest -- it is the most expensive
# to compute and the noisiest on a six-host graph.
GRAPH_WEIGHTS = {
    "degree": 1.0,
    "weighted_degree": 0.3,
    "new_neighbour_ratio": 2.0,
    "port_diversity": 1.0,
    "betweenness": 0.5,
    "community_change": 1.0,
}

# Alert threshold theta. Set from C1 so that normal traffic produces no alerts.
GRAPH_SCORE_THRESHOLD = 6.0

# Optional control condition: cumulative distinct destinations is deliberately
# disabled in the original detector by default so the historical unit tests
# continue to represent the per-window baseline. The control campaign enables
# it explicitly through LANTERN_CUMULATIVE_LATERAL.
CUMULATIVE_LATERAL_ENABLED = _os.environ.get("LANTERN_CUMULATIVE_LATERAL", "0") == "1"
CUMULATIVE_NEW_DESTINATIONS = int(
    _os.environ.get("LANTERN_CUMULATIVE_NEW_DESTINATIONS", "6")
)

# Both detector mitigation arms use this single class-to-action policy.  It is
# recorded in every run so a detector arm cannot silently receive a different
# response policy.
MITIGATION_POLICY_NAME = "class-equivalent-v1"
MITIGATION_POLICY = {
    "portscan": "drop_source",
    "lateral": "drop_source",
    "bruteforce": "drop_pair",
    "dos": "drop_pair",
    "graph_anomaly": "log_only",
}

# --------------------------------------------------------------------------
# Decision and mitigation (Algorithm D, report section 5.7)
# --------------------------------------------------------------------------

# Suppress repeat alerts for the same (source, attack class) for this long, so
# one scan produces one alert rather than one per window.
ALERT_COOLDOWN_SECONDS = 30.0

# Installed mitigation rules take priority over the learning switch's rules.
MITIGATION_PRIORITY = 100
LEARNING_SWITCH_PRIORITY = 1

# Temporary blocks expire on their own (Algorithm D step 8).
MITIGATION_IDLE_TIMEOUT = 30
MITIGATION_HARD_TIMEOUT = 0  # 0 = no hard timeout; idle timeout governs.

# Which detector is allowed to actuate mitigation.
#
# This matters more than it looks. If both detectors install drop rules, the
# faster one destroys the traffic the other still needed to observe, and the
# detection comparison measures nothing. Detection-comparison runs use "none":
# both detectors score, neither blocks.
MITIGATOR_MODES = ("baseline", "graph", "hybrid", "both", "none")
DEFAULT_MITIGATOR = "none"

# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

RESOURCE_SAMPLE_INTERVAL = 1.0  # seconds between psutil samples of the controller
RESULTS_RAW_DIR = "results/raw"
RESULTS_TABLES_DIR = "results/tables"
RESULTS_FIGS_DIR = "results/figs"

# Campaign paths and a frozen, calibration-derived threshold override.
import json as _json

RESULTS_RAW_DIR = _os.environ.get("LANTERN_RAW", RESULTS_RAW_DIR)
_THRESHOLD_KEYS = {
    "PORTSCAN_PORTS",
    "PORTSCAN_HOSTS",
    "DOS_PPS",
    "BRUTEFORCE_ATTEMPTS",
    "GRAPH_SCORE_THRESHOLD",
}
if _os.environ.get("LANTERN_CONFIG"):
    with open(_os.environ["LANTERN_CONFIG"]) as _handle:
        _overrides = _json.load(_handle)
    if set(_overrides) - _THRESHOLD_KEYS:
        raise ValueError("unsupported threshold override")
    for _key, _value in _overrides.items():
        if not isinstance(_value, (int, float)) or not 0 < _value < float("inf"):
            raise ValueError("threshold must be finite and positive")
        globals()[_key] = _value
