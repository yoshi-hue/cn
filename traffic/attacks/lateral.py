"""Sequential internal-contact simulation from one source host.

A fixed, low-volume path is evaluated against frozen detectors. This is not a
successful compromise or a multi-host propagation chain. Threshold comparisons
are diagnostics only: a baseline detection is a valid experimental outcome.
"""

import random
import sys
import time


from scapy.all import IP, TCP  # noqa: E402

from traffic.common import send

from lantern import config  # noqa: E402
from traffic.common import (
    GroundTruth,
    attack_parser,
    jitter,
    resolve_source,
    seeded,
)  # noqa: E402

# One plausible service port per target. Using a single port per host keeps the
# per-window port count far below the port-scan rule, while still being the
# kind of service an attacker would actually probe.
def default_path():
    """Return a deterministic path that scales with the configured topology."""
    ports = [22, 445, 3389]
    path = [(host, ports[index % len(ports)])
            for index, host in enumerate(config.WORKSTATIONS)]
    path += [("h5", 22), ("server", 1433)]
    return path

PACKETS_PER_TARGET = 3


def check_pacing(dwell, packets_per_target=PACKETS_PER_TARGET):
    """Report approximate pacing relative to the configured thresholds.

    Returns a list of problems; empty means the scenario is still a fair test.
    """
    problems = []

    hosts_per_window = config.WINDOW_SECONDS / dwell
    if hosts_per_window > config.PORTSCAN_HOSTS:
        problems.append(
            "pacing contacts ~%.1f hosts per %.0fs window, which crosses the "
            "baseline's port-scan host threshold of %d -- increase --dwell"
            % (hosts_per_window, config.WINDOW_SECONDS, config.PORTSCAN_HOSTS)
        )

    ports_per_window = hosts_per_window  # one port per target
    if ports_per_window > config.PORTSCAN_PORTS:
        problems.append(
            "pacing touches ~%.1f ports per window, crossing the port threshold of %d"
            % (ports_per_window, config.PORTSCAN_PORTS)
        )

    auth_targets = [t for t in default_path() if t[1] in config.AUTH_PORTS]
    attempts_per_target = packets_per_target
    if attempts_per_target > config.BRUTEFORCE_ATTEMPTS and auth_targets:
        problems.append(
            "%d attempts per auth target crosses the brute-force threshold of %d"
            % (attempts_per_target, config.BRUTEFORCE_ATTEMPTS)
        )

    return problems


def run(
    src_ip,
    path,
    dwell,
    packets_per_target=PACKETS_PER_TARGET,
    truth=None,
    verbose=False,
):
    """Walk the path, pausing `dwell` seconds between targets."""
    visited = []
    for host_name, port in path:
        target_ip = config.HOST_TO_IP[host_name]
        if target_ip == src_ip:
            continue

        sport = random.randint(30000, 60000)
        for index in range(packets_per_target):
            # A synthetic SYN and data-shaped packets; no TCP session is completed.
            flags = "S" if index == 0 else "A"
            payload = b"" if index == 0 else b"x" * random.randint(20, 120)
            send(
                IP(src=src_ip, dst=target_ip)
                / TCP(sport=sport, dport=port, flags=flags)
                / payload,
                verbose=verbose,
            )
            time.sleep(jitter(0.15))

        visited.append({"host": host_name, "ip": target_ip, "port": port})
        if truth is not None:
            truth.add_target(target_ip)
        time.sleep(jitter(dwell, spread=0.15))

    return visited


def main():
    parser = attack_parser(__doc__)
    parser.add_argument(
        "--dwell",
        type=float,
        default=4.0,
        help="seconds between targets; raise it to make the scenario quieter",
    )
    parser.add_argument("--packets", type=int, default=PACKETS_PER_TARGET)
    args = parser.parse_args()
    seeded(args.seed)

    problems = check_pacing(args.dwell, args.packets)
    if problems:
        for problem in problems:
            print("lateral: PACING PROBLEM: %s" % problem, file=sys.stderr)
        print(
            "lateral: diagnostic only; fixed workload is evaluated even when baseline thresholds are crossed",
            file=sys.stderr,
        )

    src_ip = resolve_source(args)
    with GroundTruth(
        "lateral",
        args.case,
        args.trial,
        src_ip,
        note="sequential contact with %d internal hosts, %d packets each, %.1fs apart"
        % (len(default_path()), args.packets, args.dwell),
    ) as truth:
        visited = run(src_ip, default_path(), args.dwell, args.packets, truth=truth)

    print(
        "lateral: %s reached %d hosts: %s"
        % (src_ip, len(visited), ", ".join(v["host"] for v in visited))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
