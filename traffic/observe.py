"""Receiver counters with explicit capture interface and independent health checks."""

import argparse
import json
import signal
import threading
import time
from scapy.all import AsyncSniffer, IP

ATTACK_MARKER = 0x10
HEALTH_MARKER = 0x20


def count_packet(packet, ip, counts, health_counts):
    if IP not in packet or packet[IP].dst != ip:
        return
    marker = packet[IP].tos
    target = counts if marker == ATTACK_MARKER else health_counts if marker == HEALTH_MARKER else None
    if target is not None:
        src = packet[IP].src
        target[src] = target.get(src, 0) + 1


def capture_alive(sniffer):
    # Scapy 2.5 can leave running=True if its thread raises unexpectedly.
    return sniffer.running and sniffer.thread.is_alive()


def main(argv=None):
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    counts, health_counts = {}, {}
    ready, stopped = threading.Event(), threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    sniffer = AsyncSniffer(
        iface=args.iface, store=False, filter="ip and dst host " + args.ip,
        prn=lambda p: count_packet(p, args.ip, counts, health_counts),
        started_callback=ready.set,
    )
    sniffer.start()
    try:
        if not ready.wait(5):
            raise RuntimeError("receiver capture did not become ready on " + args.iface)
        with open(args.output, "x", buffering=1) as handle:
            while not stopped.is_set():
                if not capture_alive(sniffer):
                    raise RuntimeError("receiver capture stopped on " + args.iface)
                handle.write(json.dumps(dict(
                    kind="receiver", wall=time.time(), dst=args.ip, iface=args.iface,
                    ready=True, counts=dict(counts), health_counts=dict(health_counts),
                )) + "\n")
                stopped.wait(1)
    finally:
        if capture_alive(sniffer):
            sniffer.stop()


if __name__ == "__main__":
    main()
