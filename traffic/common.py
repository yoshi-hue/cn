"""Shared helpers for traffic generators.

Every attack script writes a ground-truth marker before and after it runs. That
marker is what the analysis joins alerts against, so it is the only thing that
makes a detection a *true* positive rather than merely an alert. Writing it
from the attack process rather than from the controller matters: the controller
must not be told what the truth is, or the experiment would be circular.
"""

import argparse
import random
import sys
import time
import uuid


from lantern import config  # noqa: E402
from lantern.metrics import truth_log_path, write_truth_marker  # noqa: E402


def attack_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--case", default="adhoc", help="experimental case label")
    parser.add_argument("--trial", type=int, default=0)
    parser.add_argument("--src", default=None, help="source IP (defaults to attacker)")
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--seed", type=int, default=None)
    return parser


def resolve_source(args):
    return args.src or config.HOST_TO_IP[config.ATTACKER]


_active_truth = None


def send(*args, **kwargs):
    from scapy.all import send as scapy_send, IP

    packets = args[0] if isinstance(args[0], list) else [args[0]]
    for packet in packets:
        if IP in packet:
            packet[IP].tos = (
                0x10  # receiver-side identification, not a detector feature
            )
    if _active_truth is not None:
        now = time.time()
        _active_truth.first_send = _active_truth.first_send or now
    result = scapy_send(*args, **kwargs)
    if _active_truth is not None:
        _active_truth.last_send = time.time()
        _active_truth.sent += len(packets)
    return result


class GroundTruth:
    """Context manager writing the start and end markers for one attack."""

    def __init__(self, attack_class, case, trial, src, targets=None, note=""):
        self.path = truth_log_path(case, trial)
        self.attack_class = attack_class
        self.src = src
        self.targets = list(targets or [])
        self.note = note
        self.t_start = None
        self.first_send = None
        self.last_send = None
        self.sent = 0
        self.attack_id = uuid.uuid4().hex

    def __enter__(self):
        global _active_truth
        _active_truth = self
        self.t_start = time.time()
        return self

    def add_target(self, target):
        if target not in self.targets:
            self.targets.append(target)

    def __exit__(self, exc_type, exc, tb):
        global _active_truth
        _active_truth = None
        write_truth_marker(
            self.path,
            {
                "schema_version": 2,
                "attack_id": self.attack_id,
                "first_send": self.first_send,
                "last_send": self.last_send,
                "sent": self.sent,
                "attack_class": self.attack_class,
                "src": self.src,
                "targets": self.targets,
                "t_start": self.t_start,
                "t_end": time.time(),
                "note": self.note,
                "aborted": exc_type is not None,
            },
        )
        return False


def seeded(seed):
    """Seed the intended workload; live scheduling remains nondeterministic."""
    if seed is not None:
        random.seed(seed)


def jitter(base, spread=0.3):
    """Randomised delay; constant-rate traffic is unrealistically easy to spot."""
    return max(base * (1.0 + random.uniform(-spread, spread)), 0.0)
