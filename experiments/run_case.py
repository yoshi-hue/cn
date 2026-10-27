"""Execute one isolated trial. Prefer the host campaign driver for repetitions."""

import argparse
import json
import os
from pathlib import Path
import time
from lantern import config
from lantern.metrics import run_log_path
from experiments.cases import CASES, FORCED_MITIGATOR
from experiments.validation import read_events, validate_run

WARMUP_SECONDS = config.PROFILE_WARMUP_WINDOWS * config.WINDOW_SECONDS + 15.0
DRAIN_SECONDS = 45.0  # permits idle rule expiry and service recovery


def reserve_run(label, trial):
    path = Path(run_log_path(label, trial))
    path.parent.mkdir(parents=True, exist_ok=True)
    if list(path.parent.glob(path.stem + "*")):
        raise FileExistsError("run already exists: " + str(path))
    path.with_suffix(".reserved").touch(exist_ok=False)
    return str(path)


def monitor(seconds, controller, workload):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if controller.process.poll() is not None:
            raise RuntimeError("controller exited prematurely")
        workload.assert_alive()
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def run_trial(
    case,
    trial,
    mitigator,
    warmup=None,
    seed=1000,
    verbose=False,
    label=None,
    phase="detection",
    observation=60,
    reverse=False,
    benign=False,
    detector_mode="both",
    topology_size=None,
    window_seconds=None,
    profile_alpha=None,
    cumulative_lateral=False,
    policy="class",
):
    if topology_size is not None:
        config.configure_topology(topology_size)
    if window_seconds is not None:
        config.WINDOW_SECONDS = window_seconds
    if profile_alpha is not None:
        config.PROFILE_ALPHA = profile_alpha
    if cumulative_lateral:
        config.CUMULATIVE_LATERAL_ENABLED = True
    from experiments.runner import Controller, Workload, dump_flows
    from topo.lantern_topo import build_network, disable_offloads

    warmup = WARMUP_SECONDS if warmup is None else warmup
    if warmup < config.PROFILE_WARMUP_WINDOWS * config.WINDOW_SECONDS:
        raise ValueError("warmup is shorter than profiling minimum")
    mitigator = FORCED_MITIGATOR.get(case, mitigator)
    label = label or case
    log = reserve_run(label, trial)
    metadata = dict(
        case=case,
        trial=trial,
        mitigator=mitigator,
        seed=seed,
        phase=phase,
        measurement_protocol_version=2,
        reverse=reverse,
        benign=benign,
        warmup=warmup,
        observation=observation,
        detector_mode=detector_mode,
        topology_size=len(config.HOSTS),
        window_seconds=config.WINDOW_SECONDS,
        profile_alpha=config.PROFILE_ALPHA,
        cumulative_lateral=config.CUMULATIVE_LATERAL_ENABLED,
        policy=policy,
        started_wall=time.time(),
    )
    meta_path = Path(log).with_suffix(".meta.json")
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n")
    controller = Controller(
        label, trial, mitigator, log, detector_mode=detector_mode,
        topology_size=topology_size, window_seconds=window_seconds,
        profile_alpha=profile_alpha, cumulative_lateral=cumulative_lateral,
        policy=policy,
    )
    net = workload = None
    reasons = []
    attacks = list(CASES[case].attacks)
    if reverse:
        attacks.reverse()
    try:
        controller.start()
        net = build_network()
        net.start()
        disable_offloads(net)
        net.staticArp()
        time.sleep(3)
        for name in list(config.WORKSTATIONS) + [config.ATTACKER]:
            target = config.HOST_TO_IP[config.APP_SERVER]
            connected = False
            for _attempt in range(3):
                output = net.get(name).cmd("ping -c 1 -W 2 " + target)
                if " 0% packet loss" in output:
                    connected = True
                    break
                time.sleep(1)
            if not connected:
                raise RuntimeError("connectivity failed for " + name)
        workload = Workload(net, label, trial)
        workload.controller = controller
        workload.start_measurements()
        workload.start_normal(
            duration=0,
            rate=CASES[case].normal_rate,
            seed=seed,
            peer_after=warmup if benign else None,
            rate_switch_after=(
                warmup + observation / 2 if phase == "calibration" else None
            ),
        )
        monitor(warmup, controller, workload)
        metadata["evaluation_start"] = time.time()
        events = read_events(log)
        ready = [
            e for e in events if e["kind"] == "detector_timing" and not e["warming_up"]
        ]
        if (
            not ready
            or config.HOST_TO_IP[config.ATTACKER] not in ready[-1]["eligible_hosts"]
        ):
            raise RuntimeError("attacker profile is not ready")
        for index, (module, args) in enumerate(attacks):
            code = workload.run_attack(
                module, extra_args=list(args) + ["--seed", str(seed + index)]
            )
            if code:
                raise RuntimeError("%s exited with %d" % (module, code))
        if not attacks:
            monitor(observation, controller, workload)
        metadata["recovery_start"] = time.time()
        monitor(DRAIN_SECONDS, controller, workload)
        dump_flows(net, log.replace(".jsonl", ".flows.txt"))
    except Exception as exc:
        reasons.append("%s: %s" % (type(exc).__name__, exc))
    finally:
        if workload:
            workload.stop()
        if net:
            net.stop()
        controller.stop()
    metadata["ended_wall"] = time.time()
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n")
    validity = validate_run(log, len(attacks))
    validity["reasons"] += reasons
    validity["valid"] = not validity["reasons"]
    Path(log).with_suffix(".validity.json").write_text(
        json.dumps(validity, indent=2) + "\n"
    )
    print(json.dumps(dict(log=log, **validity)), flush=True)
    if not validity["valid"]:
        raise RuntimeError("invalid run: " + "; ".join(validity["reasons"]))
    return log


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument("--trial", type=int, default=1)
    parser.add_argument("--mitigator", choices=config.MITIGATOR_MODES, default="none")
    parser.add_argument("--warmup", type=float, default=WARMUP_SECONDS)
    parser.add_argument("--seed", type=int, default=1001)
    parser.add_argument("--label")
    parser.add_argument("--phase", default="detection")
    parser.add_argument("--observation", type=float, default=60)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--benign", action="store_true")
    parser.add_argument("--detector-mode", choices=("both", "hybrid"), default="both")
    parser.add_argument("--topology-size", type=int)
    parser.add_argument("--window-seconds", type=float)
    parser.add_argument("--profile-alpha", type=float)
    parser.add_argument("--cumulative-lateral", action="store_true")
    parser.add_argument("--policy", choices=config.MITIGATION_POLICY_MODES, default="class")
    args = parser.parse_args()
    from mininet.log import setLogLevel

    setLogLevel("warning")
    run_trial(**vars(args))


if __name__ == "__main__":
    main()
