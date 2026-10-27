"""Pure experiment planner; no Mininet or Docker imports."""

import argparse
import json
from experiments.run_case import WARMUP_SECONDS, DRAIN_SECONDS


def plan(trials=5, warmup=WARMUP_SECONDS):
    runs = []

    def add(case, phase, actuator="none", **extra):
        for trial in range(1, trials + 1):
            runs.append(
                dict(
                    case=case,
                    phase=phase,
                    mitigator=actuator,
                    trial=trial,
                    seed=20000 + trial * 100,
                    warmup=warmup,
                    label="%s-%s-%s" % (phase, case, actuator),
                    **extra,
                )
            )

    for case in ["C1", "C2", "C3", "C4", "C5", "C6", "C7"]:
        add(case, "detection")
    for case in ["C2", "C3", "C4", "C5", "C6"]:
        for actuator in ["baseline", "graph"]:
            add(case, "mitigation", actuator)
    add("C1", "benign", benign=True)
    add("C7", "order", reverse=True)
    return runs


def extended_plan(trials=20, warmup=WARMUP_SECONDS):
    """Submission-complete matrix: >=20 trials/class on >=20 hosts.

    The returned plan is declarative; execute it in Docker/Mininet with the
    campaign driver. No result is claimed until those runs produce evidence.
    """
    runs = []
    for case in ("C2", "C3", "C4", "C5"):
        for trial in range(1, trials + 1):
            runs.append(dict(case=case, phase="large20", mitigator="none",
                             trial=trial, seed=30000 + trial,
                             warmup=warmup, topology_size=20,
                             label="large20-%s-none" % case))
    # Direct control for the reviewer's definitional concern: the cumulative
    # threshold baseline is evaluated beside the graph detector on identical
    # 20-host lateral-movement trials, with actuation disabled.
    for trial in range(1, trials + 1):
        runs.append(dict(case="C5", phase="control", mitigator="none",
                         trial=trial, seed=35000 + trial,
                         warmup=warmup, topology_size=20,
                         cumulative_lateral=True,
                         label="control20-C5-none"))
    for detector in ("baseline", "graph"):
        for policy in ("source", "pair"):
            for case in ("C2", "C3", "C4", "C5"):
                for trial in range(1, trials + 1):
                    runs.append(dict(case=case, phase="policy", mitigator=detector,
                                     policy=policy, trial=trial,
                                     seed=36000 + trial, warmup=warmup,
                                     topology_size=20,
                                     label="policy20-%s-%s-%s" % (detector, policy, case)))
    for window in (5.0, 10.0, 20.0):
        for alpha in (0.1, 0.2, 0.4):
            for trial in range(1, 6):
                runs.append(dict(case="C5", phase="sweep", mitigator="none",
                                 trial=trial, seed=40000 + trial,
                                 warmup=12 * window + 15, window_seconds=window,
                                 profile_alpha=alpha,
                                 label="sweep-C5-w%s-a%s" % (window, alpha)))
    for case in ("C2", "C3", "C4", "C5"):
        for trial in range(1, trials + 1):
            runs.append(dict(case=case, phase="hybrid", mitigator="hybrid",
                             detector_mode="hybrid", trial=trial,
                             seed=50000 + trial, warmup=warmup,
                             topology_size=20, cumulative_lateral=True,
                             label="hybrid20-%s" % case))
    return runs


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--warmup", type=float, default=WARMUP_SECONDS)
    parser.add_argument("--extended", action="store_true")
    args = parser.parse_args()
    runs = extended_plan(args.trials, args.warmup) if args.extended else plan(args.trials, args.warmup)
    print(json.dumps(dict(runs=runs, count=len(runs)), indent=2))


if __name__ == "__main__":
    main()
