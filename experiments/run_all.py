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


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--warmup", type=float, default=WARMUP_SECONDS)
    args = parser.parse_args()
    runs = plan(args.trials, args.warmup)
    print(json.dumps(dict(runs=runs, count=len(runs)), indent=2))


if __name__ == "__main__":
    main()
