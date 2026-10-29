"""Prepare or run isolated native workers for the unfinished extended plan."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.run_all import extended_plan

SOURCE = ROOT / "results/campaigns/native-extended-20-v6"
PARALLEL = Path(os.environ.get(
    "LANTERN_PARALLEL_ROOT",
    str(ROOT / "results/campaigns/native-extended-20-v6-parallel"),
))
METADATA = ("manifest.json", "dependencies.txt", "source.sha256",
            "thresholds.json", "thresholds.sha256", "calibration.json")


def setup(workers):
    remaining = extended_plan(20)[100:]
    PARALLEL.mkdir(parents=True, exist_ok=True)
    for index in range(workers):
        directory = PARALLEL / ("worker-%02d" % (index + 1))
        directory.mkdir(exist_ok=True)
        if (directory / "execution.jsonl").exists():
            raise RuntimeError("worker already has results; use --run to resume: " + str(directory))
        for name in METADATA:
            shutil.copy2(SOURCE / name, directory / name)
        runs = remaining[index::workers]
        (directory / "worker_plan.json").write_text(json.dumps(runs, indent=2) + "\n")
        (directory / "worker.conf").write_text(
            "worker=%d\ncontroller_port=%d\nrun_count=%d\n"
            % (index + 1, 16661 + index, len(runs))
        )
    print("prepared %d workers for %d remaining runs" % (workers, len(remaining)))


def run_worker(directory):
    runs = json.loads((directory / "worker_plan.json").read_text())
    from experiments.campaign import execute
    execute(directory, runs, directory / "thresholds.json")


def run(workers, container_mode=False):
    processes = []
    for index in range(workers):
        directory = PARALLEL / ("worker-%02d" % (index + 1))
        log = (directory / "worker.log").open("a", buffering=1)
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        if container_mode:
            env.pop("LANTERN_NATIVE", None)
            env.pop("LANTERN_NATIVE_CLEAN", None)
            env.pop("LANTERN_WORKER_PREFIX", None)
            env["LANTERN_CONTROLLER_PORT"] = "6653"
            env["LANTERN_DOCKER"] = "docker" if os.name == "nt" else "docker.exe"
        else:
            env.update(
                LANTERN_NATIVE="1",
                LANTERN_NATIVE_CLEAN="0",
                LANTERN_WORKER_PREFIX="w%02d_" % (index + 1),
                LANTERN_CONTROLLER_PORT=str(16661 + index),
            )
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--worker", str(directory)],
            cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        processes.append((process, log, directory))
    failures = 0
    for process, log, directory in processes:
        code = process.wait()
        log.close()
        print("%s exited %d" % (directory.name, code), flush=True)
        failures += code != 0
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--worker")
    parser.add_argument("--output-root")
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    if args.output_root:
        global PARALLEL
        PARALLEL = (ROOT / args.output_root).resolve()
    if args.worker:
        run_worker(Path(args.worker).resolve())
        return
    if not 1 <= args.workers <= 4:
        raise SystemExit("workers must be between 1 and 4")
    if not args.run:
        setup(args.workers)
        return
    return run(args.workers, container_mode=args.container)


if __name__ == "__main__":
    raise SystemExit(main() or 0)
