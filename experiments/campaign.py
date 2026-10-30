"""Host-side campaign execution with immutable provenance and bounded retries."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from experiments.run_all import plan, extended_plan
from experiments.run_case import WARMUP_SECONDS
from experiments.validation import read_events

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("IMAGE", "lantern-sdn-ids")


def command_output(command):
    if command and command[0] == "docker":
        command = [os.environ.get("LANTERN_DOCKER", "docker")] + command[1:]
    return subprocess.check_output(command, cwd=str(ROOT), text=True).strip()


def git_metadata():
    try:
        return {
            "revision": command_output(["git", "rev-parse", "HEAD"]),
            "working_tree": command_output(["git", "status", "--porcelain"]),
        }
    except subprocess.CalledProcessError:
        return {"revision": None, "working_tree": "source archive (no Git metadata)"}


def source_files():
    # Explicit source inventory, including new files before a user commits.
    paths = []
    for directory in [
        "lantern",
        "experiments",
        "traffic",
        "topo",
        "tests",
        "scripts",
        "docker",
    ]:
        paths += [
            p
            for p in (ROOT / directory).rglob("*")
            if p.is_file()
            and "__pycache__" not in p.parts
            and p.suffix not in (".pyc",)
        ]
    paths += [
        ROOT / name
        for name in ["Makefile", ".gitignore", ".dockerignore"]
        if (ROOT / name).exists()
    ]
    return sorted(paths)


def source_hash():
    digest = hashlib.sha256()
    for path in source_files():
        digest.update(
            str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0"
        )
    return digest.hexdigest()


def container_command(run, raw, frozen=None):
    native = os.environ.get("LANTERN_NATIVE") == "1"
    receiver_health_timeout = os.environ.get("LANTERN_RECEIVER_HEALTH_TIMEOUT")
    if native:
        command = ["python3", "-m", "experiments.run_case"]
        command = ["env", "LANTERN_RAW=" + str(raw)] + command
        if receiver_health_timeout:
            command.insert(1, "LANTERN_RECEIVER_HEALTH_TIMEOUT=" + receiver_health_timeout)
        if frozen:
            command.insert(1, "LANTERN_CONFIG=" + str(frozen))
    else:
        docker_cli = os.environ.get("LANTERN_DOCKER", "docker")
        volume_root = str(ROOT)
        if docker_cli.lower().endswith(".exe") and os.name != "nt":
            volume_root = subprocess.check_output(
                ["wslpath", "-w", str(ROOT)], text=True
            ).strip()
        command = [
            docker_cli,
            "run",
            "--rm",
            "--privileged",
            "--network",
            "none",
            "-w",
            "/opt/lantern",
            "-v",
            volume_root + ":/opt/lantern",
            "-e",
            "LANTERN_RAW=" + str(raw.relative_to(ROOT)).replace("\\", "/"),
        ]
        if frozen:
            command += [
                "-e",
                "LANTERN_CONFIG=" + str(frozen.relative_to(ROOT)).replace("\\", "/"),
            ]
        if receiver_health_timeout:
            command += ["-e", "LANTERN_RECEIVER_HEALTH_TIMEOUT=" + receiver_health_timeout]
        command += [IMAGE, "python3", "-m", "experiments.run_case"]
    flag_names = {
        "topology_size": "topology-size",
        "window_seconds": "window-seconds",
        "profile_alpha": "profile-alpha",
        "detector_mode": "detector-mode",
        "cumulative_lateral": "cumulative-lateral",
        "policy": "policy",
    }
    for key, value in run.items():
        flag = flag_names.get(key, key)
        if isinstance(value, bool):
            if value:
                command += ["--" + flag]
        else:
            command += ["--" + flag, str(value)]
    return command


def create(directory):
    directory.mkdir(parents=True, exist_ok=False)
    image = json.loads(command_output(["docker", "image", "inspect", IMAGE]))[0]
    dependencies = command_output(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            IMAGE,
            "-c",
            "python3 -m pip freeze && dpkg-query -W",
        ]
    )
    manifest = dict(
        schema_version=2,
        created=datetime.now(timezone.utc).isoformat(),
        revision=git_metadata()["revision"],
        source_hash=source_hash(),
        working_tree=git_metadata()["working_tree"],
        image_id=image["Id"],
        image_digests=image.get("RepoDigests", []),
        platform=platform.platform(),
        machine=platform.machine(),
        python=sys.version,
        command=sys.argv,
        matrix=plan(),
        calibration_seeds=[11001, 11002, 11003],
        note="95 evaluation runs; the requested matrix arithmetic was corrected from 105.",
    )
    from lantern import config

    def convert(value):
        if isinstance(value, set):
            return sorted(value)
        raise TypeError(type(value).__name__)

    manifest["configuration"] = {
        k: v for k, v in vars(config).items() if k.isupper() and not k.startswith("_")
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, default=convert) + "\n"
    )
    (directory / "dependencies.txt").write_text(dependencies + "\n")
    (directory / "source.sha256").write_text(manifest["source_hash"] + "\n")
    return manifest


def verify_source(directory, check_image=True):
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["source_hash"] != source_hash():
        raise RuntimeError(
            "source changed since campaign creation; create a new campaign"
        )
    # Native WSL runs use the host's Mininet/OVS and native Ryu; they do not
    # require the Docker daemon or image. Keep the image check for container
    # campaigns, while allowing native campaigns to proceed offline.
    check_image = check_image and os.environ.get("LANTERN_NATIVE") != "1"
    if check_image:
        current = json.loads(command_output(["docker", "image", "inspect", IMAGE]))[0][
            "Id"
        ]
        if current != manifest["image_id"]:
            raise RuntimeError("container image changed")
    return manifest


def execute(directory, runs, frozen=None):
    verify_source(directory)
    records = []
    for number, run in enumerate(runs, 1):
        verify_source(directory)
        success = False
        max_attempts = int(os.environ.get("LANTERN_MAX_ATTEMPTS", "10"))
        for attempt in range(1, max_attempts + 1):
            # Separate directories retain every attempt. Existing successful
            # attempts are resumable; a partially written attempt is never reused.
            raw = directory / run["phase"] / ("attempt-%d" % attempt) / "raw"
            log = raw / ("%s_trial%02d.jsonl" % (run["label"], run["trial"]))
            validity = log.with_suffix(".validity.json")
            if validity.exists() and json.loads(validity.read_text()).get("valid"):
                success = True
                break
            if raw.exists() and list(raw.glob(log.stem + "*")):
                continue
            raw.mkdir(parents=True, exist_ok=True)
            driver_log = raw.parent / (log.stem + ".driver.log")
            # A prior interrupted run may have left the attempt-level driver
            # log behind even when the raw directory is incomplete. Preserve
            # that attempt and use the next one rather than failing on open("x").
            if driver_log.exists():
                continue
            # Native Mininet runs can leave a namespace/veth behind after an
            # invalid startup. Clear only Mininet's own state before retrying.
            if os.environ.get("LANTERN_NATIVE") == "1" and os.environ.get("LANTERN_NATIVE_CLEAN") == "1":
                subprocess.run(
                    ["mn", "-c"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            cmd = container_command(run, raw, frozen)
            print(
                "[%d/%d] %s trial %d attempt %d"
                % (number, len(runs), run["label"], run["trial"], attempt),
                flush=True,
            )
            started = time.time()
            with driver_log.open("x") as output:
                result = subprocess.run(
                    cmd, cwd=str(ROOT), stdout=output, stderr=subprocess.STDOUT
                )
            record = dict(
                run=run,
                attempt=attempt,
                command=cmd,
                seconds=time.time() - started,
                exit_code=result.returncode,
            )
            records.append(record)
            with (directory / "execution.jsonl").open("a") as handle:
                handle.write(json.dumps(record) + "\n")
            if (
                result.returncode == 0
                and validity.exists()
                and json.loads(validity.read_text()).get("valid")
            ):
                success = True
                break
            print("  invalid attempt retained", flush=True)
        if not success:
            raise RuntimeError("two attempts failed; inspect " + str(log))
        if (
            os.environ.get("LANTERN_STOP_AFTER_CONTROL_C5") == "1"
            and run.get("label") == "control20-C5-none"
            and run.get("trial") == 20
        ):
            print("control C5 trial 20 complete; stopping at requested boundary", flush=True)
            return records
    verify_source(directory)
    return records


def calibrate(directory, topology_size=None):
    runs = [
        dict(
            case="C1",
            phase="calibration",
            mitigator="none",
            trial=i,
            seed=11000 + i,
            warmup=WARMUP_SECONDS,
            observation=600,
            label="calibration-C1-none",
        )
        for i in range(1, 4)
    ]
    if topology_size:
        for run in runs:
            run["topology_size"] = topology_size
    execute(directory, runs)
    from experiments.analyze import discover_runs

    maxima = dict(
        PORTSCAN_PORTS=0.0,
        PORTSCAN_HOSTS=0.0,
        DOS_PPS=0.0,
        BRUTEFORCE_ATTEMPTS=0.0,
        GRAPH_SCORE_THRESHOLD=0.0,
    )
    rows = []
    for run in discover_runs(directory / "calibration"):
        path = Path(run["log"])
        if not json.loads(path.with_suffix(".validity.json").read_text())["valid"]:
            continue
        meta = json.loads(path.with_suffix(".meta.json").read_text())
        for event in read_events(path):
            if (
                event["kind"] != "detector_timing"
                or event.get("warming_up")
                or not meta["evaluation_start"]
                <= event["wall"]
                <= meta["recovery_start"]
            ):
                continue
            values = dict(
                event["baseline_features"],
                GRAPH_SCORE_THRESHOLD=event.get("top_score") or 0,
            )
            rows.append(dict(run=path.stem, window=event["window_index"], **values))
            for key, value in values.items():
                maxima[key] = max(maxima[key], value)
    if len(rows) < 150:
        raise RuntimeError("insufficient calibration observations")
    import math

    thresholds = {key: math.ceil(value * 1.25 + 1) for key, value in maxima.items()}
    path = directory / "thresholds.json"
    if path.exists():
        if json.loads(path.read_text()) != thresholds:
            raise RuntimeError("frozen thresholds would change")
    else:
        path.write_text(json.dumps(thresholds, indent=2) + "\n")
    (directory / "calibration.json").write_text(
        json.dumps(
            dict(
                rule="ceil(1.25 * maximum normal-only value + 1)",
                maxima=maxima,
                thresholds=thresholds,
                observations=rows,
                frozen_design="weights, variance floors, warmup and online profile policy unchanged",
            ),
            indent=2,
        )
        + "\n"
    )
    (directory / "thresholds.sha256").write_text(
        hashlib.sha256(path.read_bytes()).hexdigest() + "\n"
    )
    print("frozen thresholds: " + json.dumps(thresholds), flush=True)


def import_thresholds(directory, source):
    """Reuse pre-existing normal-only calibration without tuning on new attacks."""
    from experiments.package import hashes
    source = Path(source).resolve()
    checksum_path = source / "checksums.json"
    if checksum_path.exists() and hashes(source) != json.loads(checksum_path.read_text()):
        raise RuntimeError("calibration source evidence checksum mismatch")
    thresholds = source / "thresholds.json"
    checksum = hashlib.sha256(thresholds.read_bytes()).hexdigest()
    if checksum != (source / "thresholds.sha256").read_text().strip():
        raise RuntimeError("imported threshold checksum mismatch")
    expected = {"PORTSCAN_PORTS", "PORTSCAN_HOSTS", "DOS_PPS",
                "BRUTEFORCE_ATTEMPTS", "GRAPH_SCORE_THRESHOLD"}
    values = json.loads(thresholds.read_text())
    if set(values) != expected or any(not isinstance(v, (int, float)) or v <= 0 for v in values.values()):
        raise ValueError("invalid imported detector thresholds")
    import shutil
    for name in ("thresholds.json", "thresholds.sha256", "calibration.json"):
        destination = directory / name
        if destination.exists():
            raise FileExistsError(destination)
        shutil.copyfile(source / name, destination)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["measurement_protocol_version"] = 2
    manifest["calibration_provenance"] = dict(
        mode="reused", source=source.name, threshold_sha256=checksum,
        calibration_sha256=hashlib.sha256((source / "calibration.json").read_bytes()).hexdigest(),
        source_hash=json.loads((source / "manifest.json").read_text())["source_hash"],
    )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


def pilot_matrix():
    return [dict(case=case, phase="pilot", mitigator=mode, trial=1,
                 seed=9101, warmup=WARMUP_SECONDS, label="pilot-%s-%s" % (case, mode))
            for case in ("C2", "C3", "C4", "C5") for mode in ("none", "baseline", "graph")]


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument(
        "action", choices=["create", "pilot", "calibrate", "evaluate", "extended", "all", "verify"]
    )
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--thresholds-from", type=Path, help="reuse a verified calibration directory")
    parser.add_argument("--topology-size", type=int, help="topology size for native calibration")
    args = parser.parse_args()
    directory = (ROOT / args.campaign).resolve()
    if ROOT not in directory.parents:
        raise ValueError("campaign must be inside the checkout")
    if args.action in ("create", "all"):
        create(directory)
        if args.thresholds_from:
            import_thresholds(directory, args.thresholds_from)
    if args.action == "verify":
        print(json.dumps(verify_source(directory), indent=2))
    if args.action == "all" and not args.thresholds_from:
        calibrate(directory, args.topology_size)
    if args.action in ("pilot", "all"):
        frozen = directory / "thresholds.json"
        if not frozen.exists():
            raise RuntimeError("pilot requires frozen thresholds; import or calibrate first")
        records = execute(directory, pilot_matrix(), frozen)
        if records:
            duration = sum(r["seconds"] for r in records) / len(records)
            print("Measured pilot mean %.1fs; evaluation at least %.1f hours plus mixed-case time."
                  % (duration, duration * 95 / 3600), flush=True)
        from experiments.analyze import discover_runs, score_run
        for run in discover_runs(directory / "pilot"):
            result = score_run(run)

            for row in result["containment"]:
                if row.get("blocking_outcome") in (
                    "insufficient_post_confirmation_traffic", "unavailable_receiver_evidence"
                ):
                    raise RuntimeError("pilot cannot measure blocking: " + str(row))
    if args.action == "extended":
        frozen = directory / "thresholds.json"
        if not frozen.exists():
            raise RuntimeError("extended evaluation requires frozen thresholds")
        records = execute(directory, extended_plan(20), frozen)
        print("extended evaluation complete: %d runs" % len(records), flush=True)
    if args.action == "calibrate":
        calibrate(directory, args.topology_size)
    if args.action in ("evaluate", "all"):
        frozen = directory / "thresholds.json"
        if not frozen.exists():
            raise RuntimeError("calibrate before evaluation")
        if (
            hashlib.sha256(frozen.read_bytes()).hexdigest()
            != (directory / "thresholds.sha256").read_text().strip()
        ):
            raise RuntimeError("frozen threshold checksum changed")
        execute(directory, plan(), frozen)
        print("evaluation complete; analyze and package this campaign", flush=True)


if __name__ == "__main__":
    main()
