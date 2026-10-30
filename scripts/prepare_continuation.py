"""Write a source-pinned, explicit continuation manifest without touching history."""

import hashlib
import json
import argparse
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.run_all import continuation_plan
from experiments.campaign import source_hash


HISTORICAL = ROOT / "results/campaigns/native-extended-20-v6"
DEFAULT_OUTPUT = ROOT / "results/campaigns/native-extended-20-v6-continuation-20261029"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise SystemExit("refusing to overwrite existing continuation directory: " + str(output))
    historical_manifest = json.loads((HISTORICAL / "manifest.json").read_text())
    threshold_bytes = (HISTORICAL / "thresholds.json").read_bytes()
    threshold_checksum = hashlib.sha256(threshold_bytes).hexdigest()
    recorded_checksum = (HISTORICAL / "thresholds.sha256").read_text().strip()
    if threshold_checksum != recorded_checksum:
        raise SystemExit("historical threshold checksum mismatch")
    runs = continuation_plan(20)
    output.mkdir(parents=True)
    shutil.copyfile(HISTORICAL / "thresholds.json", output / "thresholds.json")
    shutil.copyfile(HISTORICAL / "thresholds.sha256", output / "thresholds.sha256")
    shutil.copyfile(HISTORICAL / "calibration.json", output / "calibration.json")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    working_tree = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    image_id = subprocess.check_output(
        ["docker", "image", "inspect", "lantern-sdn-ids", "--format", "{{.Id}}"],
        cwd=ROOT, text=True,
    ).strip()
    image_digests = json.loads(subprocess.check_output(
        ["docker", "image", "inspect", "lantern-sdn-ids", "--format", "{{json .RepoDigests}}"],
        cwd=ROOT, text=True,
    ))
    manifest = {
        "schema_version": 3,
        "created": datetime.now(timezone.utc).isoformat(),
        "revision": revision,
        "working_tree": working_tree,
        "image_id": image_id,
        "image_digests": image_digests,
        "source_hash": source_hash(),
        "source_snapshot_required": historical_manifest.get("source_hash") != source_hash(),
        "historical_campaign": str(HISTORICAL.relative_to(ROOT)).replace("\\", "/"),
        "historical_source_hash": historical_manifest.get("source_hash"),
        "historical_source_file_hash": (HISTORICAL / "source.sha256").read_text().strip(),
        "threshold_provenance": {
            "source": str(HISTORICAL.relative_to(ROOT)).replace("\\", "/"),
            "threshold_sha256": threshold_checksum,
            "calibration_sha256": hashlib.sha256((HISTORICAL / "calibration.json").read_bytes()).hexdigest(),
        },
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version,
        "command": ["python", "scripts/prepare_continuation.py"],
        "matrix": runs,
        "run_count": len(runs),
        "integrity": {
            "historical_results_immutable": True,
            "excluded_policy_cases": ["C2", "C3", "C4"],
            "policy_cases": ["C5"],
            "required_phases": {"hybrid": 80, "sweep": 45, "policy": 80},
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "source.sha256").write_text(manifest["source_hash"] + "\n")
    (output / "continuation-plan.json").write_text(json.dumps({"runs": runs, "count": len(runs)}, indent=2) + "\n")
    print(json.dumps({"output": str(output), "count": len(runs), "source_snapshot_required": manifest["source_snapshot_required"]}, indent=2))


if __name__ == "__main__":
    main()
