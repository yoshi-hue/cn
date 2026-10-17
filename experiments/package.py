"""Curate and verify an allowlisted source/evidence submission archive."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
from experiments.campaign import ROOT, source_files, verify_source
from experiments.analyze import analyze, discover_runs, read_events


def hashes(directory):
    return {
        str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.rglob("*"))
        if p.is_file() and p.name != "checksums.json"
    }


def inspect_text(paths):
    # Deliberately narrow patterns avoid treating test network IPs and UUIDs
    # as credentials. Findings are paths only; never echo matched secrets.
    patterns = [
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"AKIA[A-Z0-9]{16}",
        r"sk-proj-[A-Za-z0-9_-]{40,}",
        r"[/]Users[/][^/\s]+[/]",
        r"[/]home[/][^/\s]+[/]",
    ]
    findings = []
    for path in paths:
        try:
            text = path.read_text()
        except (UnicodeError, OSError):
            continue
        if any(re.search(pattern, text) for pattern in patterns):
            findings.append(str(path))
    return findings


def curate(campaign, destination):
    verify_source(campaign, check_image=False)
    if destination.exists():
        raise FileExistsError(destination)
    runs = discover_runs(campaign)
    valid = []
    for r in runs:
        p = Path(r["log"])
        if (
            p.with_suffix(".validity.json").exists()
            and json.loads(p.with_suffix(".validity.json").read_text())["valid"]
        ):
            valid.append(r)
    expected = json.loads((campaign / "manifest.json").read_text())["matrix"]
    identities = set()
    for r in valid:
        m = json.loads(Path(r["log"]).with_suffix(".meta.json").read_text())
        identities.add((m["phase"], m["case"], m["mitigator"], m["trial"]))
    missing = [
        r
        for r in expected
        if (r["phase"], r["case"], r["mitigator"], r["trial"]) not in identities
    ]
    if missing:
        raise RuntimeError("%d evaluation conditions missing" % len(missing))
    destination.mkdir(parents=True)
    # Strip machine-local argv and status descriptions from public metadata;
    # retain content hashes, versions, seed policy and relative reproduction commands.
    manifest = json.loads((campaign / "manifest.json").read_text())
    manifest.pop("command", None)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for name in [
        "thresholds.json",
        "thresholds.sha256",
        "calibration.json",
        "dependencies.txt",
        "source.sha256",
    ]:
        shutil.copyfile(campaign / name, destination / name)
    # All attempts are preserved, including invalid ones. Copy known evidence
    # extensions only; excludes process diagnostics that may embed local paths.
    for r in runs:
        p = Path(r["log"])
        relative = p.parent.relative_to(campaign)
        target = destination / "evidence" / relative
        target.mkdir(parents=True, exist_ok=True)
        for source in p.parent.glob(p.stem + "*"):
            if source.suffix in (".jsonl", ".json", ".txt"):
                shutil.copyfile(source, target / source.name)
    analyze(destination / "evidence", destination / "tables")
    (destination / "checksums.json").write_text(
        json.dumps(hashes(destination), indent=2) + "\n"
    )
    verify(destination)


def verify(directory):
    expected = json.loads((directory / "checksums.json").read_text())
    if hashes(directory) != expected:
        raise RuntimeError("evidence checksum mismatch")
    findings = inspect_text([p for p in directory.rglob("*") if p.is_file()])
    if findings:
        raise RuntimeError(
            "review potential sensitive content in: " + ", ".join(findings)
        )
    # Recompute in temporary output and compare every CSV byte-for-byte.
    import tempfile

    with tempfile.TemporaryDirectory() as temporary:
        analyze(directory / "evidence", temporary)
        for table in (directory / "tables").glob("*.csv"):
            if table.read_bytes() != (Path(temporary) / table.name).read_bytes():
                raise RuntimeError("table does not reproduce: " + table.name)
    return True


def archive(directory, output):
    verify(directory)
    docs = [ROOT / name for name in ["README.md", "AUTHORS.md", "ATTRIBUTION.md"]]
    docs += list((ROOT / "docs").glob("*.md"))
    files = source_files() + [p for p in docs if p.exists()]
    findings = inspect_text(files)
    if findings:
        raise RuntimeError("review source content in: " + ", ".join(findings))
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    with tarfile.open(output, "w:gz") as tar:
        for source in files:
            tar.add(
                source,
                arcname="lantern/" + str(source.relative_to(ROOT)),
                recursive=False,
            )
        for source in sorted(directory.rglob("*")):
            if source.is_file():
                tar.add(
                    source,
                    arcname="lantern/submission/" + str(source.relative_to(directory)),
                    recursive=False,
                )
    with tarfile.open(output) as tar:
        for member in tar.getmembers():
            if (
                not member.isfile()
                or ".." in Path(member.name).parts
                or Path(member.name).is_absolute()
            ):
                raise RuntimeError("unexpected archive member")
            if any(
                x in Path(member.name).parts for x in [".git", "__pycache__", ".venv"]
            ):
                raise RuntimeError("excluded content entered archive")
    output.with_suffix(output.suffix + ".sha256").write_text(
        hashlib.sha256(output.read_bytes()).hexdigest() + "  " + output.name + "\n"
    )
    print("archive verified: " + str(output))


def main():
    p = argparse.ArgumentParser(__doc__)
    p.add_argument("action", choices=["curate", "verify", "archive"])
    p.add_argument("--campaign", type=Path)
    p.add_argument("--submission", type=Path, default=Path("submission"))
    p.add_argument(
        "--output", type=Path, default=Path("output/lantern-submission.tar.gz")
    )
    args = p.parse_args()
    if args.action == "curate":
        curate(args.campaign.resolve(), args.submission)
    elif args.action == "verify":
        verify(args.submission)
        print("evidence and tables verified")
    else:
        archive(args.submission, args.output)


if __name__ == "__main__":
    main()
