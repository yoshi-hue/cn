"""Serve or export a supplementary replay without changing frozen sources."""

import argparse
import sys
import tempfile
from pathlib import Path
import zipfile

from .data import DEFAULT_SUBMISSION, prepare
from .server import serve

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for action in ("serve", "export"):
        p = sub.add_parser(action)
        p.add_argument("--submission", type=Path, default=ROOT / DEFAULT_SUBMISSION)
        if action == "serve":
            p.add_argument("--port", type=int, default=8000)
        else:
            p.add_argument("--output", type=Path, default=ROOT / "output/lantern-replay.zip")
    args = parser.parse_args()
    try:
        if args.command == "serve":
            # Fresh directory prevents stale or concurrent generations being served.
            parent = ROOT / "output/replay"
            parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="viewer-", dir=parent) as folder:
                runs = prepare(args.submission, Path(folder))
                print("Verified and prepared %d recorded runs." % len(runs), flush=True)
                serve(folder, args.port)
        else:
            if args.output.exists():
                raise FileExistsError("Export already exists: " + str(args.output))
            with tempfile.TemporaryDirectory() as folder:
                prepare(args.submission, Path(folder))
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(args.output, "x", zipfile.ZIP_DEFLATED) as archive:
                    for path in sorted(Path(folder).rglob("*")):
                        if path.is_file():
                            info = zipfile.ZipInfo("lantern-replay/" + str(path.relative_to(folder)))
                            info.compress_type = zipfile.ZIP_DEFLATED
                            info.external_attr = 0o644 << 16
                            archive.writestr(info, path.read_bytes())
            print("Portable replay exported: " + str(args.output))
    except (OSError, ValueError, KeyError, StopIteration) as exc:
        hint = " Choose another --port, for example 8001." if isinstance(exc, OSError) and exc.errno in (48, 98) else ""
        print("Replay error: %s%s" % (exc, hint), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
