"""Real HTTP delivery probes; results are independent of controller decisions."""

import argparse
import json
import signal
import time
import urllib.request

running = True


def stop(*_):
    global running
    running = False


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, stop)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with open(args.output, "x", buffering=1) as handle:
        while running:
            wall = time.time()
            start = time.monotonic()
            error = None
            try:
                with opener.open(
                    "http://%s:8000/" % args.target, timeout=1
                ) as response:
                    success = (
                        response.status == 200 and response.read() == b"lantern-ok\n"
                    )
            except Exception as exc:
                success, error = False, type(exc).__name__
            handle.write(
                json.dumps(
                    dict(
                        kind="probe",
                        wall=wall,
                        src=args.source,
                        dst=args.target,
                        success=success,
                        error=error,
                        latency=time.monotonic() - start,
                    )
                )
                + "\n"
            )
            time.sleep(max(0, args.interval - (time.monotonic() - start)))


if __name__ == "__main__":
    main()
