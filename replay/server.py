"""Local-only static replay server, also usable from the portable export."""

import argparse
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit


def verified_inventory(root):
    expected = json.loads((root / "checksums.json").read_text())
    for name, checksum in expected.items():
        path = root / name
        if (Path(name).is_absolute() or ".." in Path(name).parts
                or path.is_symlink() or root.resolve() not in path.resolve().parents
                or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != checksum):
            raise ValueError("Replay checksum mismatch or unsafe file: " + name)
    return set(expected) | {"checksums.json"}


def make_handler(root):
    allowed = verified_inventory(root)

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def send_head(self):
            name = unquote(urlsplit(self.path).path).lstrip("/") or "index.html"
            if name not in allowed or ".." in Path(name).parts:
                self.send_error(404, "File not available in replay")
                return None
            return super().send_head()

        def end_headers(self):
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'")
            super().end_headers()

    return Handler


def serve(root, port=8000):
    root = Path(root).resolve()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(root))
    print("Lantern replay: http://localhost:%d (Ctrl+C to stop)" % server.server_port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        serve(Path(__file__).parent, args.port)
    except (OSError, ValueError) as exc:
        print("Replay cannot start: %s. Try another --port if occupied." % exc, file=sys.stderr)
        sys.exit(1)
