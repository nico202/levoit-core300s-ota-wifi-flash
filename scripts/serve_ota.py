#!/usr/bin/env python3
"""
serve_ota.py - minimal HTTP server used to deliver the OTA package during the
MITM. It answers 200 (with the package) for ANY path, so the exact URL the
device requests does not matter, and it logs every request so you can confirm
the device hit you.

Usage:
    ./serve_ota.py --port 18080 --file esphome_core300s_ota.bin
"""
from __future__ import annotations

import argparse
import http.server
import os
import socketserver
import sys
import time


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "vesync-ota/1.0"
    package_path = ""
    protocol_version = "HTTP/1.1"

    def _serve(self, body: bool) -> None:
        data = open(self.package_path, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if body:
            try:
                self.wfile.write(data)
            except BrokenPipeError:
                pass

    def log_message(self, fmt, *args):  # noqa: A003
        sys.stderr.write(
            f"[{time.strftime('%H:%M:%S')}] {self.client_address[0]} "
            f"{self.command} {self.path} UA={self.headers.get('User-Agent')!r}\n"
        )

    def do_GET(self):  # noqa: N802
        self._serve(True)

    def do_HEAD(self):  # noqa: N802
        self._serve(False)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):  # noqa: A003
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--file", required=True)
    args = ap.parse_args()
    Handler.package_path = args.file
    print(f"serving {args.file} ({os.path.getsize(args.file)} bytes) on {args.bind}:{args.port}",
          flush=True)
    with Server((args.bind, args.port), Handler) as httpd:
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
