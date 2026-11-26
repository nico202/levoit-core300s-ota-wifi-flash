#!/usr/bin/env python3
"""
cloud_ota.py - serve a 1.x VeSync OTA package and ask the VeSync cloud to push it.

The device downloads firmware over plain HTTP when the cloud sends it an
``upFirmware`` command.  Instead of ARP-spoofing ``fw.vesync.com`` (the approach
in ``host_mitm.sh``), this script submits the command through the cloud's
``bypassV2`` relay with a URL that points at this machine, so no root and no L2
tricks are needed:

    upFirmware {url: http://<dashed-lan-ip>.nip.io:<port>/fw.bin,
                newVersion: 2.0.00, pluginName: mainFw, upMode: 3}

The cloud forwards the command to the device; the device fetches the package
from us and flashes it.  ``upMode`` must be **3 or 4** (1/2 are rejected by the
firmware before it starts the download).  The URL must be a resolvable hostname
that passes the cloud's URL filter - a raw private IP is rejected with HTTP 403;
``<dashed-ip>.nip.io`` is accepted and resolves back to this machine.

Requires: ``pip install pyvesync``, and VESYNC_USERNAME / VESYNC_PASSWORD in the
environment.  Build the package first with ``make_ota_v1.py``.

Usage:
    export VESYNC_USERNAME='you@example.com' VESYNC_PASSWORD='...'
    ./cloud_ota.py --cid <device-cid> --package dist/pkg-v1.bin \
        --new-version 2.0.00 --port 18080

    # print the JSON and serve only, for triggering by other means:
    ./cloud_ota.py --package dist/pkg-v1.bin --print-json
"""
from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import os
import socket
import socketserver
import sys
import threading
import time
import uuid


def lan_ip() -> str:
    """Best-effort LAN address: prefer a physical 192.168/10/172 interface.

    A VPN/tunnel is often the default route, so connect()-based detection can
    return an address the purifier cannot reach; ``--host-ip`` overrides this.
    """
    import re
    import subprocess

    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
        candidates = []
        for block in re.split(r"^(?=\S)", out, flags=re.M):
            if not block.strip():
                continue
            name = block.split(":")[0].split()[0]
            if name.startswith(("lo", "utun", "tun", "tailscale", "docker", "bridge")):
                continue
            for match in re.finditer(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", block):
                candidates.append(match.group(1))
        if candidates:
            return candidates[0]
    except Exception:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


class OtaHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    image = b""
    hits = 0

    def do_GET(self):
        OtaHandler.hits += 1
        print(f"\n[ota] device fetched {self.path} from {self.client_address[0]} "
              f"UA={self.headers.get('User-Agent')!r}", flush=True)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(OtaHandler.image)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(OtaHandler.image)
        except Exception as exc:  # client disconnected early
            print(f"[ota] write failed: {exc!r}", flush=True)

    def log_message(self, fmt, *args):
        pass


def serve(package: bytes, port: int) -> socketserver.TCPServer:
    OtaHandler.image = package
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("0.0.0.0", port), OtaHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def build_command(cid: str, url: str, version: str, plugin: str, up_mode: int) -> dict:
    return {
        "method": "bypassV2",
        "cid": cid,
        "traceId": uuid.uuid4().hex,
        "payload": {
            "method": "upFirmware",
            "source": "APP",
            "data": {
                "newVersion": version,
                "pluginName": plugin,
                "url": url,
                "upMode": up_mode,
            },
        },
    }


async def inject(cmd: dict, country: str) -> int:
    try:
        from dataclasses import MISSING, fields
        from pyvesync import VeSync
        from pyvesync.models.vesync_models import RequestFirmwareModel
        from pyvesync.utils.helpers import Helpers
    except ImportError:
        print("[cloud] pyvesync is not installed: pip install pyvesync", file=sys.stderr)
        return 2

    user = os.environ.get("VESYNC_USERNAME")
    password = os.environ.get("VESYNC_PASSWORD")
    if not user or not password:
        print("[cloud] set VESYNC_USERNAME and VESYNC_PASSWORD", file=sys.stderr)
        return 2

    async with VeSync(user, password, country_code=country, redact=False) as manager:
        await manager.login()
        await manager.update()
        devices = list(manager.devices)
        if not devices:
            print("[cloud] no devices on this account", file=sys.stderr)
            return 1
        if not cmd["cid"]:
            cmd["cid"] = devices[0].cid
        # The API expects the standard manager context fields alongside the method.
        body = dict(cmd)
        try:
            body_fields = tuple(
                f.name for f in fields(RequestFirmwareModel)
                if f.default_factory is MISSING and f.default is MISSING
            )
            context = Helpers.get_manager_attributes(manager, body_fields)
            context.update(body)
            body = context
        except Exception as exc:
            print(f"[cloud] context build failed ({exc!r}); sending bare body", flush=True)
        resp, status = await manager.async_call_api(
            "/cloud/v2/deviceManaged/bypassV2", "post", json_object=body
        )
        print(f"[cloud] HTTP {status}\n{json.dumps(resp, indent=2)}", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Serve a 1.x OTA package and push it via the cloud.")
    ap.add_argument("--cid", default="", help="device cid (auto-detected for a single device)")
    ap.add_argument("--package", required=True, help="package built by make_ota_v1.py")
    ap.add_argument("--new-version", default="2.0.00", help="must match the package header")
    ap.add_argument("--plugin", default="mainFw")
    ap.add_argument("--up-mode", type=int, default=3, choices=[3, 4])
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--host-ip", default="", help="LAN IP to advertise (default: auto-detect)")
    ap.add_argument("--url", default="", help="override the advertised URL")
    ap.add_argument("--country", default=os.environ.get("VESYNC_COUNTRY", "US"))
    ap.add_argument("--print-json", action="store_true", help="print the command and do not call the cloud")
    ap.add_argument("--wait", type=int, default=300, help="seconds to watch for the device")
    args = ap.parse_args()

    package = open(args.package, "rb").read()
    if not package:
        print("empty package", file=sys.stderr)
        return 2
    if package[0] != 0x01:
        print(f"WARNING: package byte 0 is {package[0]:#04x}, not 0x01 "
              f"(not a 1.x package?)", file=sys.stderr)
    ip = args.host_ip or lan_ip()
    url = args.url or f"http://{ip.replace('.', '-')}.nip.io:{args.port}/fw.bin"
    cmd = build_command(args.cid, url, args.new_version, args.plugin, args.up_mode)

    print(f"[ota] serving {len(package)} bytes on 0.0.0.0:{args.port}")
    print(f"[ota] device URL: {url}")
    print("[cloud] command:\n" + json.dumps(cmd, indent=2), flush=True)
    serve(package, args.port)

    if args.print_json:
        print("[cloud] --print-json: not calling the API; Ctrl-C to stop", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return 0

    rc = asyncio.run(inject(cmd, args.country))
    if rc != 0:
        return rc

    print(f"\n[ota] waiting up to {args.wait}s for the device to fetch the package ...", flush=True)
    deadline = time.time() + args.wait
    while time.time() < deadline:
        if OtaHandler.hits:
            print("[ota] fetch seen. The device verifies the header/MD5, writes the inactive "
                  "slot and reboots into it; watch it come back on the new firmware.", flush=True)
            time.sleep(60)
            return 0
        time.sleep(1)
    print("[ota] no fetch. Check the cid, upMode=3, that the URL resolves, and that the "
          "cloud did not reject the URL (HTTP 403).", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
