#!/usr/bin/env python3
"""
cloud_ota.py - serve a VeSync OTA package and ask the VeSync cloud to push it.

The device downloads firmware over HTTP when the cloud sends it an
``upFirmware`` command.  Instead of ARP-spoofing ``fw.vesync.com`` (the approach
in ``host_mitm.sh``), this script submits the command through the cloud's
``bypassV2`` relay with a URL that points at this machine, so no root and no L2
tricks are needed:

    bypassV2 -> upFirmware {url, newVersion, pluginName, upMode}        (1.x)
    bypassV2 -> upFirmware {urlV1, newVersion, pluginName, upMode}      (2.x, --v2)

The cloud forwards the command to the device; the device fetches the package
from us and flashes it.  ``upMode`` must be **3 or 4**.  The URL must be a
resolvable hostname that passes the cloud's URL filter - a raw private IP is
rejected with HTTP 403; ``<dashed-ip>.nip.io`` is accepted and resolves back to
this machine.

Two container generations exist:

    v1 (1.0.00)  [0x01][AES-128-CBC header][app]   built by make_ota_v1.py
    v2 (2.x)     [plaintext 128-byte header][app]  built by make_ota.py

The 2.x handler reads ``urlV1`` and queues the OTA on its event loop; the 1.x
handler reads ``url`` and starts the download task directly.  Use ``--v2`` for
2.x units.

Requires: ``pip install pyvesync``, and VESYNC_USERNAME / VESYNC_PASSWORD.

Usage:
    export VESYNC_USERNAME='you@example.com' VESYNC_PASSWORD='...'

    # 1.x: build and deliver in one go
    ./cloud_ota.py --cid <cid> --build-from firmware.ota.bin \\
        --new-version 2.0.00 --model LAP-C302S-WGC --hw 1.0 --region AE

    # 2.x
    ./cloud_ota.py --v2 --cid <cid> --build-from firmware.ota.bin \\
        --new-version 2.0.00 --name Core300s --region EU

    # a package built earlier (make_ota_v1.py or make_ota.py)
    ./cloud_ota.py --cid <cid> --package dist/pkg-v1.bin --new-version 2.0.00

    # print the command and serve only, for triggering by other means
    ./cloud_ota.py --v2 --package dist/pkg-v2.bin --print-json
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import http.server
import json
import os
import socket
import socketserver
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


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


def build_package(args) -> bytes:
    if args.package:
        return open(args.package, "rb").read()
    app = open(args.build_from, "rb").read()
    if not app or app[0] != 0xE9:
        raise SystemExit("--build-from must be an ESP32 application image (starts 0xE9)")
    if args.v2:
        import make_ota  # plaintext 128-byte header
        md5 = hashlib.md5(app).hexdigest()
        return make_ota.build_header(md5, args.name, args.new_version, args.region) + app
    import make_ota_v1  # encrypted 1.x container
    pkg, _ = make_ota_v1.build_package(
        app, args.model, args.new_version, args.hw, args.region
    )
    return pkg


def build_command(cid: str, url: str, version: str, plugin: str, up_mode: int,
                  v2: bool) -> dict:
    data = {
        "newVersion": version,
        "pluginName": plugin,
        ("urlV1" if v2 else "url"): url,
        "upMode": up_mode,
    }
    return {
        "method": "bypassV2",
        "cid": cid,
        "traceId": uuid.uuid4().hex,
        "payload": {"method": "upFirmware", "source": "APP", "data": data},
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
    ap = argparse.ArgumentParser(description="Serve an OTA package and push it via the cloud.")
    ap.add_argument("--cid", default="", help="device cid (auto-detected for a single device)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--package", help="package built by make_ota_v1.py (v1) or make_ota.py (v2)")
    src.add_argument("--build-from", metavar="APP", help="build the package from an ESP32 app image")
    ap.add_argument("--v2", action="store_true",
                    help="2.x device/container: plaintext header, send 'urlV1'")
    ap.add_argument("--new-version", default="2.0.00", help="must match the package header")
    ap.add_argument("--plugin", default="mainFw")
    ap.add_argument("--up-mode", type=int, default=3, choices=[3, 4])
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--host-ip", default="", help="LAN IP to advertise (default: auto-detect)")
    ap.add_argument("--url", default="", help="override the advertised URL")
    ap.add_argument("--country", default=os.environ.get("VESYNC_COUNTRY", "US"))
    ap.add_argument("--model", default="LAP-C302S-WGC", help="1.x model string")
    ap.add_argument("--hw", default="1.0", help="1.x hardware version")
    ap.add_argument("--name", default="Core300s", help="2.x device name")
    ap.add_argument("--region", default="", help="region list (default: AE for 1.x, EU for 2.x)")
    ap.add_argument("--print-json", action="store_true", help="print the command and do not call the cloud")
    ap.add_argument("--wait", type=int, default=300, help="seconds to watch for the device")
    args = ap.parse_args()
    args.region = args.region or ("EU" if args.v2 else "AE")

    package = build_package(args)
    if not package:
        print("empty package", file=sys.stderr)
        return 2
    if args.v2:
        if not chr(package[0]).upper() in "0123456789ABCDEF":
            print(f"WARNING: package starts with {package[0]:#04x}, not an MD5 hex digit - "
                  f"is this a 2.x (make_ota.py) package?", file=sys.stderr)
    elif package[0] != 0x01:
        print(f"WARNING: package starts with {package[0]:#04x}, not 0x01 - "
              f"is this a 1.x (make_ota_v1.py) package?", file=sys.stderr)

    ip = args.host_ip or lan_ip()
    url = args.url or f"http://{ip.replace('.', '-')}.nip.io:{args.port}/fw.bin"
    cmd = build_command(args.cid, url, args.new_version, args.plugin, args.up_mode, args.v2)

    print(f"[ota] {'2.x' if args.v2 else '1.x'} package, {len(package)} bytes, "
          f"served on 0.0.0.0:{args.port}")
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
