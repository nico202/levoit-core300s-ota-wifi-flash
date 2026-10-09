#!/usr/bin/env python3
"""
make_ota.py - wrap an ESPHome/ESP32 application image into the VeSync OTA
container used by Levoit/Etekcity devices (tested on Levoit Core 300S EU).

The VeSync OTA file is:
    128-byte header  +  ESP32 application image (starts with 0xE9)

Header layout (reverse-engineered from a genuine Core300s EU OTA package):

    offset  size  field
    ------  ----  -----------------------------------------
      0      32   uppercase hex MD5 of the payload (bytes 128..end)
     32       4   0xFF
     36       8   device name, 0xFF-padded        ("Core300s")
     44       8   0xFF
     52       6   firmware version, 0xFF-padded   (e.g. "2.0.00")
     58       6   0xFF
     64       4   0xFF
     68       3   "1.0", 0xFF-padded              (part/min version tag)
     71       6   0xFF
     77       2   region, 0xFF-padded             ("EU", "US", ...)
     79      49   0xFF

IMPORTANT: the version field MUST equal the version the cloud announced for
this firmware (the device compares it), and the device name/region must match
the device. The MD5 is over the payload only (not the header).

Usage:
    ./make_ota.py APP_IMAGE.bin OUT.bin --version 2.0.00 --name Core300s --region EU
    ./make_ota.py APP_IMAGE.bin OUT.bin              # defaults to 2.0.00 / Core300s / EU
"""
from __future__ import annotations

import argparse
import hashlib
import sys

HEADER_SIZE = 128


def build_header(md5_hex: str, name: str, version: str, region: str) -> bytes:
    if len(md5_hex) != 32:
        raise ValueError("md5 must be 32 hex chars")
    h = bytearray(b"\xff" * HEADER_SIZE)
    h[0:32] = md5_hex.upper().encode("ascii")
    h[36:36 + min(len(name), 8)] = name.encode("ascii")[:8]
    h[52:52 + min(len(version), 6)] = version.encode("ascii")[:6]
    h[68:71] = b"1.0"
    h[77:77 + min(len(region), 2)] = region.encode("ascii")[:2]
    return bytes(h)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a VeSync OTA package.")
    ap.add_argument("app_image", help="ESP32 application image (.bin, must start with 0xE9)")
    ap.add_argument("output", help="output package path")
    ap.add_argument("--version", default="2.0.00", help="firmware version announced by the cloud")
    ap.add_argument("--name", default="Core300s", help="device name in the header")
    ap.add_argument("--region", default="EU", help="region (EU/US/...)")
    args = ap.parse_args()

    img = open(args.app_image, "rb").read()
    if not img:
        print("empty image", file=sys.stderr)
        return 2
    if img[0] != 0xE9:
        print(f"WARNING: payload does not start with 0xE9 (got {img[0]:#x}); "
              f"is this an ESP32 *application* image (firmware.bin/firmware.ota.bin)?",
              file=sys.stderr)

    md5 = hashlib.md5(img).hexdigest()
    header = build_header(md5, args.name, args.version, args.region)
    pkg = header + img
    open(args.output, "wb").write(pkg)

    print(f"wrote {args.output}: header 128B + payload {len(img)}B = {len(pkg)}B")
    print(f"  version={args.version} name={args.name} region={args.region} md5(payload)={md5.upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
