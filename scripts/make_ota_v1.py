#!/usr/bin/env python3
"""
make_ota_v1.py - wrap an ESP32 application image into the **1.x** VeSync OTA
container (Levoit Core 300S / Etekcity, firmware 1.0.00 family).

Firmware 2.x (the format handled by ``make_ota.py``) uses a plaintext 128-byte
header.  The 1.0.00 build uses a different, encrypted container:

    [1 byte crypto_type = 0x01][128-byte AES-128-CBC header][ESP32 image]

The 128-byte header, once decrypted:

    offset  size  field
    ------  ----  -----------------------------------------------------------
      0       1   format version, must be 0x01
      1      32   uppercase hex MD5 of the payload (bytes 129..EOF)
     33       1   NUL
     34      16   model, NUL-padded            ("LAP-C302S-WGC")
     50      16   firmware version, NUL-padded (must equal the cloud's newVersion)
     66       8   hardware version, NUL-padded ("1.0")
     74       -   region list, NUL-terminated  ("AE", "EU", ... or "UN" to bypass)

Encryption: AES-128-CBC with key = IV = MD5("Vesync")
(``555ad6d072a97649fb9fe5e44e023b81``).  The key is derived at boot by the
firmware itself from that literal string, so it is fixed for every unit.

On the wire the firmware expects 129 bytes before it parses anything, and calls
``esp_ota_begin(Content-Length - 129)``; the MD5 therefore covers the payload
after the 129-byte prefix.

Usage:
    ./make_ota_v1.py APP.bin OUT.bin --version 2.0.00 \
        --model LAP-C302S-WGC --hw 1.0 --region AE
    ./make_ota_v1.py --verify OUT.bin
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys

HEADER_SIZE = 128
KEY = hashlib.md5(b"Vesync").digest()  # key == IV


def _aes_cbc(data: bytes, decrypt: bool) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return _aes_cbc_openssl(data, decrypt)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(KEY))
    op = cipher.decryptor() if decrypt else cipher.encryptor()
    return op.update(data) + op.finalize()


def _aes_cbc_openssl(data: bytes, decrypt: bool) -> bytes:
    cmd = ["openssl", "enc", "-aes-128-cbc", "-K", KEY.hex(), "-iv", KEY.hex(), "-nopad"]
    if decrypt:
        cmd.insert(2, "-d")
    try:
        res = subprocess.run(cmd, input=data, capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise SystemExit(
            "AES-128-CBC needs either `pip install cryptography` or the `openssl` CLI "
            f"({exc})"
        )
    return res.stdout


def build_header(md5_hex: str, model: str, version: str, hw: str, region: str) -> bytes:
    if len(md5_hex) != 32:
        raise ValueError("md5 must be 32 hex chars")
    h = bytearray(HEADER_SIZE)
    h[0] = 1
    h[1:33] = md5_hex.encode("ascii")
    h[34:50] = model.encode("ascii")[:16].ljust(16, b"\0")
    h[50:66] = version.encode("ascii")[:16].ljust(16, b"\0")
    h[66:74] = hw.encode("ascii")[:8].ljust(8, b"\0")
    reg = region.encode("ascii")[:4]
    h[74:74 + len(reg)] = reg
    return bytes(h)


def build_package(app: bytes, model: str, version: str, hw: str, region: str,
                  md5_case: str = "upper") -> tuple[bytes, str]:
    md5 = hashlib.md5(app).hexdigest()
    if md5_case == "upper":
        md5 = md5.upper()
    header = build_header(md5, model, version, hw, region)
    return b"\x01" + _aes_cbc(header, decrypt=False) + app, md5


def cmd_build(args) -> int:
    app = open(args.app_image, "rb").read()
    if not app:
        print("empty image", file=sys.stderr)
        return 2
    if app[0] != 0xE9:
        print(f"WARNING: payload does not start with 0xE9 (got {app[0]:#x}); "
              f"this must be the ESP32 *application* image", file=sys.stderr)
    pkg, md5 = build_package(app, args.model, args.version, args.hw, args.region, args.md5_case)
    open(args.output, "wb").write(pkg)
    print(f"wrote {args.output}: 1 + 128 + {len(app)} = {len(pkg)} bytes")
    print(f"  model={args.model} version={args.version} hw={args.hw} region={args.region}")
    print(f"  md5(payload)={md5}  crypto_type=0x01  cipher=AES-128-CBC")
    print(f"  serve with Content-Length {len(pkg)}")
    return 0


def _field(raw: bytes) -> str:
    return raw.split(b"\0")[0].decode("ascii", "replace")


def cmd_verify(args) -> int:
    pkg = open(args.verify, "rb").read()
    if len(pkg) < HEADER_SIZE + 1:
        print("too short", file=sys.stderr)
        return 2
    if pkg[0] != 0x01:
        print(f"crypto_type = {pkg[0]:#04x} (expected 0x01)", file=sys.stderr)
        return 1
    header = _aes_cbc(pkg[1:129], decrypt=True)
    payload = pkg[129:]
    md5 = hashlib.md5(payload).hexdigest().upper()
    print(f"package : {len(pkg)} bytes (129 prefix + {len(payload)} payload)")
    print(f"ver     : {header[0]}")
    print(f"md5     : {_field(header[1:33])}")
    print(f"model   : {_field(header[34:50])}")
    print(f"version : {_field(header[50:66])}")
    print(f"hw      : {_field(header[66:74])}")
    print(f"region  : {_field(header[74:])}")
    match = "match" if _field(header[1:33]).upper() == md5 else "MISMATCH"
    print(f"payload : {len(payload)} bytes, md5 {md5} ({match})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Build/verify a VeSync 1.x OTA package.")
    ap.add_argument("app_image", nargs="?", help="ESP32 application image (.bin, starts 0xE9)")
    ap.add_argument("output", nargs="?", help="output package path")
    ap.add_argument("--version", default="2.0.00", help="must equal the cloud's newVersion")
    ap.add_argument("--model", default="LAP-C302S-WGC", help="device model string")
    ap.add_argument("--hw", default="1.0", help="hardware version string")
    ap.add_argument("--region", default="AE", help="region list (AE/EU/US/... or UN to bypass)")
    ap.add_argument("--md5-case", choices=["upper", "lower"], default="upper")
    ap.add_argument("--verify", metavar="PACKAGE", help="decrypt and print an existing package")
    args = ap.parse_args()
    if args.verify:
        return cmd_verify(args)
    if not args.app_image or not args.output:
        ap.error("app_image and output are required unless --verify is used")
    return cmd_build(args)


if __name__ == "__main__":
    raise SystemExit(main())
