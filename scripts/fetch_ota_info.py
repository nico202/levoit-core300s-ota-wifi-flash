#!/usr/bin/env python3
"""
fetch_ota_info.py - query the VeSync cloud for the firmware update info of your
devices. This reveals the exact download URL, the announced new version and the
file size (the device compares the version, and possibly the size/hash).

Requires: pip install pyvesync

Credentials via environment:
    export VESYNC_USERNAME='you@example.com'
    export VESYNC_PASSWORD='...'
    export VESYNC_COUNTRY='IT'      # optional (ISO alpha-2)

Usage:
    ./fetch_ota_info.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import MISSING, fields

from pyvesync import VeSync
from pyvesync.models.vesync_models import RequestFirmwareModel
from pyvesync.utils.helpers import Helpers


async def main() -> int:
    user = os.environ.get("VESYNC_USERNAME")
    pw = os.environ.get("VESYNC_PASSWORD")
    country = os.environ.get("VESYNC_COUNTRY", "US")
    if not user or not pw:
        print("set VESYNC_USERNAME and VESYNC_PASSWORD", file=sys.stderr)
        return 2

    async with VeSync(user, pw, country_code=country, redact=False) as m:
        await m.login()
        await m.update()
        for d in m.devices:
            print(f"device: {getattr(d, 'device_name', None)}  cid={d.cid}  "
                  f"configModule={getattr(d, 'config_module', None)}")
        body_fields = tuple(
            f.name for f in fields(RequestFirmwareModel)
            if f.default_factory is MISSING and f.default is MISSING
        )
        body = Helpers.get_manager_attributes(m, body_fields)
        body["cidList"] = [d.cid for d in m.devices if getattr(d, "cid", None)]
        resp, status = await m.async_call_api(
            "/cloud/v2/deviceManaged/getFirmwareUpdateInfoList",
            "post",
            json_object=RequestFirmwareModel(**body),
        )
        print(f"\nHTTP {status}")
        print(json.dumps(resp, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
