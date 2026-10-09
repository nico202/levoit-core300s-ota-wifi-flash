#!/usr/bin/env python3
"""
trigger_update.py - ask the VeSync cloud to push a firmware update to a device.

This is what the app does when you press "Update": POST
/cloud/v2/deviceManaged/updateFirmwareV2. The cloud then tells the device (over
MQTT) to download the firmware from the URL it knows; with the MITM in place,
that URL resolves to YOUR package.

The request body must contain the FULL set of standard fields (the server
rejects a partial body with "illegal argument"), so we reuse pyvesync's
RequestFirmwareModel to fill them, then add the business fields.

Requires: pip install pyvesync

Env:
    VESYNC_USERNAME, VESYNC_PASSWORD, VESYNC_COUNTRY (optional)
    CID, CONFIG_MODULE, PLUGIN (optional; auto-detected for a single device)

Usage:
    ./trigger_update.py
    ./trigger_update.py --plugin mainFw
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import MISSING, fields

from pyvesync import VeSync
from pyvesync.models.vesync_models import RequestFirmwareModel
from pyvesync.utils.helpers import Helpers


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin", default="mainFw", help="pluginName to update (default mainFw)")
    args = ap.parse_args()

    user = os.environ.get("VESYNC_USERNAME")
    pw = os.environ.get("VESYNC_PASSWORD")
    country = os.environ.get("VESYNC_COUNTRY", "US")
    if not user or not pw:
        print("set VESYNC_USERNAME and VESYNC_PASSWORD", file=sys.stderr)
        return 2

    async with VeSync(user, pw, country_code=country, redact=False) as m:
        await m.login()
        await m.update()
        devs = list(m.devices)
        if not devs:
            print("no devices", file=sys.stderr)
            return 1
        d = devs[0]
        cid = os.environ.get("CID", d.cid)
        config_module = os.environ.get("CONFIG_MODULE", getattr(d, "config_module", None))
        region = getattr(d, "device_region", None) or country

        body_fields = tuple(
            f.name for f in fields(RequestFirmwareModel)
            if f.default_factory is MISSING and f.default is MISSING
        )
        body = Helpers.get_manager_attributes(m, body_fields)
        model = RequestFirmwareModel(**body, cidList=[]).to_dict()
        model.pop("cidList", None)
        model["method"] = "updateFirmwareV2"
        model.update({
            "cid": cid,
            "configModule": config_module,
            "deviceRegion": region,
            "pluginName": args.plugin,
        })
        resp, status = await m.async_call_api(
            "/cloud/v2/deviceManaged/updateFirmwareV2", "post", json_object=model
        )
        print(f"HTTP {status} -> {resp}")
        print("If code == 0 the cloud accepted the request; watch your OTA server log.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
