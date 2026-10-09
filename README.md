# Flashing ESPHome on a Levoit Core 300S **over Wi‑Fi** (no disassembly)

Turn a stock **Levoit Core 300S** (VeSync) air purifier into a local
**ESPHome** device **without opening it and without soldering**, by hijacking the
firmware download of the vendor cloud (`fw.vesync.com`) on your LAN.

> This is a proof of concept. It worked on a Core 300S EU (ESP32‑SOLO‑1C,
> mainFw 1.1.08 → 2.0.00). Understand the risks before you try it.

---

## TL;DR

1. Build a normal ESPHome image for the Core 300S (app image, `0xE9…`).
2. Wrap it in the VeSync OTA container (a 128‑byte header + the app image).
3. On your LAN, **ARP‑spoof the purifier** and **redirect its HTTP traffic to a
   local server** that serves your package.
4. Ask the cloud to update the device (app button or API). The device downloads
   **your** package and flashes it.

No cloud emulation, no DNS changes on the router, no firmware dumps.

---

## How it works

The stock device updates itself: the app only asks the cloud
(`updateFirmwareV2`), the cloud tells the device (MQTT) to fetch a URL, and the
device performs a plain **HTTP GET** on `fw.vesync.com`. The OTA file is a
128‑byte header (MD5 + name + version + region) followed by a raw **ESP32
application image**; there is **no signature** and **Secure Boot is disabled**.

So we leave the cloud alone and only hijack the HTTP fetch:

```
device ──(ARP spoof: "gateway is at my MAC")──▶ our host
our host  • DNAT  tcp/80 (from device)  → our OTA server  (serves OUR package)
          • forward + SNAT everything else              (device stays online)
```

Because the device stays connected to the real cloud, the cloud still issues the
OTA command, but the device downloads from us. Full details and the exact header
layout are in [`docs/protocol.md`](docs/protocol.md).

---

## Requirements

* A Linux machine on the **same L2 network** as the purifier, with **root**
  (for `iptables` + ARP spoofing). A Raspberry Pi works great.
* `python3`, `iptables`, and either **`scapy`** (`pip install scapy`) or
  **`arpspoof`** (dsniff). Optional: `arpspoof.c` compiled with `cc`.
* **ESPHome** to build the firmware: either `pip install esphome` or Docker
  (`ghcr.io/esphome/esphome`).
* `pyvesync` only if you want to query/trigger the cloud from the CLI
  (`pip install pyvesync`).
* A **VeSync account with the device added** (so the cloud will offer the update).

---

## Procedure

### 1. Find the device on your network

The purifier's Wi‑Fi MAC is close to its BLE MAC. Find its IP:

```bash
# from a host on the same subnet (nmap/arp-scan), or from the router's client list
nmap -sn 192.168.1.0/24
ip neigh | grep -i '30:c9:22:46:ac'   # adjust to your MAC prefix
```

You need: the device **IP**, its **MAC**, and the **gateway IP**.

### 2. Build the ESPHome firmware

Edit `firmware/levoit-core300s.yaml` (or `firmware/secrets.yaml`, copied from
`secrets.example.yaml`) and build:

```bash
./scripts/build_firmware.sh 2.0.00      # version MUST match what the cloud announces
```

This produces `dist/esphome_core300s_ota.bin` (the VeSync OTA package).
The app image itself is at
`firmware/.esphome/build/levoit-core300s/build/firmware.ota.bin` (`0xE9…`).

> **Why the version matters:** the device compares the header version with the
> version the cloud announced for this update. Use the exact same string (e.g.
> `2.0.00`). Wrong version ⇒ the device aborts after a few KB.

> **Guix/NixOS:** ESPHome ships prebuilt glibc toolchains. Run the build inside an
> FHS/emulated environment (see the note at the top of `scripts/build_firmware.sh`).

### 3. Serve the package

```bash
./scripts/serve_ota.py --port 18080 --file dist/esphome_core300s_ota.bin
```

It logs every request – that's how you confirm the device hit you.

### 4. Start the MITM (as root, in another terminal)

```bash
sudo IFACE=wlan0 GATEWAY=192.168.1.1 DEVICE=192.168.1.50 PORT=18080 \
     ./scripts/host_mitm.sh
```

It ARP‑spoofs the device, forwards its traffic (cloud stays online) and DNATs its
HTTP to your server. It also blocks the device's HTTPS to `fw.vesync.com` so it
can never silently pull the genuine binary. Stop with **Ctrl‑C**.

### 5. Verify the redirect (recommended)

From another host that you spoof the same way (or temporarily include a second
victim), request the firmware URL and check that you get *your* package:

```bash
curl -s http://fw.vesync.com/WiFiBTOnboardingNotify_AirPurifier_Core300S_EU/... | head -c 32
# must print your package's ASCII MD5 header
```

### 6. Trigger the update

Either in the **VeSync app** (device → Settings → the app's *Firmware Update*
screen → *Update*), or from the CLI:

```bash
export VESYNC_USERNAME=... VESYNC_PASSWORD=... VESYNC_COUNTRY=IT
./scripts/trigger_update.py --plugin mainFw
```

Watch `serve_ota.py`: you should see
`192.168.x.y GET /... UA='ESP32 HTTP Client/1.0'` from the device.

### 7. Done

The device downloads your package and **reboots into ESPHome**. Since it can't
join your Wi‑Fi yet (placeholder credentials), it starts the fallback AP:

* SSID **`Levoit-Core300S`** (open)
* the device is at **`http://192.168.4.1/`** (ESPHome captive portal) → enter your
  Wi‑Fi SSID/password.

After it joins your network:
* add it in **Home Assistant** (ESPHome integration) or the **ESPHome dashboard**;
* any future change is a normal **ESPHome OTA** – no MITM ever again.

### 8. Clean up

```bash
sudo GATEWAY=192.168.1.1 DEVICE=192.168.1.50 ./scripts/host_mitm_stop.sh
```

---

## No web page after flashing?

The sample config enables the ESPHome **native API** + OTA but **not** the web
server, so `http://<device>` returns nothing — that's expected. Options:

* **Home Assistant**: Settings → Devices & Services → ESPHome → it is auto‑discovered
  (mDNS, API port 6053), or add it by IP.
* **Web UI**: add `web_server:` to the YAML and reflash (the device is now OTA‑updateable):
  ```bash
  esphome run firmware/levoit-core300s.yaml --device <device-ip>
  ```

---

## Scripts

| Script | Purpose |
|---|---|
| `scripts/build_firmware.sh` | Build ESPHome firmware and wrap it into the VeSync OTA container |
| `scripts/make_ota.py` | Build the 128‑byte VeSync header + ESP32 app image (the core trick) |
| `scripts/serve_ota.py` | HTTP server that serves the package and logs hits |
| `scripts/host_mitm.sh` / `host_mitm_stop.sh` | ARP‑spoof + iptables DNAT/forward (needs root) |
| `scripts/arpspoof.c` | Dependency‑free ARP spoofer (if you don't want scapy/dsniff) |
| `scripts/fetch_ota_info.py` | Query the VeSync cloud for the firmware URL/version/size |
| `scripts/trigger_update.py` | Ask the cloud to update the device (what the app does) |

---

## Troubleshooting

* **Device downloads the genuine firmware / never hits your server.** Your ARP
  spoof or DNAT isn't in effect. Verify with
  `sudo iptables -t nat -L PREROUTING -v -n` (packet counters should grow) and
  `sudo tcpdump -i <iface> host <device-ip>` (you should see the `ESP32 HTTP
  Client/1.0` GET).
* **Device downloads a few KB then resets the connection.** The header version
  doesn't match the version the cloud announced – rebuild with the exact version.
* **Device tries HTTPS (443).** It's blocked on purpose; the device uses HTTP in
  practice. If yours insists on HTTPS you'd have to serve TLS (the device trusts
  the VeSync CA, so this is harder).
* **Phone/other client can't be used as the "test victim".** A VPN on the client
  routes traffic outside your LAN and bypasses the spoof; disable it for the test.

---

## Legal / ethics

For research and for your **own** hardware. Intercepting network traffic you
don't own may be illegal where you live. Flashing alternative firmware may void
your warranty. You are responsible for what you do. No warranty of any kind.

## Credits

See [`docs/sources.md`](docs/sources.md). This project builds on the work of
**acvigue**, **mulcmu**, **tuct**, **epicRE** and the pyvesync/ESPHome
communities. Licensed under the MIT License (see `LICENSE`).
