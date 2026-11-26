# Reverse-engineering notes

Everything below was obtained by decompiling the VeSync Android app
(`com.etekcity.vesyncplatform`, v5.9.80), analysing a genuine OTA package, and
live observation of the device. It documents *how* the exploit works.

## Device

* Levoit Core 300S air purifier, module = **ESP32-SOLO-1C** (Espressif ESP32),
  stock firmware built with **ESP-IDF**.
* There is a second MCU (the "U2" MCU) that drives the fans/sensors/UI; the ESP32
  bridges it to the cloud over UART (`0xA5` frame protocol, 115200 8N1).
* Cloud config module: `WiFiBTOnboardingNotify_AirPurifier_Core300S_EU`
  (US: `..._US`); connection type `WiFi+BTOnboarding+BTNotify`.
* The ESP32 talks to the VeSync cloud over MQTT and downloads firmware from
  `fw.vesync.com`.

## How the stock OTA works

The app does **not** push the firmware. It asks the cloud, and the **device
downloads it itself**:

1. App -> cloud: `POST /cloud/v2/deviceManaged/updateFirmwareV2`
   (`UpdateRequest{cid, configModule, deviceRegion, pluginName, upMode}`).
   (legacy variants: `PUT /v2/device/{cid}/firmware`, `/cloud/v1/.../updateDevice`)
2. The cloud tells the device (over MQTT) to fetch a firmware URL it knows.
3. The device performs `HTTP GET` on that URL (an ESP-IDF HTTP client, UA
   `ESP32 HTTP Client/1.0`) and writes the payload to its OTA partition.

`getFirmwareUpdateInfoList` returns, per device, a `firmUpdateInfos` list with,
for each plugin, `currentVersion`, `latestVersion`, `latestVersionUrl` (HTTP) and
`latestVersionUrlV1` (HTTPS), `fileSize`, `isMainFw`. Example for a Core 300S EU:

```
pluginName mainFw : current 1.1.08 -> latest 2.0.00
  http://fw.vesync.com/WiFiBTOnboardingNotify_AirPurifier_Core300S_EU/mainFirmware/v2.0.00/Core300s_EU_ota_v2.0.00.rel.bin
pluginName mcuFw-C2 : current 2.0.11 -> latest 2.0.11 (already up to date)
```

## The OTA file format

`fw.vesync.com` is an AWS ELB; `curl` fails TLS verification against it (private
CA), and the device uses plain **HTTP**. The downloaded `.rel.bin` is:

```
128-byte header  +  ESP32 application image (starts with 0xE9)
```

Header (little detail, `0xFF` padding everywhere not listed):

| offset | size | field |
|-------:|-----:|-------|
|   0    |  32  | ASCII **uppercase MD5 of the payload** (bytes 128..EOF) |
|  36    |   8  | device name, e.g. `Core300s` |
|  52    |   6  | firmware version, e.g. `2.0.00` |
|  68    |   3  | `1.0` |
|  77    |   2  | region, e.g. `EU` |

The payload begins with the ESP-IDF image magic `0xE9`. The firmware contains
`Parse OTA header`, `OTA image has invalid magic byte (expected 0xE9)`,
`Firmware downgrade not allowed` and `secure_version=0` with no signature block
=> **Secure Boot is not enabled**, so any valid ESP32 app image wrapped in this
header is accepted.

> The **version field must equal the version the cloud announced** for that
> update (the device cross-checks it). Using a different version makes the
> device abort the download.

## The trick: redirect the download, don't fight the cloud

We do **not** need to emulate the VeSync cloud. We let the device stay connected
normally and only hijack the HTTP fetch of `fw.vesync.com`:

```
device --(ARP spoof: gateway is at our MAC)--> our host
our host: DNAT tcp/80 (src=device) -> our OTA server   (serves OUR package)
our host: MASQUERADE + forward everything else          (device stays online)
```

Because the device's cloud connection keeps working, the cloud still commands
the update; the device then downloads from *us* instead of `fw.vesync.com`. The
404/other paths don't matter: our server answers 200 for every path.

If the device ever fetches over HTTPS (443), block it for the device so it cannot
silently pull the genuine binary (the device uses HTTP in practice).

The (device -> cloud) MQTT connection is TLS to the MQTT broker, which the
device accepts even with a self-signed cert (as documented by others); we simply
forward it untouched.

## Firmware 1.0.00 (1.x): the encrypted container

Units that ship with `mainFw 1.0.00` (for example the AE model `LAP-C302S-WGC`,
configModule `VS_WFON_APR_LAP-C302S-WGC_AE`) do **not** use the plaintext header
described above. Their downloaded file is:

```
1 byte      crypto_type, must be 0x01
128 bytes   AES-128-CBC(header)
N bytes     ESP32 application image (starts 0xE9)
```

### Encryption

```
key = IV = MD5("Vesync") = 555ad6d072a97649fb9fe5e44e023b81
AES-128-CBC, exactly 128 bytes, no padding
```

The key is not stored as a blob: `vesync_ota_init` derives it at boot from the
literal string `"Vesync"` with the firmware's MD5, so it is identical on every
unit and region. (The SDK also carries a separate default key/IV,
`llwantaeskey1.01` / `llwantaesivv1.01`, used for generic payload crypto - not
for the OTA header.)

### Decrypted header

| offset | size | field |
|-------:|-----:|-------|
| 0 | 1 | format version, must be `0x01` |
| 1 | 32 | ASCII **uppercase MD5 of the payload** (bytes 129..EOF) |
| 33 | 1 | NUL |
| 34 | 16 | model, NUL-padded (`LAP-C302S-WGC`) |
| 50 | 16 | firmware version, NUL-padded, **must equal the cloud's `newVersion`** |
| 66 | 8 | hardware version, NUL-padded (`1.0`) |
| 74 | .. | region list (`AE`, `EU`, ...) or `UN` to bypass the region check |

### What the device checks, in order

1. it has accumulated exactly **129** bytes and `crypto_type == 1`
2. AES-CBC decrypt, decrypted byte 0 == `0x01`
3. model == the unit's model (two 16-byte compares)
4. version == the `newVersion` from the cloud command (16-byte compare)
5. hardware version == `1.0` (8-byte compare)
6. region == the unit's region, or the list is `UN`
7. `esp_ota_begin(Content-Length - 129)`
8. stream to the inactive slot, incremental MD5, compare at the end

**Why a 2.x package is rejected:** its first byte is the first hex digit of the
MD5 (`'4'`), so the device aborts at step 1 before parsing any field. That is
why varying model/version/region in the plaintext header changed nothing.

### Delivery

The 1.0.00 cloud has no `mainFw` record for some SKUs, so `updateFirmwareV2`
cannot be used to trigger the download. The command can instead be submitted
through the cloud's `bypassV2` relay:

```
POST /cloud/v2/deviceManaged/bypassV2
{"method":"bypassV2", "cid":..., "traceId":...,
 "payload":{"method":"upFirmware","source":"APP",
            "data":{"newVersion":"2.0.00","pluginName":"mainFw",
                    "url":"http://<lan-ip-with-dashes>.nip.io:18080/fw.bin",
                    "upMode":3}}}
```

The cloud relays it to the device over its own MQTT connection. `upMode` must be
**3 or 4** (the firmware rejects 0/1/2/5 before starting the download), and the
URL must survive the cloud's URL filter: a raw private IP is rejected with HTTP
403, while a dash-form `nip.io` hostname is accepted and resolves back to the
serving machine. `scripts/cloud_ota.py` serves the package and submits this
command.

> This container was recovered by static analysis of a stock 1.0.00 AE dump.
> `make_ota_v1.py` builds and re-verifies it offline; hardware validation of the
> full chain is still pending. Nothing here is signed, so any image the device
> accepts will run.
