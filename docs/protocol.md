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
