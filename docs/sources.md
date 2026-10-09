# Sources & credits

This work stands on the shoulders of the ESPHome/Levoit community plus the
reverse-engineering of the VeSync app.

## ESPHome firmware for Levoit (UART protocol, GPIO pins)
- acvigue - https://github.com/acvigue/esphome-levoit-air-purifier
- acvigue (blog) - https://vigue.me/posts/levoit-air-purifier-esphome-conversion
- mulcmu - https://github.com/mulcmu/esphome-levoit-core300s (also documents the
  stock UART protocol and that OTA is MQTT-initiated from `fw.vesync.com`)
- tuct - https://github.com/tuct/levoit (maintained ESPHome component used here)
- ESPHome devices page - https://devices.esphome.io/devices/levoit-core-300s

## Local network control of VeSync devices (DNS redirection)
- epicRE - https://github.com/epicRE/levoit-local-control
  (shows that redirecting `vdmpmqtt.vesync.com` / `*.vesync.com` to a local
  server works, and that the device tolerates a self-signed TLS broker - the
  same weak-trust property we rely on for the OTA download)

## VeSync cloud API
- pyvesync - https://github.com/webdjoe/pyvesync
- Home Assistant VeSync integration - https://www.home-assistant.io/integrations/vesync

## Tools
- ESPHome - https://esphome.io
- scapy - https://scapy.net
- dsniff `arpspoof` - https://github.com/dugsong/dsniff (fallback spoof method)
- jadx (used to decompile the APK) - https://github.com/skylot/jadx

## Hardware references
- FCC filings (Arovast/VeSync) - https://fccid.io/2ARBY (internal PCB photos;
  the Core 300S uses an ESP32-SOLO-1C).
