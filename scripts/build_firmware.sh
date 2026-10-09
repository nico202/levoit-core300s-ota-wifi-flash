#!/usr/bin/env bash
#
# build_firmware.sh - build the ESPHome firmware and wrap it into the VeSync OTA
# container.
#
# It uses Docker if available (recommended, includes the toolchain), otherwise a
# local `esphome` (pip / venv). Output:
#   firmware/.esphome/build/<name>/build/firmware.ota.bin   (app image, 0xE9...)
#   dist/esphome_core300s_ota.bin                           (VeSync OTA package)
#
# Usage:
#   ./build_firmware.sh [VERSION]      # VERSION must match what the cloud announces
#
# NOTE for Guix/NixOS: esphome ships prebuilt glibc toolchains that don't run in
# strict store-based systems. Run this inside an FHS/emu environment, e.g.:
#   guix shell --container --network --emulate-fhs --share=$PWD \
#     bash coreutils python python-wrapper python-pip git tar gzip xz which \
#     libusb nss-certs gcc zlib -- bash -lc \
#     'unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH; ./build_firmware.sh'
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FW="$ROOT/firmware"
VERSION=${1:-2.0.00}
NAME=levoit-core300s
OUT="$ROOT/dist/esphome_core300s_ota.bin"
mkdir -p "$ROOT/dist"

echo "[*] building ESPHome firmware ($FW/$NAME.yaml) ..."
if command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$FW":/config ghcr.io/esphome/esphome compile "$NAME.yaml"
elif command -v esphome >/dev/null 2>&1; then
  ( cd "$FW" && esphome compile "$NAME.yaml" )
else
  echo "!! neither docker nor esphome found. Install one (pip install esphome, or use Docker)." >&2
  exit 1
fi

APP="$FW/.esphome/build/$NAME/build/firmware.ota.bin"
[ -f "$APP" ] || APP="$FW/.esphome/build/$NAME/build/firmware.bin"
echo "[*] app image: $APP ($(stat -c%s "$APP" 2>/dev/null || echo '?') bytes)"

echo "[*] wrapping into VeSync OTA container (version=$VERSION) ..."
python3 "$ROOT/scripts/make_ota.py" "$APP" "$OUT" --version "$VERSION"
echo "[*] done -> $OUT"
