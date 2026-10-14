#!/usr/bin/env bash
# Build delfyRTL firmware for Ai-Thinker BW16 (RTL8720DN) in a linux/amd64 container,
# so the x86_64 AmebaD toolchain runs natively (no Rosetta). Flash from the Mac afterwards.
set -euo pipefail
SKETCH_DIR="${1:?sketch dir}"   # .../delfyRTL/RTL8720dn-firmware
OUT_DIR="${2:?out dir}"
A15="${3:?arduino15 cache dir}"
IDX="https://github.com/Ameba-AIoT/ameba-arduino-d/raw/dev/Arduino_package/package_realtek_amebad_early_index.json"
FQBN="realtek:AmebaD:Ai-Thinker_BW16"
# Pin the core to delfy's era (last real commit 2025-04); 3.2.0 (2026) broke the core headers.
CORE_VER="${CORE_VER:-3.1.7-build20240216}"
mkdir -p "$OUT_DIR" "$A15"

PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"   # holds patch_wificlient.py
docker run --rm --platform linux/amd64 \
  -v "$SKETCH_DIR":/sketch:ro \
  -v "$OUT_DIR":/out \
  -v "$A15":/root/.arduino15 \
  -v "$PATCH_DIR":/patch:ro \
  -e IDX="$IDX" -e FQBN="$FQBN" -e CORE_VER="$CORE_VER" \
  debian:bookworm-slim bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl python3 python3-pip git ca-certificates xxd >/dev/null
    ln -sf /usr/bin/python3 /usr/local/bin/python
    if ! command -v arduino-cli >/dev/null 2>&1; then
      curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh \
        | BINDIR=/usr/local/bin sh >/dev/null
    fi
    arduino-cli version
    arduino-cli config init --overwrite >/dev/null
    arduino-cli core update-index --additional-urls "$IDX"
    # Pin exactly CORE_VER: remove any other installed AmebaD, install the pinned one.
    if ! arduino-cli core list 2>/dev/null | grep -qi "realtek:AmebaD[[:space:]].*$CORE_VER"; then
      arduino-cli core uninstall realtek:AmebaD 2>/dev/null || true
      arduino-cli core install "realtek:AmebaD@$CORE_VER" --additional-urls "$IDX"
    else
      echo "AmebaD core $CORE_VER already installed (cached)"
    fi
    # patch core WiFiClient to expose remoteIP() (per-client captive 204 needs peer IP)
    CORE_WIFI="/root/.arduino15/packages/realtek/hardware/AmebaD/$CORE_VER/libraries/WiFi/src"
    python3 /patch/patch_wificlient.py "$CORE_WIFI"
    # sketch folder name must match the .ino basename; /sketch is mounted ro so copy it
    INO=$(basename /sketch/*.ino .ino)
    cp -r /sketch "/tmp/$INO"
    echo "=== compiling $INO ==="
    arduino-cli compile --fqbn "$FQBN" --output-dir /out --build-path /out/build -v "/tmp/$INO" 2>&1 \
      | grep -iE "postbuild|img2|image2|km0_km4|error|\.bin|Sketch uses" | tail -30
    echo "=== images in /out (save_file target) ==="; find /out -maxdepth 2 -iname "*.bin" -exec ls -la {} \;
  '
