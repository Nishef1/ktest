#!/usr/bin/env bash
set -euo pipefail
# Reuse the pinned upstream AAR for manifest/source checks or authorized builds.
VERSION="2.19.3"
EXPECTED="ab6c581e6157680cfe5687ee7bbdcf95405c006c2db3701879ec44b9e5f83836"
BASE="https://github.com/heiher/hev-socks5-tunnel/releases/download"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="$ROOT/android/app/libs/hev-socks5-tunnel.aar"
mkdir -p "$(dirname "$DEST")"
if [[ -f "$DEST" ]]; then
  echo "$EXPECTED  $DEST" | sha256sum --check --status || {
    echo "Existing HEV AAR has an unexpected digest" >&2; exit 1;
  }
  exit 0
fi
TMP="$(mktemp "$ROOT/android/app/libs/.hev-XXXXXXXX")"
trap 'rm -f "$TMP"' EXIT
curl -fL --retry 2 --connect-timeout 15 --max-time 90 \
  "$BASE/$VERSION/hev-socks5-tunnel.aar" -o "$TMP"
echo "$EXPECTED  $TMP" | sha256sum --check
unzip -t "$TMP" >/dev/null
unzip -Z1 "$TMP" | grep -Fx 'classes.jar' >/dev/null
unzip -Z1 "$TMP" | grep -F 'arm64-v8a' >/dev/null
unzip -Z1 "$TMP" | grep -F 'armeabi-v7a' >/dev/null
mv "$TMP" "$DEST"
