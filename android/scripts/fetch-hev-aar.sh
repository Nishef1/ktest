#!/usr/bin/env bash
set -euo pipefail
# Called solely by manually dispatched Android verification/release workflow.
VERSION="2.19.0"
EXPECTED="fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0"
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
