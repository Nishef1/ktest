#!/usr/bin/env bash
set -euo pipefail

# Pinned upstream HEV Android AAR. No APK is built by this script.
VERSION="2.19.0"
SHA256="fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0"
URL="https://github.com/heiher/hev-socks5-tunnel/releases/download/${VERSION}/hev-socks5-tunnel.aar"
DEST="android/app/libs/hev-socks5-tunnel.aar"

cd "$(dirname "$0")/../.."
mkdir -p "$(dirname "$DEST")"
if [[ -f "$DEST" ]]; then
  if echo "$SHA256  $DEST" | sha256sum -c --status; then
    echo "Pinned HEV AAR already verified"
    exit 0
  fi
  echo "Wrong checksum on existing HEV AAR" >&2
  exit 1
fi
TMP="$(mktemp "$(dirname "$DEST")/.hev.XXXXXXXX")"
trap 'rm -f "$TMP"' EXIT
curl -fL --retry 2 --connect-timeout 15 --max-time 90 "$URL" -o "$TMP"
echo "$SHA256  $TMP" | sha256sum -c --status || { echo "HEV AAR checksum mismatch" >&2; exit 1; }
unzip -t "$TMP" >/dev/null
unzip -Z1 "$TMP" | grep -Fx 'classes.jar' >/dev/null
unzip -Z1 "$TMP" | grep -F 'arm64-v8a' >/dev/null
unzip -Z1 "$TMP" | grep -F 'armeabi-v7a' >/dev/null
mv "$TMP" "$DEST"
echo "Verified HEV AAR installed for future MANUAL Android build"
