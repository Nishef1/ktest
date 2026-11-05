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
  if echo "$EXPECTED  $DEST" | sha256sum --check --status; then
    exit 0
  fi
  # Existing installs may have the previously pinned 2.19.0 AAR. Only
  # replace that known artifact, and only after verifying the new download.
  PREVIOUS="fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0"
  if ! echo "$PREVIOUS  $DEST" | sha256sum --check --status; then
    echo "Existing HEV AAR is not an approved previous version" >&2; exit 1
  fi
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
