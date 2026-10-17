#!/usr/bin/env bash
set -euo pipefail
# Source validation only: generate Java bindings, then compile Kotlin against
# them and upstream HEV's exact Java API. No native library, AAR or APK is built.
# Requires Linux, Go, JDK 17+, Android platform 36 and Gradle 9.5.0 on PATH.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
check_dir="$(mktemp -d -t ktest-android-source-XXXXXXXX)"
trap 'rm -rf -- "$check_dir"' EXIT
cd "$root"
mobile_version="v0.0.0-20261011034528-197770444867"
hev_version="2.19.0"
hev_source_sha="7a6fa6cd2f558a8f40a4554eb091389b97114fe716a3c05c7fe9b24156dc1bc9"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
test -f "$sdk/platforms/android-36/android.jar"
cp go.mod "$check_dir/check.mod"
cp go.sum "$check_dir/check.sum"
go mod edit -modfile="$check_dir/check.mod" -require="golang.org/x/mobile@$mobile_version"
export GOFLAGS="-mod=mod -modfile=$check_dir/check.mod"
go run "golang.org/x/mobile/cmd/gobind@$mobile_version" \
  -lang=java -outdir "$check_dir/bindings" ./mobilebridge
mkdir -p "$check_dir/hev/hev/htproxy" "$check_dir/classes"
curl -fL --retry 2 --connect-timeout 15 --max-time 90 \
  "https://raw.githubusercontent.com/heiher/hev-socks5-tunnel/$hev_version/android/hev/htproxy/TProxyService.java" \
  -o "$check_dir/hev/hev/htproxy/TProxyService.java"
echo "$hev_source_sha  $check_dir/hev/hev/htproxy/TProxyService.java" | sha256sum --check
find "$check_dir/bindings/java" "$check_dir/hev" -name '*.java' > "$check_dir/java-sources"
javac -classpath "$sdk/platforms/android-36/android.jar" -d "$check_dir/classes" @"$check_dir/java-sources"
jar --create --file "$check_dir/bindings.jar" -C "$check_dir/classes" .
cp -R android "$check_dir/android"
python3 - "$check_dir" <<'PY'
from pathlib import Path
import sys
check = Path(sys.argv[1])
build = check / 'android/app/build.gradle.kts'
source = build.read_text()
go_dep = 'implementation(files("libs/mobilebridge.aar"))'
hev_dep = 'implementation(files("libs/hev-socks5-tunnel.aar"))'
assert source.count(go_dep) == 1 and source.count(hev_dep) == 1
source = source.replace(go_dep, f'implementation(files("{check}/bindings.jar"))')
source = source.replace(hev_dep, '')
build.write_text(source)
PY
gradle -p "$check_dir/android" :app:compileDebugKotlin \
  --no-daemon --max-workers=2 --console=plain
echo "Android Java/Kotlin source compilation passed; native linking, TUN and device behavior remain untested."
