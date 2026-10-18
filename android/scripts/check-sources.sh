#!/usr/bin/env bash
set -euo pipefail
# Source validation only: generate Java bindings, then compile Kotlin against
# the pinned HEV AAR API and merge its manifest. No native library, AAR or APK
# is built; HEV is downloaded unchanged, not rebuilt.
# Requires Linux, Go, JDK 17+, Android platform 36 and Gradle 9.5.0 on PATH.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
check_dir="$(mktemp -d -t ktest-android-source-XXXXXXXX)"
trap 'rm -rf -- "$check_dir"' EXIT
cd "$root"
mobile_version="v0.0.0-20261011034528-197770444867"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
test -f "$sdk/platforms/android-36/android.jar"
cp go.mod "$check_dir/check.mod"
cp go.sum "$check_dir/check.sum"
go mod edit -modfile="$check_dir/check.mod" -require="golang.org/x/mobile@$mobile_version"
export GOFLAGS="-mod=mod -modfile=$check_dir/check.mod"
go run "golang.org/x/mobile/cmd/gobind@$mobile_version" \
  -lang=java -outdir "$check_dir/bindings" ./mobilebridge
mkdir -p "$check_dir/classes"
find "$check_dir/bindings/java" -name '*.java' > "$check_dir/java-sources"
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
assert source.count(go_dep) == 1
source = source.replace(go_dep, f'implementation(files("{check}/bindings.jar"))')
build.write_text(source)
PY
bash "$check_dir/android/scripts/fetch-hev-aar.sh"
gradle -p "$check_dir/android" :app:compileDebugKotlin :app:processDebugMainManifest \
  --no-daemon --max-workers=2 --console=plain
echo "Android source and real HEV manifest checks passed; native linking, TUN and device behavior require separate validation."
