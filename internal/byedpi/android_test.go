package byedpi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAndroidBinaryRejectsMissingTamperedAndUnpinnedCores(t *testing.T) {
	dir := t.TempDir()
	if _, err := AndroidBinary("relative", "arm64"); err == nil {
		t.Fatal("accepted a relative executable path")
	}
	if _, err := AndroidBinary(dir, "386"); err == nil {
		t.Fatal("accepted an unpinned ABI")
	}
	if _, err := AndroidBinary(dir, "arm64"); err == nil {
		t.Fatal("accepted a missing executable")
	}
	if err := os.WriteFile(filepath.Join(dir, "libciadpi.so"), []byte("modified core"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := AndroidBinary(dir, "arm64"); err == nil {
		t.Fatal("accepted a modified executable")
	}
}

func TestAndroidBinaryAcceptsPreparedOfficialPayloads(t *testing.T) {
	dir := os.Getenv("KTEST_ANDROID_BUNDLE_TEST_DIR")
	if dir == "" {
		t.Skip("prepare-native-cores.py output is required for this integration check")
	}
	for goarch, abi := range map[string]string{"arm": "armeabi-v7a", "arm64": "arm64-v8a", "amd64": "x86_64"} {
		if _, err := AndroidBinary(filepath.Join(dir, abi), goarch); err != nil {
			t.Fatal(err)
		}
	}
}
