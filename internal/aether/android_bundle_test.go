package aether

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAndroidBundleRejectsMissingTamperedAndUnsupportedCores(t *testing.T) {
	if _, err := AndroidBundlePaths("relative/path", "arm64"); err == nil {
		t.Fatal("accepted writable relative native path")
	}
	dir := t.TempDir()
	if _, err := AndroidBundlePaths(dir, "386"); err == nil {
		t.Fatal("accepted unpinned ABI")
	}
	if _, err := AndroidBundlePaths(dir, "arm64"); err == nil {
		t.Fatal("accepted missing packaged cores")
	}
	if err := os.WriteFile(filepath.Join(dir, "libaether.so"), []byte("tampered core"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := AndroidBundlePaths(dir, "arm64"); err == nil {
		t.Fatal("accepted an unverified native executable")
	}
}

func TestAndroidBundleMatchesPreparedOfficialExecutables(t *testing.T) {
	dir := os.Getenv("KTEST_ANDROID_BUNDLE_TEST_DIR")
	if dir == "" {
		t.Skip("set KTEST_ANDROID_BUNDLE_TEST_DIR after prepare-native-cores.py to verify official payloads")
	}
	for goarch, abi := range map[string]string{"arm": "armeabi-v7a", "arm64": "arm64-v8a", "amd64": "x86_64"} {
		paths, err := AndroidBundlePaths(filepath.Join(dir, abi), goarch)
		if err != nil {
			t.Fatal(err)
		}
		if paths.ABI != abi || paths.Aether == "" || paths.Psiphon == "" || paths.Lyrebird == "" {
			t.Fatalf("incomplete verified bundle: %+v", paths)
		}
	}
}
