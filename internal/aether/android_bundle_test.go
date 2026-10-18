package aether

import (
	"os"
	"path/filepath"
	"slices"
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
func TestAndroidProfileArgsUsePinnedHelpersOnlyForMatchingModes(t *testing.T) {
	dir := t.TempDir()
	paths := AndroidPaths{
		Aether:   filepath.Join(dir, "libaether.so"),
		Psiphon:  filepath.Join(dir, "libpsiphon-tunnel-core.so"),
		Lyrebird: filepath.Join(dir, "liblyrebird.so"),
	}
	cases := []struct {
		name string
		p    Profile
		want []string
		deny []string
	}{
		{"tor", Profile{Label: "Tor-only", Args: []string{"--tor-only"}}, []string{"--tor-pt", paths.Lyrebird, "--tor-dir", filepath.Join(dir, "tor")}, []string{"--psiphon-bin"}},
		{"psiphon", Profile{Label: "Psiphon", Args: []string{"--psiphon-only"}}, []string{"--psiphon-bin", paths.Psiphon, "--psiphon-dir", filepath.Join(dir, "psiphon")}, []string{"--tor-pt"}},
		{"psiphon-cdn", Profile{Label: "Psiphon CDN", Args: []string{"--psiphon-only", "--psiphon-mode", "cdn"}}, []string{"--psiphon-bin", paths.Psiphon}, []string{"--tor-pt"}},
		{"aether", Profile{Label: "MASQUE H2", Args: []string{"--masque", "--h2"}}, nil, []string{"--tor-pt", "--psiphon-bin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := paths.ProfileArgs(tc.p, 18001, dir)
			for _, want := range tc.want {
				if !slices.Contains(args, want) {
					t.Fatalf("%s omitted required pinned helper or state path %q: %v", tc.name, want, args)
				}
			}
			for _, deny := range tc.deny {
				if slices.Contains(args, deny) {
					t.Fatalf("%s unexpectedly invoked unrelated helper %q: %v", tc.name, deny, args)
				}
			}
		})
	}
}
