package aether

import (
	"strings"
	"testing"
)

func TestAetherReleaseLocksMatchAndArePinned(t *testing.T) {
	desktop, err := DesktopBundleManifest()
	if err != nil { t.Fatal(err) }
	android, err := AndroidBundleManifest()
	if err != nil { t.Fatal(err) }
	if desktop.Version != android.Version || desktop.Repository != android.Repository {
		t.Fatalf("Android and desktop Aether releases diverged: desktop=%s Android=%s", desktop.Version, android.Version)
	}
	for _, key := range []string{"windows/amd64", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"} {
		goos, goarch, ok := strings.Cut(key, "/")
		if !ok { t.Fatal(key) }
		url, digest, err := DesktopArchiveFor(goos, goarch)
		if err != nil || !strings.Contains(url, "/releases/download/"+desktop.Version+"/") ||
			len(digest) != 64 {
			t.Fatalf("%s release is missing/invalid: %s %s %v", key, url, digest, err)
		}
	}
	for _, abi := range []string{"arm64-v8a", "armeabi-v7a", "x86_64"} {
		bundle, ok := android.ABIs[abi]
		if !ok || len(bundle.SHA256) != 64 || len(bundle.Files) != 3 {
			t.Fatalf("Android %s core/helper pin missing: %+v", abi, bundle)
		}
		for _, file := range bundle.Files {
			if len(file.SHA256) != 64 { t.Fatalf("Android %s %s digest missing", abi, file.Name) }
		}
	}
}
