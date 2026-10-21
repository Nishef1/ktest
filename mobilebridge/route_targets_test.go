package mobilebridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/quickcheck"
)

func TestRouteTargetsPersistEditsAndRemovalOfDefaults(t *testing.T) {
	dir := t.TempDir()
	defaults, err := loadRouteTargets(dir)
	if err != nil || len(defaults) < len(quickcheck.Targets())+4 {
		t.Fatalf("missing quickcheck/X transport controls: %+v, %v", defaults, err)
	}
	for _, control := range quickcheck.Targets() {
		found := false
		for _, target := range defaults {
			found = found || target.URL == control.URL
		}
		if !found {
			t.Fatalf("missing existing control %s", control.URL)
		}
	}
	before := routeTargetsRevision(defaults)
	if _, err := SaveRouteTarget(dir, "custom", "My test", "https://www.youtube.com/watch?v=one", true); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveRouteTarget(dir, "custom", "Edited", "https://www.youtube.com/generate_204?x=two", false); err != nil {
		t.Fatal(err)
	}
	if _, err := DeleteRouteTarget(dir, defaults[0].ID); err != nil {
		t.Fatal(err)
	}
	got, err := loadRouteTargets(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range got {
		if target.ID == defaults[0].ID {
			t.Fatal("deleted default silently restored")
		}
		if target.ID == "custom" && (target.Fronting || target.Name != "Edited" || target.URL != "https://www.youtube.com/generate_204?x=two") {
			t.Fatalf("edit lost: %+v", target)
		}
	}
	if before == routeTargetsRevision(got) {
		t.Fatal("revision did not change")
	}
	reversed := append([]routeTarget(nil), got...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	if routeTargetsRevision(got) != routeTargetsRevision(reversed) {
		t.Fatal("revision depends on display order")
	}
	for _, target := range got {
		if _, err := DeleteRouteTarget(dir, target.ID); err != nil {
			t.Fatal(err)
		}
	}
	empty, err := loadRouteTargets(dir)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty override restored defaults: %+v %v", empty, err)
	}
	info, err := os.Stat(filepath.Join(dir, routeTargetsFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 && os.PathSeparator != '\\' {
		t.Fatalf("unsafe mode: %v", info.Mode())
	}
}

func TestRouteTargetValidationAndFamilyScope(t *testing.T) {
	dir := t.TempDir()
	for _, raw := range []string{"http://youtube.com/", "https://u:p@youtube.com/", "https://youtube.com/#x", "https://youtube.com/#", "https://youtube.com/\r\nHost: evil", "https://youtube.com/%0d%0aHost:evil", "https://bad..example/", "https://youtube.com:bad/"} {
		if _, err := SaveRouteTarget(dir, "invalid", "Bad", raw, true); err == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	targets := []routeTarget{{ID: "one", Name: "One", URL: "https://www.youtube.com/watch?v=test", Fronting: true}, {ID: "ai", Name: "AI", URL: "https://gemini.google.com/", Fronting: true}, {ID: "unknown", Name: "Unknown", URL: "https://unlisted.example/", Fronting: true}}
	if !routeFrontingAllowed(targets, "WWW.YOUTUBE.COM.") {
		t.Fatal("exact enabled host not matched")
	}
	// The whole family is covered, as on Windows; non-family hosts never.
	for _, host := range []string{"youtube.com", "rr5---sn-u14g55-5f.googlevideo.com", "i.ytimg.com"} {
		if !routeFrontingAllowed(targets, host) {
			t.Errorf("family host %s not fronted", host)
		}
	}
	for _, host := range []string{"www.youtube.com.evil.example", "unlisted.example"} {
		if routeFrontingAllowed(targets, host) {
			t.Errorf("fronting scope widened to %s", host)
		}
	}
	targets[0].Fronting = false
	if routeFrontingAllowed(targets, "www.youtube.com") {
		t.Fatal("disabled target still permits fronting")
	}
}

func TestRouteTargetsInspectOnlyExistingPublicCA(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, androidFrontCADirectory)
	if _, err := RouteTargets(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(caDir); !os.IsNotExist(err) {
		t.Fatal("listing generated a CA")
	}
	if _, err := front.Create(caDir, []string{"youtube.com"}); err != nil {
		t.Fatal(err)
	}
	// Coverage inspection must work with the public certificate alone. It must
	// neither load the private key nor regenerate an incomplete CA.
	if err := os.Remove(filepath.Join(caDir, front.KeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveRouteTarget(dir, "custom", "Unknown", "https://outside.example/path", true); err != nil {
		t.Fatal(err)
	}
	raw, err := RouteTargets(dir)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Targets []struct {
			ID, URL, Family, Note string
			CACovered             bool `json:"ca_covered"`
			Supported             bool
		}
	}
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatal(err)
	}
	for _, target := range report.Targets {
		if strings.Contains(target.URL, "www.youtube.com/") && !target.CACovered {
			t.Fatal("existing cert coverage lost")
		}
		if target.ID == "custom" && (target.CACovered || target.Supported || target.Note == "") {
			t.Fatalf("unproven custom family claimed supported: %+v", target)
		}
	}
	if _, err := os.Stat(filepath.Join(caDir, front.KeyFile)); !os.IsNotExist(err) {
		t.Fatal("private key regenerated")
	}
}

func TestRouteTargetsRejectUnsafeStorageAndActiveEdits(t *testing.T) {
	for _, dir := range []string{"", ".", filepath.VolumeName(t.TempDir()) + string(filepath.Separator)} {
		if _, err := loadRouteTargets(dir); err == nil {
			t.Errorf("accepted unsafe directory %q", dir)
		}
	}
	dir := t.TempDir()
	proxyMu.Lock()
	previous := pendingProxy
	pendingProxy = &proxyStartup{mode: "balanced", phase: "calibrating"}
	proxyMu.Unlock()
	t.Cleanup(func() { proxyMu.Lock(); pendingProxy = previous; proxyMu.Unlock() })
	if _, err := SaveRouteTarget(dir, "busy", "Busy", "https://youtube.com/", true); err == nil {
		t.Fatal("edited targets during startup/calibration")
	}
	if _, err := DeleteRouteTarget(dir, "default-youtube"); err == nil {
		t.Fatal("deleted target during startup/calibration")
	}
}

func TestRouteTargetsRejectSymlinksAndCorruptOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, routeTargetsFile)
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRouteTargets(dir); err == nil {
		t.Fatal("corrupt override silently restored defaults")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := SaveRouteTarget(dir, "link", "Link", "https://youtube.com/", true); err == nil {
		t.Fatal("followed symlinked target file")
	}
}

func TestRouteDirectoryAllowsPlatformAncestorMapping(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real-user")
	leaf := filepath.Join(realParent, "app", "files")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "user-0")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Skipf("platform alias fixture unavailable: %v", err)
	}
	got, err := realRouteDirectory(filepath.Join(alias, "app", "files"))
	gotInfo, gotStatErr := os.Stat(got)
	leafInfo, leafStatErr := os.Stat(leaf)
	if err != nil || gotStatErr != nil || leafStatErr != nil || !os.SameFile(gotInfo, leafInfo) {
		t.Fatalf("legitimate platform ancestor mapping rejected: %s %v (stat: %v, %v)", got, err, gotStatErr, leafStatErr)
	}
	if _, err := SaveRouteTarget(filepath.Join(alias, "app", "files"), "mapped", "Mapped", "https://youtube.com/", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(leaf, routeTargetsFile)); err != nil {
		t.Fatal(err)
	}
	leafAlias := filepath.Join(base, "leaf-alias")
	if err := os.Symlink(leaf, leafAlias); err != nil {
		t.Fatal(err)
	}
	if _, err := realRouteDirectory(leafAlias); err == nil {
		t.Fatal("accepted a symlink as the caller's private leaf")
	}
}

func TestRouteTargetOperationsRejectHeldStartupGate(t *testing.T) {
	dir := t.TempDir()
	proxyStartMu.Lock()
	defer proxyStartMu.Unlock()
	if _, err := SaveRouteTarget(dir, "busy", "Busy", "https://outside.example/", false); err == nil {
		t.Fatal("edit raced the startup gate")
	}
	if _, err := DeleteRouteTarget(dir, "default-youtube"); err == nil {
		t.Fatal("deletion raced the startup gate")
	}
	if _, err := TestTargetFronting(dir, "https://outside.example/", "8.8.8.8", 1); err == nil {
		t.Fatal("active test raced the startup gate")
	}
}
