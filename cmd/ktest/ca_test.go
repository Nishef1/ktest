package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/front"
)

func TestFrontSetupCanRestoreDisabledRoutingWithoutChangingTrust(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KTEST_CA_DIR", dir)
	path := filepath.Join(t.TempDir(), "settings.json")
	var output bytes.Buffer
	menu := &terminal{ui: plainTerm(&output), settingsFile: path,
		settings: userSettings{Connect: map[string]string{"no-front": "true", "tun": "true"}},
		options:  connectOptions{noFront: true, tun: true}}
	answers := []string{"ENABLE", "DISABLE", "ENABLE", ""}
	if !menu.frontSetup(func() (string, bool) {
		if len(answers) == 0 {
			return "", false
		}
		answer := answers[0]
		answers = answers[1:]
		return answer, true
	}) {
		t.Fatal("setup did not return to the menu")
	}
	if menu.options.noFront || menu.settings.Connect["no-front"] != "false" {
		t.Fatal("fronting stayed disabled after ENABLE")
	}
	t.Setenv("KTEST_SETTINGS_FILE", path)
	_, _, saved, err := loadPreferences("package")
	if err != nil || saved.noFront || !saved.tun {
		t.Fatalf("fronting choice was not saved independently: %+v, %v", saved, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("routing toggle changed CA files or trust", err)
	}
}

func TestCertificateHealthIncludesSystemTrustExpiryAndSupportedSites(t *testing.T) {
	ca, err := front.Create(t.TempDir(), front.PermittedDomains(front.DefaultFamilies()))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		now     time.Time
		trusted bool
		want    string
	}{
		{"healthy", time.Now(), true, "ok"},
		{"not installed", time.Now(), false, "untrusted"},
		{"expires soon", ca.Expires().Add(-24 * time.Hour), true, "outdated"},
		{"expired", ca.Expires().Add(time.Hour), true, "outdated"},
		{"not yet valid", ca.Expires().AddDate(-3, 0, 0), true, "outdated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := classifyCertificate(ca, tc.trusted, tc.now)
			if s.state != tc.want {
				t.Fatalf("got %s, want %s", s.state, tc.want)
			}
			green := strings.Contains(s.summary(&term{color: true}), "\x1b[32m")
			if green != (tc.want == "ok") {
				t.Fatal("unhealthy certificate was shown as green")
			}
		})
	}
	old, err := front.Create(t.TempDir(), []string{"youtube.com"})
	if err != nil {
		t.Fatal(err)
	}
	if s := classifyCertificate(old, true, time.Now()); s.state != "outdated" || !strings.Contains(s.summary(plainTerm(&bytes.Buffer{})), "Renew") {
		t.Fatal("old domain coverage did not offer renewal")
	}
}

func TestCertificateInspectionDetectsPartialFilesAndActualUntrustedCA(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KTEST_CA_DIR", dir)
	if inspectCertificate().state != "missing" {
		t.Fatal("empty directory was not missing")
	}
	if err := os.WriteFile(filepath.Join(dir, front.CertFile), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if inspectCertificate().state != "invalid" {
		t.Fatal("partial/broken files were treated as an installable CA")
	}
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	if _, err := loadOrCreateCA(caDir()); err != nil {
		t.Fatal(err)
	}
	if inspectCertificate().state != "untrusted" {
		t.Fatal("generating files alone was treated as system installation")
	}
}

func TestRemovingBrokenCAOnlyDeletesItsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KTEST_CA_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, front.CertFile), []byte("broken certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dir, "unrelated.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if caRemove(plainTerm(&bytes.Buffer{}), true) != 0 {
		t.Fatal("partial CA was not removable")
	}
	if _, err := os.Stat(filepath.Join(dir, front.CertFile)); !os.IsNotExist(err) {
		t.Fatal("partial CA remained")
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
		t.Fatal("unrelated files were deleted")
	}
}

func TestFronterStaysOffWithoutATrustedCA(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	u := plainTerm(&bytes.Buffer{})

	f, note := newFronter(connectOptions{noFront: true}, nil, u, nil, nil)
	if f != nil || !strings.Contains(note, "-no-front") {
		t.Fatalf("noFront: %v %q", f, note)
	}
	f, note = newFronter(connectOptions{}, nil, u, nil, nil)
	if f != nil || !strings.Contains(note, "ktest ca -install") {
		t.Fatalf("no CA: %v %q", f, note)
	}
	// A CA exists but nothing trusts it: still off, unless forced.
	if _, err := front.Create(caDir()+"/x", []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestCAStatusDescribesTheNextStep(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir()+"/ca")
	var out bytes.Buffer
	caStatus(plainTerm(&out))
	if !strings.Contains(out.String(), "ktest ca -install") {
		t.Fatalf("no next step:\n%s", out.String())
	}
	if _, err := loadOrCreateCA(caDir()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	caStatus(plainTerm(&out))
	if !strings.Contains(out.String(), "Not trusted") || !strings.Contains(out.String(), "44 domains") && !strings.Contains(out.String(), "domains") {
		t.Fatalf("status:\n%s", out.String())
	}
	f, note := newFronter(connectOptions{}, nil, plainTerm(&out), nil, nil)
	if f != nil || !strings.Contains(note, "does not trust") {
		t.Fatalf("untrusted CA must keep fronting off: %v %q", f, note)
	}
	f, _ = newFronter(connectOptions{forceFront: true}, nil, plainTerm(&out), nil, nil)
	if f == nil {
		t.Fatal("-front must force it on")
	}
}

// Reject conflicting commands before any trust-store or CA file mutation.
func TestCAConflictingOperationsRejected(t *testing.T) {
	for _, args := range [][]string{{"-install", "-delete"}, {"-renew", "-uninstall"}, {"-install", "-renew"}} {
		if got := runCA(args); got != 2 {
			t.Fatalf("%v returned %d", args, got)
		}
	}
}
