package mobilebridge

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/front"
)

func readFrontCAReport(t *testing.T, raw string) androidFrontCAReport {
	t.Helper()
	var report androidFrontCAReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestAndroidFrontCACreatesOnlyOnRequestAndExportsPublicCert(t *testing.T) {
	root := t.TempDir()
	start, err := FrontCAStatus(root)
	if err != nil || readFrontCAReport(t, start).State != "missing" {
		t.Fatalf("unexpected initial CA: %q, %v", start, err)
	}
	if _, err := FrontCAPublicPEM(root); err == nil {
		t.Fatal("export before explicit generation must fail")
	}
	created, err := GenerateFrontCA(root)
	if err != nil {
		t.Fatal(err)
	}
	report := readFrontCAReport(t, created)
	if report.State != "ready" || report.Trust != "not_checked" || report.Fingerprint == "" ||
		report.PermittedCount == 0 {
		t.Fatalf("generated CA must be explicitly untrusted: %+v", report)
	}
	dir := filepath.Join(root, androidFrontCADirectory)
	if info, err := os.Stat(dir); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0700) {
		t.Fatalf("CA directory is not private: %+v %v", info, err)
	}
	keyPath := filepath.Join(dir, front.KeyFile)
	info, err := os.Stat(keyPath)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("CA private key permissions: %+v %v", info, err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	public, err := FrontCAPublicPEM(root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(public, "PRIVATE KEY") || strings.Contains(public, string(keyBefore)) ||
		!strings.Contains(public, "BEGIN CERTIFICATE") {
		t.Fatal("export included a secret or omitted the public cert")
	}
	block, trailing := pem.Decode([]byte(public))
	if block == nil || len(trailing) != 0 {
		t.Fatal("public certificate is not a single PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || len(cert.PermittedDNSDomains) == 0 {
		t.Fatalf("exported CA lost domain constraints: %+v %v", cert, err)
	}
	if _, err := GenerateFrontCA(root); err == nil {
		t.Fatal("generating again would invalidate the existing device trust")
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil || string(keyBefore) != string(keyAfter) {
		t.Fatal("repeat generation changed the existing private key")
	}
	st, err := FrontCAStatus(root)
	if err != nil || readFrontCAReport(t, st).State != "ready" {
		t.Fatalf("cannot read generated CA status: %s, %v", st, err)
	}
}

func TestAndroidFrontCARejectsBrokenOrUnsafeState(t *testing.T) {
	for _, path := range []string{"", ".", "/", "relative/files"} {
		if _, err := GenerateFrontCA(path); err == nil {
			t.Fatalf("accepted unsafe private root %q", path)
		}
	}
	root := t.TempDir()
	dir := filepath.Join(root, androidFrontCADirectory)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, front.CertFile), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := FrontCAStatus(root)
	if err != nil || readFrontCAReport(t, raw).State != "invalid" {
		t.Fatalf("partial CA was not marked invalid: %s %v", raw, err)
	}
	if _, err := GenerateFrontCA(root); err == nil {
		t.Fatal("generated CA over partial files")
	}
	if _, err := FrontCAPublicPEM(root); err == nil {
		t.Fatal("exported broken CA")
	}
}

func TestAndroidFrontingOnlyUsesExistingValidatedPrivateCA(t *testing.T) {
	root := t.TempDir()
	if _, err := loadAndroidFrontCA(root); err == nil {
		t.Fatal("accepted missing local CA for fronting")
	}
	if _, err := GenerateFrontCA(root); err != nil {
		t.Fatal(err)
	}
	ca, err := loadAndroidFrontCA(root)
	if err != nil || !ca.Permits("www.youtube.com") || ca.Permits("bank.example") {
		t.Fatalf("did not restrict fronting to approved domain families: %v", err)
	}
	if _, err := StartAndroidProxyWithFronting("tor", "", "missing", root); err == nil {
		t.Fatal("fronting must not attach to Tor foreign exit")
	}
	if _, err := StartAndroidProxyWithFronting("balanced", "", "", root); err == nil {
		t.Fatal("fronting must require packaged local ByeDPI core")
	}
	dir := filepath.Join(root, androidFrontCADirectory)
	if err := os.Remove(filepath.Join(dir, front.KeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAndroidFrontCA(root); err == nil {
		t.Fatal("accepted incomplete CA after key removal")
	}
}
