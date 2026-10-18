package mobilebridge

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/front"
)

const androidFrontCADirectory = "fronting-ca"

var frontCAMu sync.Mutex

// The Android caller passes Context.filesDir, never a shared or cache directory.
// Only the public certificate can be exported through this API; the private key
// never leaves app-private storage and is never returned through gomobile.
func frontCAPath(privateFilesDir string) (string, error) {
	if !filepath.IsAbs(privateFilesDir) || privateFilesDir == string(filepath.Separator) {
		return "", errors.New("CA storage requires an absolute Android private files directory")
	}
	info, err := os.Lstat(privateFilesDir)
	if err != nil {
		return "", fmt.Errorf("private files directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("CA storage must be a real private directory")
	}
	return filepath.Join(privateFilesDir, androidFrontCADirectory), nil
}

type androidFrontCAReport struct {
	State          string `json:"state"`
	Detail         string `json:"detail"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	Expires        string `json:"expires,omitempty"`
	PermittedCount int    `json:"permitted_count,omitempty"`
	// Android's trust store cannot be inferred from a generated PEM file.
	Trust string `json:"trust"`
}

func inspectAndroidFrontCA(dir string) androidFrontCAReport {
	report := androidFrontCAReport{State: "missing", Detail: "No CA has been generated on this device.", Trust: "not_checked"}
	_, certErr := os.Lstat(filepath.Join(dir, front.CertFile))
	_, keyErr := os.Lstat(filepath.Join(dir, front.KeyFile))
	if errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist) {
		return report
	}
	if certErr != nil || keyErr != nil {
		report.State, report.Detail = "invalid", "The CA is incomplete or unreadable. No replacement was generated."
		return report
	}
	ca, err := front.Load(dir)
	if err != nil {
		report.State, report.Detail = "invalid", "The local CA files are invalid. No replacement was generated."
		return report
	}
	report.Fingerprint = ca.Fingerprint()
	report.Expires = ca.Expires().UTC().Format("2006-01-02")
	report.PermittedCount = len(ca.Permitted())
	if !ca.ValidAt(time.Now()) || time.Until(ca.Expires()) <= 30*24*time.Hour {
		report.State, report.Detail = "outdated", "The CA is expired, not yet valid, or expires within 30 days. Do not install it."
	} else if len(front.Uncovered(front.DefaultFamilies(), ca.Permitted())) > 0 {
		report.State, report.Detail = "outdated", "This CA does not cover all current fronting domains; it was not replaced."
	} else {
		report.State, report.Detail = "ready", "Generated locally. Android certificate-store installation and trust are NOT verified."
	}
	return report
}

// FrontCAStatus performs local-only file checks; it never modifies OS trust.
func FrontCAStatus(privateFilesDir string) (string, error) {
	frontCAMu.Lock()
	defer frontCAMu.Unlock()
	dir, err := frontCAPath(privateFilesDir)
	if err != nil {
		return "", err
	}
	report := inspectAndroidFrontCA(dir)
	result, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// GenerateFrontCA requires an explicit user-initiated button press from Android.
// Existing or partial files are never silently overwritten or replaced.
func GenerateFrontCA(privateFilesDir string) (string, error) {
	frontCAMu.Lock()
	defer frontCAMu.Unlock()
	dir, err := frontCAPath(privateFilesDir)
	if err != nil {
		return "", err
	}
	report := inspectAndroidFrontCA(dir)
	if report.State != "missing" {
		return "", errors.New("a local CA already exists or has incomplete files; refusing to replace an installed trust anchor")
	}
	ca, err := front.Create(dir, front.PermittedDomains(front.DefaultFamilies()))
	if err != nil {
		return "", fmt.Errorf("generate local fronting CA: %w", err)
	}
	if !ca.ValidAt(time.Now()) {
		return "", errors.New("new certificate is not valid at the current device time")
	}
	report = inspectAndroidFrontCA(dir)
	if report.State != "ready" {
		return "", errors.New("new certificate did not pass local CA validation")
	}
	result, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// FrontCAPublicPEM returns only the validated PEM-encoded public CA certificate.
// Kotlin exports it via ACTION_CREATE_DOCUMENT; never export the private key.
func FrontCAPublicPEM(privateFilesDir string) (string, error) {
	frontCAMu.Lock()
	defer frontCAMu.Unlock()
	dir, err := frontCAPath(privateFilesDir)
	if err != nil {
		return "", err
	}
	if inspectAndroidFrontCA(dir).State != "ready" {
		return "", errors.New("there is no currently valid local CA to export")
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, front.CertFile))
	if err != nil {
		return "", err
	}
	block, remainder := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(remainder) != 0 {
		return "", errors.New("invalid CA public certificate format")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || len(cert.PermittedDNSDomains) == 0 {
		return "", errors.New("invalid CA public certificate")
	}
	return string(pem.EncodeToMemory(block)), nil
}
