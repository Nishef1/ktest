package mobilebridge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/Nishef1/ktest/internal/aether"
)

// Android saves only encrypted backup bytes into a document the user picks.
// WARP private identities are never copied to shared files, clipboard or
// logcat in plaintext. Android removes app-private keys on full uninstall,
// so restoring a user-exported encrypted backup is an explicit action.
func ExportAetherIdentityBackup(privateDir, password string) (string, error) {
	if !filepath.IsAbs(privateDir) {
		return "", errors.New("Android identity backup requires an app-private absolute path")
	}
	target := filepath.Join(privateDir, "aether")
	if _, err := aether.MigrateIdentityFiles(target, filepath.Join(privateDir, "automatic-exits")); err != nil {
		return "", err
	}
	data, err := aether.BackupIdentityBundle(target, password)
	if err != nil { return "", err }
	return base64.StdEncoding.EncodeToString(data), nil
}

func ImportAetherIdentityBackup(privateDir, password, encoded string) (string, error) {
	if !filepath.IsAbs(privateDir) {
		return "", errors.New("Android identity restore requires an app-private absolute path")
	}
	target := filepath.Join(privateDir, "aether")
	if _, err := aether.MigrateIdentityFiles(target, filepath.Join(privateDir, "automatic-exits")); err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil { return "", errors.New("backup document is not correctly encoded") }
	added, err := aether.RestoreIdentityBundle(target, password, data)
	if err != nil { return "", err }
	raw, _ := json.Marshal(struct{
		Imported []string `json:"imported"`
	}{Imported: added})
	return string(raw), nil
}

// AetherIdentityStatus reads only validity flags, never credential contents.
func AetherIdentityStatus(privateDir string) string {
	target := filepath.Join(privateDir, "aether")
	count := 0
	var warnings []string
	for name, protocol := range aether.IdentityFiles {
		err := aether.CheckIdentity(filepath.Join(target, name), protocol)
		if err == nil { count++ } else if !errors.Is(err, os.ErrNotExist) {
			warnings = append(warnings, name)
		}
	}
	raw, _ := json.Marshal(struct {
		Valid int `json:"valid"`
		Invalid []string `json:"invalid"`
		PrivateDirectory string `json:"private_directory"`
	}{Valid: count, Invalid: warnings, PrivateDirectory: target})
	return string(raw)
}
