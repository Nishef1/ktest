package byedpi

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed android-cores.json
var androidManifest []byte

// AndroidBinary accepts only the unmodified, pinned APK executable. The app
// executes it from ApplicationInfo.nativeLibraryDir, never writable app files.
func AndroidBinary(nativeDir, goarch string) (string, error) {
	var manifest struct {
		ABIs map[string]struct {
			Files []struct{ Name, SHA256 string }
		}
	}
	if err := json.Unmarshal(androidManifest, &manifest); err != nil {
		return "", err
	}
	abi := map[string]string{"arm": "armeabi-v7a", "arm64": "arm64-v8a", "amd64": "x86_64"}[goarch]
	artifact, ok := manifest.ABIs[abi]
	if !ok || len(artifact.Files) != 1 {
		return "", fmt.Errorf("no pinned ByeDPI executable for %s", goarch)
	}
	if !filepath.IsAbs(nativeDir) {
		return "", errors.New("ByeDPI requires an absolute package native directory")
	}
	file := artifact.Files[0]
	if file.Name != "libciadpi.so" {
		return "", errors.New("invalid ByeDPI manifest filename")
	}
	path := filepath.Join(nativeDir, file.Name)
	stat, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("packaged ByeDPI is missing: %w", err)
	}
	if !stat.Mode().IsRegular() || stat.Size() > 1<<20 {
		return "", errors.New("packaged ByeDPI must be a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != file.SHA256 {
		return "", errors.New("packaged ByeDPI checksum mismatch; no core started")
	}
	return path, nil
}
