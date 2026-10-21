package aether

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
)

//go:embed desktop-cores.json
var desktopBundleJSON []byte

type DesktopArchive struct {
	File string `json:"file"`
	SHA256 string `json:"sha256"`
}

type DesktopManifest struct {
	Version string `json:"version"`
	Repository string `json:"repository"`
	Archives map[string]DesktopArchive `json:"archives"`
}

func DesktopBundleManifest() (DesktopManifest, error) {
	var manifest DesktopManifest
	err := json.Unmarshal(desktopBundleJSON, &manifest)
	if err != nil {
		return manifest, err
	}
	if ok, _ := regexp.MatchString(`^v[0-9]+\.[0-9]+\.[0-9]+$`, manifest.Version); !ok {
		return manifest, errors.New("invalid locked Aether desktop version")
	}
	if manifest.Repository != "https://github.com/patterniha/Aether" {
		return manifest, errors.New("unexpected Aether release repository")
	}
	for platform, archive := range manifest.Archives {
		if archive.File == "" || filepath.Base(archive.File) != archive.File {
			return manifest, fmt.Errorf("invalid Aether archive path for %s", platform)
		}
		if ok, _ := regexp.MatchString(`^[0-9a-f]{64}$`, archive.SHA256); !ok {
			return manifest, fmt.Errorf("invalid Aether SHA-256 for %s", platform)
		}
	}
	return manifest, nil
}

func DesktopVersion() string {
	m, err := DesktopBundleManifest()
	if err != nil { return "" }
	return m.Version
}

func DesktopArchiveFor(goos, goarch string) (string, string, error) {
	manifest, err := DesktopBundleManifest()
	if err != nil { return "", "", err }
	platform := goos + "/" + goarch
	archive, found := manifest.Archives[platform]
	if !found { return "", "", fmt.Errorf("no checksum-pinned Aether %s archive for %s", manifest.Version, platform) }
	return manifest.Repository+"/releases/download/"+manifest.Version+"/"+archive.File, archive.SHA256, nil
}
