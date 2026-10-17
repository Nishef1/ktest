package aether

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

//go:embed android-cores.json
var androidBundleJSON []byte

type AndroidArtifact struct {
	Archive          string                `json:"archive"`
	SHA256           string                `json:"sha256"`
	Machine          int                   `json:"machine"`
	Bits             int                   `json:"bits"`
	MinLoadAlignment int                   `json:"min_load_alignment"`
	Files            []AndroidArtifactFile `json:"files"`
}

type AndroidArtifactFile struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type AndroidManifest struct {
	Version    string                     `json:"version"`
	Repository string                     `json:"repository"`
	ABIs       map[string]AndroidArtifact `json:"abis"`
}

func AndroidBundleManifest() (AndroidManifest, error) {
	var manifest AndroidManifest
	err := json.Unmarshal(androidBundleJSON, &manifest)
	return manifest, err
}

type AndroidPaths struct {
	Aether   string `json:"aether"`
	Psiphon  string `json:"psiphon"`
	Lyrebird string `json:"lyrebird"`
	ABI      string `json:"abi"`
	Version  string `json:"version"`
}

// AndroidBundlePaths accepts only complete checksum-pinned native APK contents.
// Kotlin supplies ApplicationInfo.nativeLibraryDir; the ABI is Go's own runtime
// architecture. No binary is downloaded, copied to app storage or executed here.
func AndroidBundlePaths(nativeDir, goarch string) (AndroidPaths, error) {
	manifest, err := AndroidBundleManifest()
	if err != nil {
		return AndroidPaths{}, err
	}
	abi := map[string]string{"arm": "armeabi-v7a", "arm64": "arm64-v8a", "amd64": "x86_64"}[goarch]
	artifact, ok := manifest.ABIs[abi]
	if !ok {
		return AndroidPaths{}, fmt.Errorf("no pinned Aether Android bundle for %s", goarch)
	}
	if !filepath.IsAbs(nativeDir) {
		return AndroidPaths{}, errors.New("native core directory must be an absolute Android package path")
	}
	paths := AndroidPaths{ABI: abi, Version: manifest.Version}
	for _, file := range artifact.Files {
		if file.Name == "" || filepath.Base(file.Name) != file.Name {
			return AndroidPaths{}, errors.New("invalid native core manifest filename")
		}
		path := filepath.Join(nativeDir, file.Name)
		stat, err := os.Lstat(path)
		if err != nil {
			return AndroidPaths{}, fmt.Errorf("packaged native core %s is missing: %w", file.Name, err)
		}
		if !stat.Mode().IsRegular() || stat.Size() > 100<<20 {
			return AndroidPaths{}, fmt.Errorf("packaged native core %s is not a regular bounded file", file.Name)
		}
		reader, err := os.Open(path)
		if err != nil {
			return AndroidPaths{}, err
		}
		hash := sha256.New()
		_, readErr := io.Copy(hash, io.LimitReader(reader, (100<<20)+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
			return AndroidPaths{}, fmt.Errorf("packaged native core %s checksum mismatch; no core started", file.Name)
		}
		switch file.Name {
		case "libaether.so":
			paths.Aether = path
		case "libpsiphon-tunnel-core.so":
			paths.Psiphon = path
		case "liblyrebird.so":
			paths.Lyrebird = path
		}
	}
	if paths.Aether == "" || paths.Psiphon == "" || paths.Lyrebird == "" {
		return AndroidPaths{}, errors.New("native core bundle is incomplete")
	}
	return paths, nil
}

func (paths AndroidPaths) ProfileArgs(p Profile, port int, stateDir string) []string {
	args := RunArgs(p, port, stateDir)
	if p.Psiphon() || p.Has("--psiphon") || p.Has("--psiphon-reverse") {
		args = append(args, "--psiphon-bin", paths.Psiphon)
	}
	if p.Has("--tor-only") || p.Has("--tor") || p.Has("--tor-reverse") {
		args = append(args, "--tor-pt", paths.Lyrebird, "--tor-dir", filepath.Join(stateDir, "tor"))
	}
	return args
}
