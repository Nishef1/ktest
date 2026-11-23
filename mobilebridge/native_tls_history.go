package mobilebridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/tlsshape"
)

// Reuse only profiles from the current inventory, never execute cached args.
// Scope history to the network, exact APK core artifact and user's settings.
func nativeTLSHistoryKey(o nativeOptions) string {
	network := tlsNetworkKey()
	manifest, err := aether.AndroidBundleManifest()
	if network == "" || o.privateDir == "" || err != nil {
		return ""
	}
	abi := map[string]string{"arm64": "arm64-v8a", "arm": "armeabi-v7a", "amd64": "x86_64"}[runtime.GOARCH]
	core, ok := manifest.ABIs[abi]
	if !ok {
		return ""
	}
	key := network + "|" + core.SHA256 + "|" + currentAetherTLS().Key() + "|" + o.method
	if o.carrier != "" {
		key += "|carrier"
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func nativeTLSHistoryPath(dir string) string {
	return filepath.Join(dir, "aether", "native-tls-winner.json")
}

func preferNativeTLSHistory(profiles []aether.Profile, dir, key string) []aether.Profile {
	if dir == "" || key == "" {
		return profiles
	}
	var hint nativeHint
	raw, err := os.ReadFile(nativeTLSHistoryPath(dir))
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &hint) != nil ||
		hint.Key != key || time.Since(hint.Checked) > 24*time.Hour || time.Until(hint.Checked) > time.Minute {
		return profiles
	}
	for i, p := range profiles {
		if tlsshape.HistoryKey(p) == hint.ID {
			out := append([]aether.Profile(nil), profiles...)
			copy(out[1:i+1], out[:i])
			out[0] = p
			return out
		}
	}
	return profiles
}

func saveNativeTLSHistory(dir, key string, profile aether.Profile) error {
	if dir == "" || key == "" {
		return os.ErrInvalid
	}
	path := nativeTLSHistoryPath(dir)
	raw, err := json.Marshal(nativeHint{Key: key, ID: tlsshape.HistoryKey(profile), Checked: time.Now()})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".native-tls-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(raw)
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), path)
}
