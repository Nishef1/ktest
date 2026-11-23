package mobilebridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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
	key := network + "|" + core.SHA256 + "|" + currentAetherTLS().Key()
	if o.carrier != "" {
		key += "|carrier"
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

var nativeHistoryMu sync.Mutex

func nativeTLSHistoryPath(dir string) string {
	return filepath.Join(dir, "aether", "native-tls-winner.json")
}

func preferNativeTLSHistory(profiles []aether.Profile, dir, key string) []aether.Profile {
	if dir == "" || key == "" {
		return profiles
	}
	nativeHistoryMu.Lock()
	hints := readNativeTLSHistory(dir)
	nativeHistoryMu.Unlock()
	hint, ok := hints[key]
	if !ok || hint.Key != key || time.Since(hint.Checked) > 24*time.Hour || time.Until(hint.Checked) > time.Minute {
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
	nativeHistoryMu.Lock()
	defer nativeHistoryMu.Unlock()
	path := nativeTLSHistoryPath(dir)
	hints := readNativeTLSHistory(dir)
	hints[key] = nativeHint{Key: key, ID: tlsshape.HistoryKey(profile), Checked: time.Now()}
	for len(hints) > 16 {
		oldest := ""
		for id, hint := range hints {
			if id != key && (oldest == "" || hint.Checked.Before(hints[oldest].Checked)) {
				oldest = id
			}
		}
		delete(hints, oldest)
	}
	raw, err := json.Marshal(hints)
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

// Read the bounded map and migrate the earlier single-entry format safely.
func readNativeTLSHistory(dir string) map[string]nativeHint {
	hints := map[string]nativeHint{}
	raw, err := os.ReadFile(nativeTLSHistoryPath(dir))
	if err != nil || len(raw) > 32<<10 {
		return hints
	}
	if json.Unmarshal(raw, &hints) == nil && hints != nil {
		return hints
	}
	hints = map[string]nativeHint{}
	var old nativeHint
	if json.Unmarshal(raw, &old) == nil && old.Key != "" {
		hints[old.Key] = old
	}
	return hints
}
