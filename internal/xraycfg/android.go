// Package xraycfg pins Xray's native Android core and generates two
// narrowly scoped profiles: a loopback-only TLS fragmenter and a TUN adapter
// whose only outbound is KTest's local Go SOCKS policy engine.
package xraycfg

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

//go:embed android-cores.json
var pinnedAndroid []byte

// AndroidBinary accepts only the exact ELF shipped from XTLS/Xray-core's
// versioned official archive and extracted into ApplicationInfo.nativeLibraryDir.
func AndroidBinary(nativeDir, goarch string) (string, error) {
	if !filepath.IsAbs(nativeDir) {
		return "", errors.New("Xray requires an absolute read-only APK native directory")
	}
	abi := map[string]string{"arm64": "arm64-v8a"}[goarch]
	if abi == "" {
		return "", fmt.Errorf("official Android Xray is not pinned for %s", goarch)
	}
	var manifest struct {
		ABIs map[string]struct {
			Files []struct{ Name, SHA256 string }
		}
	}
	if err := json.Unmarshal(pinnedAndroid, &manifest); err != nil {
		return "", err
	}
	files := manifest.ABIs[abi].Files
	if len(files) != 1 || files[0].Name != "libxray.so" {
		return "", errors.New("invalid pinned Xray manifest")
	}
	path := filepath.Join(nativeDir, files[0].Name)
	stat, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("Xray is missing from the APK: %w", err)
	}
	if !stat.Mode().IsRegular() || stat.Size() < 1<<20 || stat.Size() > 70<<20 {
		return "", errors.New("Xray must be a bounded regular APK executable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != files[0].SHA256 {
		return "", errors.New("Xray SHA-256 mismatch: disabled rather than starting an unverified executable")
	}
	return path, nil
}

// ClientConfig uses the upstream Xray freedom/fragment feature, not KTest's
// ClientHello-cutting code. Only TCP/loopback is exposed; the shared Go policy
// retains DNS, CA fronting, verified foreign exits and device-wide routing.
func ClientConfig(port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid Xray loopback port")
	}
	// Keep the generated config small: no subscription, remote proxy, DNS
	// fallback, TUN, API, management listener or certificate/key material.
	root := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds": []any{map[string]any{
			"tag": "local-socks", "listen": "127.0.0.1", "port": port,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{map[string]any{
			"tag": "fragmented-direct", "protocol": "freedom",
			"settings": map[string]any{
				"fragment": map[string]any{"packets": "tlshello", "length": "100-200", "interval": "5-10"},
			},
			"streamSettings": map[string]any{
				"sockopt": map[string]any{"domainStrategy": "UseIP"},
			},
		}},
	}
	return json.Marshal(root)
}

// TunConfig turns Android's existing VpnService TUN fd into Xray's layer-3
// inbound, then sends every TCP/UDP flow to the local Go SOCKS engine. This is
// deliberately not a direct Internet outbound: adaptive route selection,
// DNS policy, foreign-exit verification and leak prevention remain in Go.
func TunConfig(socksPort, mtu int) ([]byte, error) {
	if socksPort < 1 || socksPort > 65535 {
		return nil, errors.New("invalid local Go SOCKS port")
	}
	if mtu < 1280 || mtu > 9000 {
		return nil, errors.New("invalid Android TUN MTU")
	}
	root := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "none"},
		"inbounds": []any{map[string]any{
			"tag":      "ktest-tun",
			"protocol": "tun",
			"settings": map[string]any{"name": "ktest-tun", "mtu": mtu},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic"},
			},
		}},
		"outbounds": []any{map[string]any{
			"tag":      "ktest-go-socks",
			"protocol": "socks",
			"settings": map[string]any{
				"servers": []any{map[string]any{
					"address": "127.0.0.1",
					"port":    socksPort,
				}},
			},
		}},
		"routing": map[string]any{
			"rules": []any{map[string]any{
				"type":        "field",
				"inboundTag":  []string{"ktest-tun"},
				"outboundTag": "ktest-go-socks",
			}},
		},
	}
	return json.Marshal(root)
}

// ValidateListen is used by tests to verify no Xray endpoint binds publicly.
func ValidateListen(listen string) bool {
	ip := net.ParseIP(listen)
	return ip != nil && ip.IsLoopback()
}


// VerifyAndroidServerlessAssets ensures geosite and geoip were packaged from
// the same SHA-256-pinned release as the Android executable. An Android app
// may copy these signed APK data assets into its private files directory;
// unknown, old, or altered files cannot be executed as route configuration.
func VerifyAndroidServerlessAssets(dir string) error {
	if !filepath.IsAbs(dir) || dir == string(filepath.Separator) {
		return errors.New("serverless Xray requires an absolute private assets directory")
	}
	var manifest struct {
		Assets map[string]string `json:"serverless_assets"`
	}
	if err := json.Unmarshal(pinnedAndroid, &manifest); err != nil {
		return err
	}
	if len(manifest.Assets) != 2 {
		return errors.New("APK was built without pinned Xray serverless geo databases")
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		want := manifest.Assets[name]
		if len(want) != 64 {
			return errors.New("invalid pinned Serverless geo database SHA-256")
		}
		path := filepath.Join(dir, name)
		file, err := os.Open(path)
		if err != nil {
			return errors.New("Serverless geo database is missing from app-private storage")
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 {
			file.Close()
			return errors.New("Serverless geo database is not a bounded regular file")
		}
		h := sha256.New()
		_, err = io.Copy(h, file)
		file.Close()
		if err != nil || hex.EncodeToString(h.Sum(nil)) != want {
			return errors.New("Serverless geo database does not match the signed Xray release")
		}
	}
	return nil
}
