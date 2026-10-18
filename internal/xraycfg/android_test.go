package xraycfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalAndroidXrayProfileHasNoAdditionalTunnelOrRemoteExit(t *testing.T) {
	raw, err := ClientConfig(31234)
	if err != nil { t.Fatal(err) }
	var profile struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port int `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct { UDP bool `json:"udp"` } `json:"settings"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Fragment struct {
					Packets string `json:"packets"`
					Length string `json:"length"`
					Interval string `json:"interval"`
				} `json:"fragment"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil { t.Fatal(err) }
	if len(profile.Inbounds) != 1 || !ValidateListen(profile.Inbounds[0].Listen) ||
		profile.Inbounds[0].Port != 31234 || profile.Inbounds[0].Protocol != "socks" || profile.Inbounds[0].Settings.UDP {
		t.Fatalf("Xray exposed an unexpected inbound: %s", raw)
	}
	if len(profile.Outbounds) != 1 || profile.Outbounds[0].Protocol != "freedom" ||
		profile.Outbounds[0].Settings.Fragment.Packets != "tlshello" ||
		profile.Outbounds[0].Settings.Fragment.Length == "" || profile.Outbounds[0].Settings.Fragment.Interval == "" {
		t.Fatalf("Xray is not a local-only TLS fragmenter: %s", raw)
	}
	for _, forbidden := range []string{"tun", "vless", "vmess", "certificate", "allowInsecure", "0.0.0.0"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("sensitive or unrelated Xray option %q found in %s", forbidden, raw)
		}
	}
	for _, port := range []int{0,-1,65536} {
		if _, err := ClientConfig(port); err == nil { t.Fatalf("accepted bad port %d", port) }
	}
}

func TestXrayNativeBinaryRejectsNonPackageOrTamperedExecutable(t *testing.T) {
	if _, err := AndroidBinary("relative", "arm64"); err == nil { t.Fatal("accepted relative APK path") }
	if _, err := AndroidBinary(t.TempDir(), "arm"); err == nil { t.Fatal("claimed unsupported ABI") }
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "libxray.so"), []byte("not signed upstream"), 0700); err != nil { t.Fatal(err) }
	if _, err := AndroidBinary(dir, "arm64"); err == nil { t.Fatal("accepted tampered Xray executable") }
}
