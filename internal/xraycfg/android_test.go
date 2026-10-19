package xraycfg

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalAndroidXrayProfileHasNoAdditionalTunnelOrRemoteExit(t *testing.T) {
	raw, err := ClientConfig(31234)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				UDP bool `json:"udp"`
			} `json:"settings"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Fragment struct {
					Packets  string `json:"packets"`
					Length   string `json:"length"`
					Interval string `json:"interval"`
				} `json:"fragment"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
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
	for _, port := range []int{0, -1, 65536} {
		if _, err := ClientConfig(port); err == nil {
			t.Fatalf("accepted bad port %d", port)
		}
	}
}

func TestXrayNativeBinaryRejectsNonPackageOrTamperedExecutable(t *testing.T) {
	if _, err := AndroidBinary("relative", "arm64"); err == nil {
		t.Fatal("accepted relative APK path")
	}
	if _, err := AndroidBinary(t.TempDir(), "arm"); err == nil {
		t.Fatal("claimed unsupported ABI")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "libxray.so"), []byte("not signed upstream"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := AndroidBinary(dir, "arm64"); err == nil {
		t.Fatal("accepted tampered Xray executable")
	}
}

func mustClientConfig(t *testing.T, port int) []byte {
	t.Helper()
	raw, err := ClientConfig(port)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOfficialXrayValidatesGeneratedAndroidProfile(t *testing.T) {
	bin := os.Getenv("KTEST_XRAY_BIN")
	if bin == "" {
		t.Skip("set KTEST_XRAY_BIN to the official pinned Xray executable to validate native schema")
	}
	dir := t.TempDir()
	profiles := []struct {
		name string
		raw  []byte
	}{
		{name: "fragment", raw: mustClientConfig(t, 31337)},
	}
	tun, err := TunConfig(31338, 1280)
	if err != nil {
		t.Fatal(err)
	}
	profiles = append(profiles, struct {
		name string
		raw  []byte
	}{name: "tun", raw: tun})
	for _, profile := range profiles {
		path := filepath.Join(dir, profile.name+".json")
		if err := os.WriteFile(path, profile.raw, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "run", "-test", "-c", path)
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("upstream Xray rejected Android %s JSON: %v: %s", profile.name, err, out)
		}
	}
}

func TestAndroidTunProfileUsesOnlyLoopbackGoSOCKS(t *testing.T) {
	raw, err := TunConfig(31234, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Name string `json:"name"`
				MTU  int    `json:"mtu"`
			} `json:"settings"`
			Sniffing struct {
				Enabled      bool     `json:"enabled"`
				DestOverride []string `json:"destOverride"`
			} `json:"sniffing"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				Servers []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				Type       string   `json:"type"`
				InboundTag []string `json:"inboundTag"`
				Outbound   string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Inbounds) != 1 {
		t.Fatalf("expected one TUN inbound: %s", raw)
	}
	in := profile.Inbounds[0]
	if in.Protocol != "tun" || in.Port != 0 || in.Tag != "ktest-tun" ||
		in.Settings.MTU != 1280 || !in.Sniffing.Enabled {
		t.Fatalf("unexpected TUN inbound: %s", raw)
	}
	if len(profile.Outbounds) != 1 {
		t.Fatalf("expected exactly one outbound: %s", raw)
	}
	out := profile.Outbounds[0]
	if out.Protocol != "socks" || out.Tag != "ktest-go-socks" ||
		len(out.Settings.Servers) != 1 ||
		out.Settings.Servers[0].Address != "127.0.0.1" ||
		out.Settings.Servers[0].Port != 31234 {
		t.Fatalf("TUN traffic is not restricted to the local Go SOCKS policy engine: %s", raw)
	}
	if len(profile.Routing.Rules) != 1 ||
		profile.Routing.Rules[0].Outbound != "ktest-go-socks" ||
		len(profile.Routing.Rules[0].InboundTag) != 1 ||
		profile.Routing.Rules[0].InboundTag[0] != "ktest-tun" {
		t.Fatalf("TUN inbound is not explicitly routed to Go SOCKS: %s", raw)
	}
	for _, forbidden := range []string{"freedom", "vless", "vmess", "allowInsecure", "0.0.0.0"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("unexpected direct/remote outbound option %q in %s", forbidden, raw)
		}
	}
	for _, tc := range []struct{ port, mtu int }{
		{0, 1280}, {-1, 1280}, {65536, 1280}, {31234, 1279}, {31234, 9001},
	} {
		if _, err := TunConfig(tc.port, tc.mtu); err == nil {
			t.Fatalf("accepted invalid TUN config port=%d mtu=%d", tc.port, tc.mtu)
		}
	}
}
