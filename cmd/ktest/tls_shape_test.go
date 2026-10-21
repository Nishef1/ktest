package main

import (
	"os"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/tlsshape"
)

func TestSessionTLSCalibrationFollowsSelectedTransport(t *testing.T) {
	cases := []struct {
		mode   ConnectionMode
		method string
		want   bool
	}{
		{ModeBalanced, "", true},
		{ModeBalanced, "auto", true},
		{ModeFast, "masque-h2", true},
		{ModeBalanced, "gool-h3", true},
		{ModeAether, "mim-h2", true},
		{ModeBalanced, "wireguard", false},
		{ModeAether, "wiw", false},
		{ModeBalanced, "psiphon", false},
		{ModeBalanced, "psiphon-cdn", false},
		{ModeTor, "auto", false},
		{ModePsiphon, "auto", false},
		{ModeWindscribe, "auto", false},
	}
	for _, tc := range cases {
		o := defaultConnectOptions(t.TempDir())
		o.mode, o.aetherMethod = tc.mode, tc.method
		if got := sessionNeedsTLSCalibration(o); got != tc.want {
			t.Errorf("mode=%s method=%q: calibration=%v, want %v", tc.mode, tc.method, got, tc.want)
		}
	}
}

func TestAetherFragmentOffSkipsTCPExitNodeMasksButKeepsUDPNoise(t *testing.T) {
	opts, err := tlsshape.ParseOptions("auto", "auto", "off")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := loadAetherProfiles(t.TempDir(), "", "", ModeAether, tlsShape{opts: opts})
	if err != nil {
		t.Fatal(err)
	}
	var udpNoise, directH2 bool
	for _, p := range profiles {
		if p.ExitNode() == tlsshape.ExitNodeMask {
			t.Fatalf("fragment=off retained a TCP TLS-hello exit-node: %s", p.Label)
		}
		if p.ExitNode() == "udp-noise" {
			udpNoise = true
		}
		if p.Method() == "masque-h2" && p.ExitNode() == "" && !p.Has("--fragment") {
			directH2 = true
		}
	}
	if !udpNoise {
		t.Fatal("fragment=off removed the distinct UDP-noise fallback")
	}
	if !directH2 {
		t.Fatal("fragment=off removed all direct non-fragmented H2 profiles")
	}
}

func TestAetherTLSOptionsValidated(t *testing.T) {
	for _, bad := range []func(*connectOptions){
		func(o *connectOptions) { o.aetherFingerprint = "safari" },
		func(o *connectOptions) { o.masqueSNI = "1.1.1.1" },
		func(o *connectOptions) { o.aetherFragment = "8-16" },
	} {
		o := defaultConnectOptions(t.TempDir())
		bad(&o)
		if validateConnectOptions(o) == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	o := defaultConnectOptions(t.TempDir())
	o.aetherFingerprint, o.masqueSNI, o.aetherFragment = "semi-python", "a.example.com,b.example.com", "off"
	if err := validateConnectOptions(o); err != nil {
		t.Fatal(err)
	}
	// Carried across UAC with every other option.
	joined := strings.Join(elevatedConnectArgs(o), " ")
	for _, want := range []string{"-aether-fingerprint=semi-python", "-masque-sni=a.example.com,b.example.com", "-aether-fragment=off"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("%s missing from elevated args", want)
		}
	}
}

// By default (auto, nothing measured yet) Aether mode carries Patterniha's
// MASQUE F&F: semi-python with the tlshello-0-len exit-node.
func TestDefaultProfilesCarryFF(t *testing.T) {
	profiles, err := loadAetherProfiles(t.TempDir(), "", "", ModeAether)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range profiles {
		if strings.Contains(p.Label, "F&F semi-python") && p.ExitNode() == tlsshape.ExitNodeMask && p.Has("--disable-grease") {
			found = true
		}
	}
	if !found {
		t.Fatal("no semi-python + tlshello-0-len profile")
	}
	if len(profiles) > 64 {
		t.Fatalf("%d profiles exceed Aether's 64", len(profiles))
	}
}

func TestTLSMenuSavesChoices(t *testing.T) {
	output := menuOutput(t, "3\n5\n1\nsemi-python\n2\n1.2.3.4\n3\n100-200/0-5\n0\n0\n0\n")
	if !strings.Contains(output, "not a server name") {
		t.Fatal("invalid SNI accepted")
	}
	data, err := os.ReadFile(os.Getenv("KTEST_SETTINGS_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"aether-fingerprint": "semi-python"`, `"aether-fragment": "100-200/0-5"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("%s not saved:\n%s", want, data)
		}
	}
}
