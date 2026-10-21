package main

import (
	"os"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/tlsshape"
)

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
