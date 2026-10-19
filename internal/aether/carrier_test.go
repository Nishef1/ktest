package aether

import (
	"reflect"
	"strings"
	"testing"
)

func TestLocalCarrierVariantsPreserveDirectUDPAndIndependentBackends(t *testing.T) {
	original := []Profile{{Label: "H2", Args: []string{"--masque", "--h2", "--fragment"}}, {Label: "H3", Args: []string{"--masque", "--h3"}}, {Label: "WG", Args: []string{"--wg"}}, {Label: "Psiphon", Args: []string{"--psiphon-only"}}}
	variants := WithLocalCarriers(original)
	if len(variants) != 6 || !variants[1].LocalCarrier() || !variants[5].LocalCarrier() || variants[4].LocalCarrier() || !reflect.DeepEqual(original[0].Args, []string{"--masque", "--h2", "--fragment"}) {
		t.Fatal("changed original profiles or generated incompatible carriers")
	}
	p := variants[1]
	id := p.ID()
	args, err := BindLocalCarrier(RunArgs(p, 19090, t.TempDir()), "127.0.0.1:19080")
	if err != nil || strings.Contains(strings.Join(args, " "), LocalCarrierURL) || !strings.Contains(strings.Join(args, " "), "--upstream socks5://127.0.0.1:19080") {
		t.Fatalf("unresolved carrier: %v %v", args, err)
	}
	if p.ID() != id || !p.LocalCarrier() {
		t.Fatal("ephemeral bind changed persistent profile identity")
	}
	fast := ProfilesForMode(variants, "fast")
	if len(fast) != 4 || !fast[1].LocalCarrier() {
		t.Fatal("Fast lost its local carrier or acquired Psiphon")
	}
	for _, address := range []string{"example.org:1080", "8.8.8.8:1080", "127.0.0.1:0", "127.0.0.1:evil", "127.0.0.1:65536"} {
		if _, err := BindLocalCarrier(p.Args, address); err == nil {
			t.Fatalf("accepted unowned carrier address %s", address)
		}
	}
}
