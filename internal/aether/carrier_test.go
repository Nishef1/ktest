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

func TestExitNodeFragmentOffDisablesOnlyTCPHelloMasks(t *testing.T) {
	profiles := []Profile{
		{Label: "H2", Args: []string{"--masque", "--h2", "--fragment"}},
		{Label: "WG", Args: []string{"--wg", "--noize", "balanced"}},
	}
	variants := WithExitNodesOptions(profiles, true)
	var udpNoise bool
	for _, p := range variants {
		if p.ExitNode() == "tlshello-0-len" {
			t.Fatalf("fragment=off retained a TLS-hello mask: %s", p.Label)
		}
		if p.ExitNode() == "udp-noise" && p.Method() == "wireguard" {
			udpNoise = true
		}
	}
	if !udpNoise {
		t.Fatal("fragment=off incorrectly removed the independent UDP-noise fallback")
	}
	if !variants[0].Has("--fragment") {
		t.Fatal("exit-node policy mutated the caller's direct profile")
	}
}

func TestExitNodeVariantsFollowPattNG(t *testing.T) {
	original := []Profile{
		{Label: "H2", Args: []string{"--masque", "--h2", "--fragment"}},
		{Label: "H3", Args: []string{"--masque", "--h3"}},
		{Label: "WG", Args: []string{"--wg", "--noize", "balanced"}},
		{Label: "Psiphon", Args: []string{"--psiphon-only"}},
		{Label: "Pinned", Args: []string{"--wg", "--upstream", "socks5://127.0.0.1:9"}},
	}
	variants := WithExitNodes(original)
	if len(variants) != 8 {
		t.Fatalf("variants = %d", len(variants))
	}
	want := map[int]string{1: "tlshello-0-len", 3: "udp-noise", 5: "udp-noise"}
	for i, preset := range want {
		if variants[i].ExitNode() != preset || !variants[i].OwnedUpstream() || variants[i].Method() != variants[i-1].Method() {
			t.Fatalf("variant %d = %+v", i, variants[i])
		}
	}
	if variants[1].Has("--fragment") || !original[0].Has("--fragment") {
		t.Fatal("exit-node H2 kept Aether's own fragmentation, or the direct profile lost it")
	}
	if variants[6].ExitNode() != "" || variants[7].ExitNode() != "" {
		t.Fatal("Psiphon or a user upstream got an exit-node")
	}
	args, err := BindLocalCarrier(RunArgs(variants[3], 19090, t.TempDir()), "127.0.0.1:19081")
	joined := strings.Join(args, " ")
	if err != nil || strings.Contains(joined, "{EXIT") || !strings.Contains(joined, "--upstream socks5://127.0.0.1:19081") {
		t.Fatalf("unresolved exit-node: %v %v", args, err)
	}
	aetherOnly := ProfilesForMode(variants, "aether")
	if len(aetherOnly) != 6 {
		t.Fatalf("aether mode kept %d profiles", len(aetherOnly))
	}
	if got := ProfilesForMode(variants, "windscribe-aether"); len(got) != 3 {
		t.Fatalf("windscribe-aether must stay directly carried, kept %d", len(got))
	}
}
