package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestGoolBootstrapFailureKeepsKeysAndDoesNotPanic(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	data := enrollmentFixture(t, time.Now().Add(time.Hour))
	if err := os.WriteFile(identityFile(), data, 0600); err != nil {
		t.Fatal(err)
	}
	// Occupy only the reserved bootstrap port. A collision is an ordinary
	// failure and must not write through a nil enrollment ledger.
	l, err := net.Listen("tcp", "127.0.0.1:10910")
	if err == nil {
		defer l.Close()
	}
	m := &warpManager{t: plainTerm(&bytes.Buffer{})}
	if err := m.prepareIdentity(context.Background(), aetherProfile{Args: []string{"--gool", "--h2"}}); err == nil {
		t.Fatal("bootstrap port conflict accepted")
	}
	if !m.enrollTried[filepath.Join(warpDir(), "masque-gool.toml")] {
		t.Fatal("failed bootstrap will be repeated per profile")
	}
	got, _ := os.ReadFile(identityFile())
	if !bytes.Equal(data, got) {
		t.Fatal("primary identity changed")
	}
}

func TestAllAetherFamiliesRemainAvailableWithoutECH(t *testing.T) {
	profiles, err := loadAetherProfiles(t.TempDir(), "", "", ModeAether)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range aetherMethodChoices {
		if method.value == "auto" {
			continue
		}
		if len(filterAetherMethod(profiles, method.value)) == 0 {
			t.Errorf("missing %s without ECH", method.value)
		}
	}
	for _, method := range []string{"masque-h2", "masque-h3", "wireguard", "gool-h2", "gool-h3", "wiw", "mim-h2", "mim-h3"} {
		for _, p := range filterAetherMethod(profiles, method) {
			if p.psiphon() {
				t.Fatal("forced WARP family selected Psiphon")
			}
		}
	}
	noQuick := aetherProfile{Args: []string{"--masque", "--no-quick-reconnect"}}
	if strings.Contains(strings.Join(aetherRunArgs(0, noQuick, 10830), " "), " --quick-reconnect") {
		t.Fatal("explicit scan policy overridden")
	}
}

func TestNestedProfilesUseTheirOwnValidatedIdentityFiles(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	fixture := enrollmentFixture(t, time.Now().Add(time.Hour))
	for _, name := range []string{"masque.toml", "wg.toml", "wg-secondary.toml", "masque-secondary.toml", "masque-gool.toml"} {
		if err := os.WriteFile(filepath.Join(warpDir(), name), fixture, 0600); err != nil {
			t.Fatal(err)
		}
	}
	m := &warpManager{t: plainTerm(&bytes.Buffer{})}
	for _, flags := range [][]string{{"--gool", "--h2"}, {"--gool", "--h3"}, {"--gool-classic"}, {"--mim", "--h2"}, {"--protocol", "mim", "--h3"}} {
		if err := m.prepareIdentity(context.Background(), aetherProfile{Args: flags}); err != nil {
			t.Fatal(flags, err)
		}
	}
	inner := filepath.Join(warpDir(), "masque-secondary.toml")
	bad := []byte("partial")
	os.WriteFile(inner, bad, 0600)
	if err := m.prepareIdentity(context.Background(), aetherProfile{Args: []string{"--mim", "--h2"}}); err == nil {
		t.Fatal("damaged inner identity accepted")
	}
	got, _ := os.ReadFile(inner)
	if !bytes.Equal(got, bad) {
		t.Fatal("damaged inner identity replaced")
	}
}

func TestInnerEnrollmentPublishesTheNamedFileThroughTheOuterCarrier(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	path := filepath.Join(warpDir(), "masque-gool.toml")
	fixture := enrollmentFixture(t, time.Now().Add(time.Hour))
	routes := []enrollmentRoute{{"outer MASQUE", []string{"--upstream", "socks5://127.0.0.1:10910"}}}
	err := enrollWarpIdentityAt(context.Background(), plainTerm(&bytes.Buffer{}), "unused", "wg", path, routes, func(_ context.Context, _ string, args []string) error {
		if enrollmentArg(args, "--upstream") != "socks5://127.0.0.1:10910" || enrollmentArg(args, "--register") != "wg" {
			t.Fatal("inner registration escaped outer carrier", args)
		}
		stage := enrollmentArg(args, "--wg-config")
		if stage == path || filepath.Base(stage) != "masque-gool.toml" {
			t.Fatal("wrong staging file", stage)
		}
		return os.WriteFile(stage, fixture, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkWarpIdentity(path, "wg"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wireguardIdentityFile()); !os.IsNotExist(err) {
		t.Fatal("inner registration replaced primary WireGuard identity")
	}
}

func TestWindscribeAetherIsExplicitAndNeverLoadsPsiphonOrUnknownCarriers(t *testing.T) {
	base := t.TempDir()
	os.MkdirAll(filepath.Join(base, "profiles"), 0700)
	custom := `good | --gool --h2
psiphon | --psiphon-only
hidden psiphon | --masque --psiphon-reverse
tor | --masque --tor-reverse
unknown | --masque --upstream socks5://127.0.0.1:9999
`
	os.WriteFile(aetherProfilesFile(base), []byte(custom), 0600)
	profiles, err := loadAetherProfiles(base, "", "", ModeWindscribeAether)
	if err != nil || len(profiles) != 1 || profiles[0].Label != "good" {
		t.Fatal("foreign carrier policy bypass", profiles, err)
	}
	rules, _ := smartproxy.NewAIDomainRules("")
	for _, mode := range []ConnectionMode{ModeWindscribe, ModeWindscribeAether} {
		cfg := smartproxy.Config{}
		mode.configure(&cfg, rules)
		if mode == ModeWindscribe && (!cfg.LocalOnly || !cfg.RejectExits) {
			t.Fatal("local mode weakened")
		}
		if mode == ModeWindscribeAether && (cfg.LocalOnly || cfg.RejectExits || !cfg.ExitOnly("chatgpt.com") || cfg.ExitOnly("windscribe.com")) {
			t.Fatal("carrier confused with AI identity")
		}
	}
	o := optionsForMode(defaultConnectOptions(base), ModeWindscribeAether)
	if err := validateConnectOptions(o); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*connectOptions){func(o *connectOptions) { o.tun = true }, func(o *connectOptions) { o.noWarp = true }, func(o *connectOptions) { o.noHTTP = true }, func(o *connectOptions) { o.exitSocks = "127.0.0.1:19999" }, func(o *connectOptions) { o.aetherMethod = "psiphon-cdn" }} {
		bad := o
		alter(&bad)
		if validateConnectOptions(bad) == nil {
			t.Fatal("incompatible chain options accepted", bad)
		}
	}
}

// The test is offline: a valid primary identity must not be mistaken for a
// successfully prepared nested identity, or cause every core to time out at 45s.
func TestNestedBootstrapBudgetAndRecoverySearch(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	p := aetherProfile{Args: []string{"--gool", "--h2"}}
	if got := profileAttemptBudget(p); got != 225*time.Second {
		t.Fatalf("pending Gool enrollment got %v", got)
	}
	m := &warpManager{profs: []aetherProfile{p}}
	if got := m.searchBudget([]int{0}); got != 237*time.Second {
		t.Fatalf("first nested search got %v", got)
	}
	if err := os.WriteFile(filepath.Join(warpDir(), "masque-gool.toml"), enrollmentFixture(t, time.Now().Add(time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	if got := profileAttemptBudget(p); got != 80*time.Second {
		t.Fatalf("existing nested identity should use fast budget, got %v", got)
	}
	if got := m.searchBudget([]int{0}); got != 92*time.Second {
		t.Fatalf("ordinary automatic search got %v", got)
	}
}

func TestStrictSiteChecksAndFrontCATrustBoundaries(t *testing.T) {
	for _, mode := range []ConnectionMode{ModeAether, ModePsiphon, ModeTor, ModeWindscribeAether} {
		if canProbeSites(mode, false) || !canProbeSites(mode, true) {
			t.Fatalf("%s probed without a verified exit", mode)
		}
		if frontCARelevant(connectOptions{mode: mode}) {
			t.Fatalf("%s must not suggest installing a local MITM CA", mode)
		}
	}
	for _, mode := range []ConnectionMode{ModeFast, ModeBalanced} {
		if !canProbeSites(mode, false) || !frontCARelevant(connectOptions{mode: mode}) {
			t.Fatalf("%s lost optional mixed routing", mode)
		}
	}
	if frontCARelevant(connectOptions{mode: ModeBalanced, noFront: true}) || frontCARelevant(connectOptions{mode: ModeWindscribe}) {
		t.Fatal("fronting disabled but CA still recommended")
	}
}

// A failed geo-check is unknown reachability, not evidence of a blocked
// country. This uses a refused local SOCKS port and never contacts a website.
func TestUnavailableEgressProbeIsNotCountryRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := benchmarkAetherRoute(ctx, "127.0.0.1:0", false)
	if result.State != "egress-unverified" || result.Failure == "" {
		t.Fatalf("misclassified unreachable neutral probe: %+v", result)
	}
}

func TestDefaultAetherH2AndFreshGatewayPolicy(t *testing.T) {
	profiles, err := loadAetherProfiles(t.TempDir(), "ECH", "162.159.1.1", ModeAether)
	if err != nil { t.Fatal(err) }
	var found bool
	for _, p := range profiles {
		if p.Label != "WARP, MASQUE over HTTP/2 with ECH" { continue }
		found = true
		if !p.has("--fragment") || p.has("--no-fragment") {
			t.Fatalf("H2 ECH disables fragmentation: %+v", p)
		}
		args := strings.Join(aetherRunArgs(0, p, 10830), " ")
		if !strings.Contains(args, "--no-quick-reconnect") || strings.Contains(args, " --quick-reconnect") {
			t.Fatalf("stale gateway reused: %s", args)
		}
	}
	if !found { t.Fatal("H2 ECH profile absent") }
	p := aetherProfile{Args: []string{"--masque", "--h2", "--quick-reconnect"}}
	if strings.Contains(strings.Join(aetherRunArgs(0, p, 10830), " "), "--no-quick-reconnect") {
		t.Fatal("explicit quick-reconnect overridden")
	}
}

func TestAetherThoroughBudgetHonorsConfiguredStartup(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	p := aetherProfile{Args: []string{"--masque", "--h2", "--startup-secs", "100"}}
	if got := profileAttemptBudget(p); got < 125*time.Second {
		t.Fatalf("thorough attempt cancelled prematurely: %v", got)
	}
	m := &warpManager{profs: []aetherProfile{p}, o: connectOptions{aetherMethod:"masque-h2"}}
	if got := m.searchBudget([]int{0}); got < profileAttemptBudget(p)+10*time.Second {
		t.Fatalf("forced scan too short: %v", got)
	}
	m.o.aetherMethod = "auto"
	m.profs = append(m.profs, aetherProfile{Args: []string{"--wg"}}, aetherProfile{Args: []string{"--masque", "--h3"}})
	if got := m.searchBudget([]int{0,1,2}); got != 40*time.Second {
		t.Fatalf("automatic wave too long: %v",got)
	}
}
