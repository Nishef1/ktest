package main

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func menuOutput(t *testing.T, input string) string {
	t.Helper()
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader(input), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	return out.String()
}

func TestMenuExits(t *testing.T) {
	for _, in := range []string{"0\n", "q\n", ""} { // "" is stdin closed
		if !strings.Contains(menuOutput(t, in), "Select >") {
			t.Fatalf("no menu for %q", in)
		}
	}
}

func TestMenuKeysAreUniqueAndContiguous(t *testing.T) {
	want := 1
	for _, s := range menuSections {
		for _, it := range s.items {
			if it.key != strconv.Itoa(want) || it.action == nil {
				t.Fatalf("item %q (%s): want key %d with an action", it.key, it.name, want)
			}
			want++
		}
	}
}

func TestBlankInputNeverShownAsInvalidChoice(t *testing.T) {
	if out := menuOutput(t, "\n0\n"); strings.Contains(out, "Unknown option") {
		t.Fatalf("empty line incorrectly rejected: %s", out)
	}
}

func TestUnknownOptionNamesTheRange(t *testing.T) {
	if out := menuOutput(t, "42\n0\n"); !strings.Contains(out, `Unknown option "42". Select 1-11`) {
		t.Fatal(out)
	}
}

func TestSetupLineShowsState(t *testing.T) {
	if out := menuOutput(t, "0\n"); !strings.Contains(out, "certificate: ") || !strings.Contains(out, "exit paths (WARP/Psiphon): off") {
		t.Fatal(out)
	}
}

func TestMenuCoveragePreservesPolicyAndKeepsWindscribeSeparate(t *testing.T) {
	for _, wholePC := range []bool{false, true} {
		var output bytes.Buffer
		menu := &terminal{options: connectOptions{tun: wholePC}, ui: plainTerm(&output)}
		menu.mainMenu(t.TempDir())
		want := "7 Current Mode: Proxy"
		if wholePC {
			want = "7 Current Mode: TUN"
		}
		found := false
		for _, line := range strings.Split(output.String(), "\n") {
			if strings.Join(strings.Fields(line), " ") == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("wholePC=%t: expected only %q on coverage row:\n%s", wholePC, want, output.String())
		}
	}
	for _, mode := range []ConnectionMode{ModeBalanced, ModeFast, ModeAether, ModePsiphon, ModeTor, ModeWindscribe} {
		for _, wholePC := range []bool{false, true} {
			menu := &terminal{options: connectOptions{tun: wholePC}}
			o := menu.menuConnectOptions("example-base", mode)
			if o.mode != mode || o.tun != (wholePC && mode != ModeWindscribe) {
				t.Fatalf("mode=%s wholePC=%t produced mode=%s tun=%t", mode, wholePC, o.mode, o.tun)
			}
		}
	}
}

func TestElevationPreservesEffectivePolicyAcrossUserProfiles(t *testing.T) {
	o := defaultConnectOptions("example-base")
	o.mode, o.tun = ModeTor, true
	o.aiExtra, o.exitSocks = "sensitive.example", "127.0.0.1:19001"
	o.noDirect, o.noFront, o.verbose = true, true, true
	o.ws.sni, o.ws.direct = "python.org", false
	o.cert = true // already performed by the parent; never replay it
	args := elevatedConnectArgs(o)
	if args[0] != "connect" || args[1] != elevatedSessionArg {
		t.Fatalf("child could load another user's defaults: %v", args)
	}
	child := defaultConnectOptions("another-admin-package")
	child.mode, child.aiExtra = ModeFast, "other-user.example"
	flags := connectFlagSet(&child)
	if err := flags.Parse(args[2:]); err != nil {
		t.Fatal(err)
	}
	// Ignore the completed one-shot action when comparing the full snapshot.
	o.cert = false
	if child != o {
		t.Fatalf("effective options changed across UAC:\nchild: %+v\nparent: %+v", child, o)
	}
	if err := validateConnectOptions(child); err != nil {
		t.Fatal(err)
	}
}
