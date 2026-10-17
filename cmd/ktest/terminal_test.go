package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func menuOutput(t *testing.T, input string) string {
	t.Helper()
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
	if out := menuOutput(t, "42\n0\n"); !strings.Contains(out, `Unknown option "42". Select 1-10`) {
		t.Fatal(out)
	}
}

func TestSetupLineShowsState(t *testing.T) {
	if out := menuOutput(t, "0\n"); !strings.Contains(out, "certificate: ") || !strings.Contains(out, "exit paths (WARP/Psiphon): off") {
		t.Fatal(out)
	}
}

func TestMenuCoveragePreservesPolicyAndKeepsWindscribeSeparate(t *testing.T) {
	for _, mode := range []ConnectionMode{ModeBalanced, ModeFast, ModeVPN, ModeTor, ModeWindscribe} {
		for _, wholePC := range []bool{false, true} {
			menu := &terminal{wholePC: wholePC}
			o := menu.menuConnectOptions("example-base", mode)
			if o.mode != mode || o.tun != (wholePC && mode != ModeWindscribe) {
				t.Fatalf("mode=%s wholePC=%t produced mode=%s tun=%t", mode, wholePC, o.mode, o.tun)
			}
		}
	}
}

func TestElevationPreservesChosenPolicyAndOriginalCLIFlags(t *testing.T) {
	o := defaultConnectOptions("example-base")
	o.mode, o.tun = ModeTor, true
	args := elevatedConnectArgs(o, nil)
	if !strings.Contains(strings.Join(args, " "), "-mode tor") {
		t.Fatalf("elevation changed Tor policy: %v", args)
	}
	original := []string{"-mode", "vpn", "-tun", "-exit-socks", "127.0.0.1:9000", "-no-front"}
	args = elevatedConnectArgs(o, original)
	if strings.Join(args[1:], "|") != strings.Join(original, "|") {
		t.Fatalf("elevation lost explicit CLI options: %v", args)
	}
}
