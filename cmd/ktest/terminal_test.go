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

func TestEnterConnectsWithSavedPolicyWithoutRepeatingSelection(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	settings, path, _, err := loadPreferences(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	settings.Connect["mode"] = "fast"
	if err := saveSettings(path, settings); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	// EOF at the certificate offer ends the operation before networking/UAC.
	if code := runInteractive(strings.NewReader("\n"), &output, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(output.String(), "Connect with Fast") || !strings.Contains(output.String(), "Policy: fast.") || strings.Contains(output.String(), "Unknown option") {
		t.Fatalf("Enter did not select the saved policy: %s", output.String())
	}
}

func TestUnknownOptionNamesTheRange(t *testing.T) {
	if out := menuOutput(t, "42\n0\n"); !strings.Contains(out, "Unknown option. Use 1-11, Enter, or 0.") {
		t.Fatal(out)
	}
}

func TestMenuDoesNotAdvertiseConfiguredExitsAsConnected(t *testing.T) {
	if out := menuOutput(t, "0\n"); !strings.Contains(out, "Disconnected") || strings.Contains(out, "exit paths (WARP/Psiphon):") || strings.Contains(out, "READY") {
		t.Fatal("configuration was presented as a connection:", out)
	}
}

func TestCoverageSaveFailureDoesNotClaimSuccess(t *testing.T) {
	var out bytes.Buffer
	menu := &terminal{ui: plainTerm(&out), options: connectOptions{tun: true}}
	lines := make(chan string, 1)
	lines <- "1"
	if !menu.chooseCoverage(&input{lines: lines}) {
		t.Fatal("coverage selection ended the menu")
	}
	menu.mainMenu(t.TempDir())
	if menu.options.tun || !strings.Contains(out.String(), "Not saved:") || strings.Contains(out.String(), "Saved: Proxy") {
		t.Fatal("unsaved coverage change was presented as durable:", out.String())
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
