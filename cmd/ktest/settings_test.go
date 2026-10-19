package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCoverageSurvivesMenuRestartAndIsSavedBeforeExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	t.Setenv("KTEST_SETTINGS_FILE", path)
	var first bytes.Buffer
	if code := runInteractive(strings.NewReader("7\n1\n0\n"), &first, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	initial := "Current Mode: Proxy"
	if runtime.GOOS == "windows" {
		initial = "Current Mode: TUN"
	}
	if !strings.Contains(first.String(), initial) {
		t.Fatalf("first launch lacks %q: %s", initial, first.String())
	}
	var reopened bytes.Buffer
	if code := runInteractive(strings.NewReader("0\n"), &reopened, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(reopened.String(), "Current Mode: Proxy") {
		t.Fatal("Proxy choice was lost on restart:", reopened.String())
	}
	// A choice is durable immediately, even if the process never exits cleanly.
	settings, file, options, err := loadPreferences("package")
	if err != nil || options.tun || settings.Connect["tun"] != "false" {
		t.Fatalf("saved Proxy choice: %+v err=%v", settings, err)
	}
	settings.Connect["tun"] = "true"
	if err := saveSettings(file, settings); err != nil {
		t.Fatal(err)
	}
	_, _, options, err = loadPreferences("package")
	if err != nil || !options.tun {
		t.Fatal("TUN choice was not restored", err)
	}
}

func TestSavedConnectionFlagsReuseTheCLIParserAndExplicitOverrides(t *testing.T) {
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	s, path, o, err := loadPreferences("package")
	if err != nil {
		t.Fatal(err)
	}
	flags := connectFlagSet(&o)
	if err := flags.Parse([]string{"-mode", "fast", "-tun=false", "-listen", "127.0.0.1:19000", "-first-byte", "3s", "-no-front", "-windscribe-wstunnel=false", "-windscribe-wstunnel-ip", "1.1.1.1", "-windscribe-wstunnel-path", "/tcp/127.0.0.1/1194", "-cert"}); err != nil {
		t.Fatal(err)
	}
	if !s.rememberFlags(flags) {
		t.Fatal("explicit choices were not recorded")
	}
	s.SkipCertificateOffer = true
	s.Tools = toolSettings{DiagnosisMode: "2", ScanProvider: "fastly", ScanCDN: "ws.example.com", WindscribeTarget: "Amsterdam", WindscribeSNIs: "python.org,none"}
	if err := saveSettings(path, s); err != nil {
		t.Fatal(err)
	}
	loaded, _, o, err := loadPreferences("package")
	if err != nil {
		t.Fatal(err)
	}
	if o.tun || o.mode != ModeFast || o.listen != "127.0.0.1:19000" || o.firstByte != 3*time.Second || !o.noFront || o.ws.direct || o.ws.serverIP != "1.1.1.1" || o.ws.path != "/tcp/127.0.0.1/1194" || o.cert {
		t.Fatalf("saved flags lost or one-shot action replayed: %+v", o)
	}
	if !loaded.SkipCertificateOffer || loaded.Tools != s.Tools || loaded.Connect["cert"] != "" {
		t.Fatalf("tool defaults or consent choice lost: %+v", loaded)
	}
	flags = connectFlagSet(&o)
	if err := flags.Parse([]string{"-mode", "tor", "-tun=true", "-no-front=false"}); err != nil {
		t.Fatal(err)
	}
	if o.mode != ModeTor || !o.tun || o.noFront || o.ws.serverIP != "1.1.1.1" || o.listen != "127.0.0.1:19000" {
		t.Fatalf("CLI override erased other saved choices: %+v", o)
	}
	if !loaded.rememberFlags(flags) || saveSettings(path, loaded) != nil {
		t.Fatal("could not update an existing settings file")
	}
	_, _, o, err = loadPreferences("package")
	if err != nil || o.mode != ModeTor || !o.tun || o.noFront {
		t.Fatalf("updated choices did not survive restart: %+v err=%v", o, err)
	}
}

func TestPolicyIsSavedEvenIfConnectionIsCancelledBeforeSetup(t *testing.T) {
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	s, path, options, err := loadPreferences("package")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	menu := &terminal{ui: plainTerm(&out), settings: s, settingsFile: path, options: options}
	lines := make(chan string)
	close(lines) // cancel at the certificate offer, before any network or UAC
	if menu.connectFromMenu("package", &input{lines: lines}, ModeFast) {
		t.Fatal("closed input was not returned")
	}
	s, _, options, err = loadPreferences("package")
	if err != nil || options.mode != ModeFast {
		t.Fatal("last policy was not saved before setup", err)
	}
	menu.settings, menu.options = s, options
	menu.mainMenu(t.TempDir())
	if !strings.Contains(out.String(), "Last used") {
		t.Fatal("restored policy is not identified in the menu")
	}
}

func TestExplicitIncompatibleFlagsStillFailBeforeConnectionOrSaving(t *testing.T) {
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	for _, args := range [][]string{
		{"-mode", "WiNdScRiBe", "-tun=true"},
		{"-mode", "balanced", "-windscribe-cdn", "ws.example.com"},
		{"-mode", "psiphon", "-exit-socks", "127.0.0.1:19000"},
	} {
		if got := runConnect(args); got != 2 {
			t.Fatalf("incompatible flags %v were not rejected: %d", args, got)
		}
	}
	path, _ := settingsPath()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid flags were persisted", err)
	}
}

func TestSavedModeAndCoverageDoNotOverrideWindscribeOwnership(t *testing.T) {
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	s, path, _, _ := loadPreferences("package")
	s.Connect = map[string]string{"mode": "windscribe", "tun": "true", "windscribe-cdn": "ws.example.com", "windscribe-cdn-sni": "ws.example.com", "exit-socks": "127.0.0.1:19001"}
	if err := saveSettings(path, s); err != nil {
		t.Fatal(err)
	}
	_, _, o, err := loadPreferences("package")
	if err != nil {
		t.Fatal(err)
	}
	menu := &terminal{options: o}
	ws := menu.menuConnectOptions("package", ModeWindscribe)
	if ws.tun || ws.exitSocks != "" || ws.ws.cdnHost != "ws.example.com" {
		t.Fatalf("other policy settings leaked into Windscribe: %+v", ws)
	}
	fast := menu.menuConnectOptions("package", ModeFast)
	if !fast.tun || fast.ws.cdnHost != "" || fast.ws.cdnSNI != "" || fast.exitSocks == "" {
		t.Fatalf("ordinary-policy choices lost: %+v", fast)
	}
	psiphon := menu.menuConnectOptions("package", ModePsiphon)
	if !psiphon.tun || psiphon.exitSocks != "" {
		t.Fatalf("Psiphon-only policy weakened: %+v", psiphon)
	}
}

func TestOrdinaryPoliciesDoNotInheritAnIsolatedAetherMethod(t *testing.T) {
	o := defaultConnectOptions("package")
	o.aetherMethod = "gool-h2"
	for _, mode := range []ConnectionMode{ModeBalanced, ModeFast} {
		got := optionsForMode(o, mode)
		if got.aetherMethod != "auto" {
			t.Fatalf("%s inherited a single-method exit search: %q", mode, got.aetherMethod)
		}
		// An explicit experiment still overrides policy defaults, as in runConnect.
		flags := connectFlagSet(&got)
		if err := flags.Parse([]string{"-aether-method", "gool-h2"}); err != nil || got.aetherMethod != "gool-h2" {
			t.Fatalf("explicit method override lost: %+v, %v", got, err)
		}
	}
	if got := optionsForMode(o, ModeAether); got.aetherMethod != "gool-h2" {
		t.Fatal("Aether's explicitly selected method was lost")
	}
}

func TestInvalidSettingsArePreservedAndRemovedFlagsCannotDisableProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	t.Setenv("KTEST_SETTINGS_FILE", path)
	bad := []byte(`{"connect":{"tun":"perhaps"}}`)
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	_, writable, _, err := loadPreferences("package")
	if err == nil || writable != "" {
		t.Fatal("invalid settings could be overwritten", err)
	}
	if err := saveSettings(writable, userSettings{}); err == nil {
		t.Fatal("silently overwrote invalid settings")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, bad) {
		t.Fatal("invalid user file was changed")
	}
	if err := os.WriteFile(path, []byte(`{"connect":{"mode":"fast","ai-direct":"true","cert":"true"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _, o, err := loadPreferences("package")
	if err != nil || o.cert || s.Connect["ai-direct"] != "" || s.Connect["cert"] != "" {
		t.Fatalf("removed opt-outs or one-shot actions survived: %+v err=%v", s, err)
	}
}
