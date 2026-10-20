package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Keep user choices, never connection state, certificates or credentials.
// Connection values use the same parser as the CLI instead of a second schema.
type userSettings struct {
	Connect              map[string]string `json:"connect,omitempty"`
	SkipCertificateOffer bool              `json:"skip_certificate_offer,omitempty"`
	Tools                toolSettings      `json:"tools,omitempty"`
}

type toolSettings struct {
	DiagnosisMode       string `json:"diagnosis_mode,omitempty"`
	ScanProvider        string `json:"scan_provider,omitempty"`
	ScanCDN             string `json:"scan_cdn,omitempty"`
	WindscribeTarget    string `json:"windscribe_target,omitempty"`
	WindscribeSNIs      string `json:"windscribe_snis,omitempty"`
	WindscribeTransport string `json:"windscribe_transport,omitempty"`
}

func settingsPath() (string, error) {
	if path := os.Getenv("KTEST_SETTINGS_FILE"); path != "" {
		return path, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ktest", "settings.json"), nil
}

// Invalid/unreadable settings are preserved for repair. This session uses
// defaults and disables writes rather than silently replacing the user's file.
func loadPreferences(base string) (userSettings, string, connectOptions, error) {
	settings := userSettings{Connect: map[string]string{}}
	defaults := defaultConnectOptions(base)
	path, err := settingsPath()
	if err != nil {
		return settings, "", defaults, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return settings, path, defaults, nil
	}
	if err == nil {
		err = json.Unmarshal(data, &settings)
	}
	if err != nil {
		return userSettings{Connect: map[string]string{}}, "", defaults, fmt.Errorf("read %s: %w", path, err)
	}
	if settings.Connect == nil {
		settings.Connect = map[string]string{}
	}
	options := defaults
	flags := connectFlagSet(&options)
	// Stable order also makes invalid configuration diagnostics reproducible.
	names := make([]string, 0, len(settings.Connect))
	for name := range settings.Connect {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "cert" || flags.Lookup(name) == nil {
			delete(settings.Connect, name) // removed flags and one-shot actions
			continue
		}
		if err = flags.Set(name, settings.Connect[name]); err != nil {
			break
		}
	}
	if err == nil {
		options.mode, err = parseConnectionMode(string(options.mode))
		if err == nil {
			err = validateConnectOptions(optionsForMode(options, options.mode))
		}
	}
	if err != nil {
		return userSettings{Connect: map[string]string{}}, "", defaults, fmt.Errorf("invalid settings in %s: %w", path, err)
	}
	return settings, path, options, nil
}

func optionsForMode(o connectOptions, mode ConnectionMode) connectOptions {
	o.mode = mode
	// The ordinary-site policies search all exit methods. A method chosen in
	// Aether's submenu must not silently restrict their fallback inventory.
	// runConnect reapplies explicit CLI experiments after these defaults.
	if mode == ModeBalanced || mode == ModeFast {
		o.aetherMethod = "auto"
	}
	if mode != ModeWindscribe {
		o.ws.zapret = ""
	}
	if mode.isWindscribe() {
		o.tun = false
	} else {
		o.ws.cdnHost, o.ws.cdnSNI, o.ws.cdnEdges = "", "", ""
	}
	if mode.isWindscribe() || mode == ModePsiphon || mode == ModeFast {
		o.exitSocks = ""
	}
	if mode == ModeWindscribeAether {
		o.ws.cdnHost, o.ws.cdnSNI, o.ws.cdnEdges = "", "", ""
	}
	if mode == ModePsiphon && !strings.HasPrefix(o.aetherMethod, "psiphon") {
		o.aetherMethod = "auto"
	}
	if mode == ModeWindscribeAether && strings.HasPrefix(o.aetherMethod, "psiphon") {
		o.aetherMethod = "auto"
	}
	return o
}

func saveSettings(path string, settings userSettings) error {
	return saveJSONFile(path, settings)
}

func saveJSONFile(path string, value any) error {
	if path == "" {
		return errors.New("settings file is unavailable; changes last for this session only")
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (s *userSettings) rememberFlags(flags *flag.FlagSet) bool {
	changed := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "cert" || f.Name == "save" {
			return // actions, never saved defaults
		}
		if s.Connect == nil {
			s.Connect = map[string]string{}
		}
		if s.Connect[f.Name] != f.Value.String() {
			s.Connect[f.Name] = f.Value.String()
			changed = true
		}
	})
	return changed
}

func (t *terminal) savePreferences() bool {
	if err := saveSettings(t.settingsFile, t.settings); err != nil {
		t.ui.Line(toneWarn, "Settings were not saved: %v", err)
		t.notice, t.noticeTone = "Not saved: changes last for this session only", toneWarn
		return false
	}
	return true
}

func (t *terminal) rememberConnect(name, value string) bool {
	if t.settings.Connect == nil {
		t.settings.Connect = map[string]string{}
	}
	t.settings.Connect[name] = value
	return t.savePreferences()
}
