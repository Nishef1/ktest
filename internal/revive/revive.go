package revive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Nishef1/ktest/internal/dnscheck"
)

const MaxProfileSize = 1 << 20

// SelectProfile reads a saved upstream subscription bundle (an array of
// JSON configuration objects) or a single JSON object. It does not fetch
// profiles from the network: the offline path is deliberate.
func SelectProfile(data []byte, variant string) ([]byte, error) {
	return SelectProfileWithDNS(data, variant, "")
}

func SelectProfileWithDNS(data []byte, variant, verifiedTransport string) ([]byte, error) {
	return SelectProfileOnPort(data, variant, verifiedTransport, DefaultPort)
}

// DefaultPort is the loopback port the upstream profile is forced onto.
const DefaultPort = 10808

// SelectProfileOnPort is SelectProfileWithDNS with a chosen loopback port, so
// several cores can run side by side.
func SelectProfileOnPort(data []byte, variant, verifiedTransport string, port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid local port")
	}
	variant = strings.ToUpper(strings.TrimSpace(variant))
	if variant != "A" && variant != "B" && variant != "OOB" {
		return nil, errors.New("variant must be A, B or OOB")
	}
	if len(data) == 0 || len(data) > MaxProfileSize {
		return nil, errors.New("profile must be 1 byte to 1 MiB")
	}
	var candidates []json.RawMessage
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		if err := json.Unmarshal(data, &candidates); err != nil {
			return nil, fmt.Errorf("invalid subscription JSON: %w", err)
		}
	} else {
		if !json.Valid(data) {
			return nil, errors.New("profile must be plain JSON; use the subscription JSON, not a .jsonc file with comments")
		}
		candidates = []json.RawMessage{data}
	}
	want := "frag" + strings.ToLower(variant)
	if variant == "OOB" {
		want = "-oob"
	}
	for _, candidate := range candidates {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(candidate, &obj); err != nil {
			return nil, err
		}
		var name string
		if err := json.Unmarshal(obj["remarks"], &name); err != nil {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), want) {
			continue
		}
		var inbound []map[string]json.RawMessage
		if err := json.Unmarshal(obj["inbounds"], &inbound); err != nil || len(inbound) != 1 {
			return nil, errors.New("profile must have exactly one local mixed inbound")
		}
		var kind string
		if err := json.Unmarshal(inbound[0]["protocol"], &kind); err != nil || kind != "mixed" {
			return nil, errors.New("expected an Xray mixed inbound")
		}
		// Force loopback even if upstream changes defaults in a future profile.
		inbound[0]["listen"] = json.RawMessage(`"127.0.0.1"`)
		inbound[0]["port"] = json.RawMessage(strconv.Itoa(port))
		inbytes, err := json.Marshal(inbound)
		if err != nil {
			return nil, err
		}
		obj["inbounds"] = inbytes
		// v52 pins all otherwise unfiltered names to Cloudflare DoH with a
		// finalQuery gate. This fails even for reachable Google if Cloudflare
		// DoH is blocked. Preserve upstream transport/routing rules, but
		// prioritize local DNS for reachable Google services and add an
		// independent encrypted DNS fallback for other destinations.
		if err := improveDNSBootstrap(obj, verifiedTransport); err != nil {
			return nil, err
		}
		return json.MarshalIndent(obj, "", "  ")
	}
	return nil, fmt.Errorf("serverless %s profile was not found in subscription", variant)
}

type Config struct {
	XrayBinary string
	Profile    string
	Variant    string
	AssetDir   string
	Port       int // loopback port; 0 means DefaultPort
	// DestinationFamily is used only by the pinned profile behind KTest's family-enforcing proxy.
	DestinationFamily string
	Output            io.Writer
	// DNS is an optional, already measured Google DNS preflight. When nil, Run
	// measures it itself; callers that did so (the menu) avoid a second wait.
	DNS *dnscheck.Result
}

func (c Config) port() int {
	if c.Port == 0 {
		return DefaultPort
	}
	return c.Port
}

var versionPattern = regexp.MustCompile(`(?m)\bXray\s+(\d+)\.(\d+)\.(\d+)\b`)

func CheckVersion(raw string) error {
	matches := versionPattern.FindStringSubmatch(raw)
	if len(matches) != 4 {
		return errors.New("unable to identify Xray version; use a verified official release")
	}
	var y, mo, day int
	if _, err := fmt.Sscanf(strings.Join(matches[1:], "."), "%d.%d.%d", &y, &mo, &day); err != nil {
		return err
	}
	if y < 26 || (y == 26 && (mo < 6 || (mo == 6 && day < 27))) {
		return fmt.Errorf("Xray %d.%d.%d is too old; need 26.6.27 or newer", y, mo, day)
	}
	return nil
}

// CheckProfileMinimum honors the minimum Xray version specified by newer
// Serverless subscriptions. Older local-only profiles remain supported, but
// unknown or outdated binaries cannot silently accept newer configuration.
func CheckProfileMinimum(versionText string, profile []byte) error {
	var metadata struct {
		Version struct {
			Min string `json:"min"`
		} `json:"version"`
	}
	if err := json.Unmarshal(profile, &metadata); err != nil {
		return fmt.Errorf("invalid selected profile: %w", err)
	}
	if metadata.Version.Min == "" {
		return nil
	}
	minimum := strings.Split(metadata.Version.Min, ".")
	found := versionPattern.FindStringSubmatch(versionText)
	if len(minimum) != 3 || len(found) != 4 {
		return errors.New("invalid or unavailable Xray version for profile minimum")
	}
	for _, part := range minimum {
		if len(part) == 0 || len(part) > 5 {
			return fmt.Errorf("invalid minimum Xray version %q", metadata.Version.Min)
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return fmt.Errorf("invalid minimum Xray version %q", metadata.Version.Min)
			}
		}
	}
	for i := range minimum {
		want, err := strconv.Atoi(minimum[i])
		if err != nil {
			return err
		}
		current, err := strconv.Atoi(found[i+1])
		if err != nil {
			return err
		}
		if current < want {
			return fmt.Errorf("serverless profile requires Xray %s or newer (installed %s)", metadata.Version.Min, strings.Join(found[1:], "."))
		}
		if current > want {
			return nil
		}
	}
	return nil
}

// Run starts a user-supplied official Xray executable with an offline profile.
// It makes no changes to machine-wide proxies, certificates, DNS or routes.
func Run(ctx context.Context, c Config) error {
	if c.XrayBinary == "" || c.Profile == "" {
		return errors.New("both Xray binary and locally saved profile are required")
	}
	info, err := os.Stat(c.Profile)
	if err != nil {
		return err
	}
	if info.Size() > MaxProfileSize {
		return errors.New("profile file exceeds 1 MiB")
	}
	content, err := os.ReadFile(c.Profile)
	if err != nil {
		return err
	}
	return runSelectedProfile(ctx, c, content)
}

func runSelectedProfile(ctx context.Context, c Config, content []byte) error {
	profile, err := SelectProfileOnPort(content, c.Variant, "", c.port())
	if err != nil {
		return err
	}
	// Current v65 has its own DNS hierarchy; the older v52 Cloudflare-DoH
	// bootstrap is not used and must not add a blocking network request.
	if needsLegacyDNSBootstrap(profile) {
		var google dnscheck.Result
		if c.DNS != nil {
			google = *c.DNS
		} else {
			google = dnscheck.CheckGoogleDNS(ctx)
		}
		if c.Output != nil {
			fmt.Fprintln(c.Output, "Legacy DNS preflight:", google.Format())
		}
		transport := ""
		if google.UDP {
			transport = "udp"
		} else if google.TCP {
			transport = "tcp"
		}
		profile, err = SelectProfileOnPort(content, c.Variant, transport, c.port())
		if err != nil {
			return err
		}
	}
	if c.DestinationFamily != "" && c.DestinationFamily != "both" {
		profile, err = constrainProfileFamily(profile, c.DestinationFamily)
		if err != nil {
			return err
		}
	}
	return runProfile(ctx, c, profile)
}

// RunPinned executes only the embedded v65 config. The caller cannot supply
// another profile or replace a validated file between checking and execution.
func RunPinned(ctx context.Context, c Config) error {
	if c.Profile != "" {
		return errors.New("pinned Serverless refuses external profile files")
	}
	c.Profile = "embedded Serverless-for-Iran v65" // status label, not a path
	return runSelectedProfile(ctx, c, pinnedServerlessV65)
}

// LocalTCPProfile generates a closed local-only configuration. No imported
// subscription, relay, redirect, DNS route or TLS-specific modifier is used.
// Numeric fragment.packets slices TCP writes, including opaque OpenVPN frames.
func LocalTCPProfile(port int, variant string) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid local port")
	}
	packets, length, interval := "1-3", "1-8", "1-2"
	switch variant {
	case "A":
	case "B":
		packets, length, interval = "1-5", "8-32", "5-10"
	default:
		return nil, errors.New("local TCP variant must be A or B")
	}
	return []byte(fmt.Sprintf(`{
  "log":{"loglevel":"warning","access":"none"},
  "inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],
  "outbounds":[{"protocol":"freedom","settings":{"fragment":{"packets":%q,"length":%q,"interval":%q}}}]
}`, port, packets, length, interval)), nil
}

// RunLocalTCP uses only generated local TCP packet shaping. Config.Profile is
// deliberately rejected rather than trusted as a local-only subscription.
func RunLocalTCP(ctx context.Context, c Config) error {
	if c.XrayBinary == "" || c.Profile != "" {
		return errors.New("local TCP requires an Xray binary and forbids imported profiles")
	}
	profile, err := LocalTCPProfile(c.port(), c.Variant)
	if err != nil {
		return err
	}
	return runProfile(ctx, c, profile)
}

func runProfile(ctx context.Context, c Config, profile []byte) error {
	checkCtx, cancel := context.WithTimeout(ctx, 15_000_000_000)
	defer cancel()
	ver, err := exec.CommandContext(checkCtx, c.XrayBinary, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("query Xray version: %w", err)
	}
	if err := CheckVersion(string(ver)); err != nil {
		return err
	}
	if err := CheckProfileMinimum(string(ver), profile); err != nil {
		return err
	}
	f, err := os.CreateTemp("", "ktest-revive-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(profile); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	env := os.Environ()
	if c.AssetDir != "" {
		abs, err := filepath.Abs(c.AssetDir)
		if err != nil {
			return err
		}
		env = append(env, "XRAY_LOCATION_ASSET="+abs)
	}
	test := exec.CommandContext(checkCtx, c.XrayBinary, "run", "-test", "-c", f.Name())
	test.Env = env
	result, err := test.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Xray rejected the profile: %v: %s", err, strings.TrimSpace(string(result)))
	}
	output := c.Output
	if output == nil {
		output = os.Stderr
	}
	if c.Profile == "" {
		fmt.Fprintf(output, "Local-only SOCKS5 TCP fragmentation: 127.0.0.1:%d (generated variant %s; no remote exit)\n", c.port(), c.Variant)
	} else {
		fmt.Fprintf(output, "Local HTTP/SOCKS5 mixed proxy: 127.0.0.1:%d (Serverless %s; direct ISP IP, NOT a foreign VPN)\n", c.port(), strings.ToUpper(c.Variant))
	}
	fmt.Fprintln(output, "Use an application that explicitly supports this proxy. Other traffic, including Windscribe WireGuard, is unchanged.")
	cmd := exec.CommandContext(ctx, c.XrayBinary, "run", "-c", f.Name())
	cmd.Env = env
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("Xray exited: %w", err)
	}
	if ctx.Err() == nil {
		return errors.New("Xray exited unexpectedly")
	}
	return nil
}
