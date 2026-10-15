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
	variant = strings.ToUpper(strings.TrimSpace(variant))
	if variant != "A" && variant != "B" {
		return nil, errors.New("variant must be A or B")
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
	for _, candidate := range candidates {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(candidate, &obj); err != nil {
			return nil, err
		}
		var name string
		if err := json.Unmarshal(obj["remarks"], &name); err != nil {
			continue
		}
		if !strings.Contains(strings.ToLower(name), want) {
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
		inbound[0]["port"] = json.RawMessage("10808")
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
	return nil, fmt.Errorf("frag%s profile was not found in subscription", variant)
}

type Config struct {
	XrayBinary string
	Profile    string
	Variant    string
	AssetDir   string
	Output     io.Writer
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
	google := dnscheck.CheckGoogleDNS(ctx)
	if c.Output != nil {
		fmt.Fprintln(c.Output, "DNS preflight:", google.Format())
	}
	transport := ""
	if google.UDP {
		transport = "udp"
	} else if google.TCP {
		transport = "tcp"
	}
	profile, err := SelectProfileWithDNS(content, c.Variant, transport)
	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15_000_000_000)
	defer cancel()
	ver, err := exec.CommandContext(checkCtx, c.XrayBinary, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("query Xray version: %w", err)
	}
	if err := CheckVersion(string(ver)); err != nil {
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
	fmt.Fprintf(output, "Local HTTPS/SOCKS5 mixed proxy: 127.0.0.1:10808 (Fragment %s)\n", strings.ToUpper(c.Variant))
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
