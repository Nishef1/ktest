package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const VerifiedRelease = "v0.7.2"

// Official v0.7.2 CLI asset hashes, as provided by the release metadata.
// We do not download, bundle, or auto-elevate the external packet injector.
var knownHashes = map[string]string{
	"sni-spoofing-windows-amd64.exe": "fc878e85aaab88362f41f66833ab85b0a9df9b399ecca1f34a75625c9dcfc8c4",
	"sni-spoofing-windows-arm64.exe": "80a03bb6c53d13ed0320827a1aab6fbd6c40f77c824bcefd366274aa0797cd7a",
	"sni-spoofing-linux-amd64":       "d5d32393bf7162d522ccd27744006acc483f4ee586c68845c180087fd31498c7",
	"sni-spoofing-linux-arm64":       "cc7fbcd57afaacbc18bf016421981c96f7e18ddae229fc236c167ca847c4e1b7",
	"sni-spoofing-darwin-amd64":      "41622463d2db93b493299393a67d30a087c5134aed124957ffaace9584a62566",
	"sni-spoofing-darwin-arm64":      "c393de00b6bcfd10c2b4820013e4328a19a1eccdc4110cd45e7928f73b15f5ee",
}

type EngineConfig struct {
	Binary      string
	SHA256      string // Optional explicit digest for a vetted newer binary.
	Bridge      string
	Target      string
	FakeSNI     string
	Fingerprint string
	Injector    string
	Fragment    bool
}

func CheckEngine(cfg EngineConfig) ([]string, error) {
	if cfg.Binary == "" {
		return nil, errors.New("engine path is required")
	}
	name := filepath.Base(cfg.Binary)
	expected := cfg.SHA256
	if expected == "" {
		expected = knownHashes[name]
	}
	if len(expected) != 64 {
		return nil, errors.New("engine is not a known release binary: supply -engine-sha256 after verifying the binary yourself")
	}
	digest, err := hex.DecodeString(expected)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("invalid expected sha256")
	}
	f, err := os.Open(cfg.Binary)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expected) {
		return nil, errors.New("engine sha256 mismatch; refusing to execute")
	}
	if !validName(strings.ToLower(cfg.FakeSNI)) {
		return nil, errors.New("invalid fake SNI")
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "firefox"
	}
	switch cfg.Fingerprint {
	case "firefox", "chrome", "edge", "safari", "ios", "qq", "360browser", "none":
	default:
		return nil, errors.New("unknown uTLS fingerprint")
	}
	if cfg.Injector == "" {
		cfg.Injector = "active"
	}
	if cfg.Injector != "active" && cfg.Injector != "passive" {
		return nil, errors.New("injector must be active or passive")
	}
	if runtime.GOOS == "darwin" && cfg.Injector != "passive" {
		return nil, errors.New("macOS supports the passive injector only")
	}
	hst, port, err := net.SplitHostPort(cfg.Target)
	if err != nil || port != "443" || hst == "" {
		return nil, errors.New("target must be host:443")
	}
	if _, _, err = net.SplitHostPort(cfg.Bridge); err != nil {
		return nil, errors.New("bridge must be host:port")
	}
	args := []string{"-listen", cfg.Bridge, "-connect", cfg.Target, "-fake-sni", cfg.FakeSNI, "-utls", cfg.Fingerprint, "-injector", cfg.Injector}
	if cfg.Fragment {
		args = append(args, "-enable-fragment")
	}
	return args, nil
}

// StartEngine launches the reviewed upstream CLI without a shell or elevation.
// Caller is responsible for starting ktest with the OS privileges the external
// packet injector requires. The child exits when the context is cancelled.
func StartEngine(ctx context.Context, cfg EngineConfig) (<-chan error, error) {
	args, err := CheckEngine(cfg)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(cfg.Binary, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start SNI engine: %w", err)
	}
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		done <- cmd.Wait()
		close(exited)
	}()
	go func() {
		select {
		case <-ctx.Done():
			// A graceful interrupt lets the external tool clean up packet hooks.
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				_ = cmd.Process.Kill()
			}
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
			}
		case <-exited:
		}
	}()
	return done, nil
}
