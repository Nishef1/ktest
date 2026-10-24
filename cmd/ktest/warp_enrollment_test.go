package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

func enrollmentFixture(t *testing.T, expires time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: expires.Add(-24 * time.Hour), NotAfter: expires}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	data, err := toml.Marshal(map[string]string{
		"device_id": "test-device", "access_token": "test-secret", "ipv4": "172.16.0.2", "ipv6": "2606:4700::1",
		"wg_private_key": b64, "wg_peer_public_key": b64,
		"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"key_pem":  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func enrollmentArg(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func TestFastEnrollmentNeverStartsPsiphonOrTorEvenForFreshIdentity(t *testing.T) {
	routes := []enrollmentRoute{{"local", []string{"--upstream", "socks5://127.0.0.1:19080"}}, {"ECH", []string{"--ech", "config"}}, {"helper", []string{"--psiphon-reverse"}}, {"tor", []string{"--tor-only"}}, {"fragment", []string{"--api-fragment"}}}
	got := fastEnrollmentRoutes(routes)
	if len(got) != 3 || got[0].label != "local" || got[1].label != "ECH" || got[2].label != "fragment" {
		t.Fatalf("Fast enrollment escaped the local/Aether boundary: %+v", got)
	}
}

func TestEnrollmentValidatesBothProtocolsOfflineAndNeverReplacesSavedKeys(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	base := t.TempDir()
	os.MkdirAll(filepath.Dir(aetherBinary(base)), 0700)
	os.WriteFile(aetherBinary(base), []byte("core"), 0700)
	data := enrollmentFixture(t, time.Now().Add(time.Hour))
	for _, p := range []string{identityFile(), wireguardIdentityFile()} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if warpState(base) != "ready" {
		t.Fatal(warpState(base))
	}
	neverRun := func(context.Context, string, []string) error {
		t.Fatal("existing identity caused registration")
		return nil
	}
	for _, protocol := range []string{"masque", "wg"} {
		if err := enrollWarpIdentity(context.Background(), plainTerm(&bytes.Buffer{}), "unused", protocol, nil, neverRun); err != nil {
			t.Fatal(err)
		}
	}
	invalid := []byte("access_token = 'test-secret'\nwg_private_key = [not toml")
	os.WriteFile(identityFile(), invalid, 0600)
	if err := enrollWarpIdentity(context.Background(), plainTerm(&bytes.Buffer{}), "unused", "masque", nil, neverRun); err == nil || strings.Contains(err.Error(), "test-secret") {
		t.Fatalf("unsafe validation error: %v", err)
	}
	got, _ := os.ReadFile(identityFile())
	if !bytes.Equal(got, invalid) {
		t.Fatal("damaged file replaced")
	}
	os.WriteFile(identityFile(), enrollmentFixture(t, time.Now().Add(-time.Hour)), 0600)
	if checkWarpIdentity(identityFile(), "masque") == nil || warpState(base) != "partial" {
		t.Fatal("expired MASQUE certificate accepted")
	}
	if err := checkWarpIdentity(wireguardIdentityFile(), "wg"); err != nil {
		t.Fatal("WireGuard was confused with MASQUE", err)
	}
}

func TestEnrollmentFallbackStagesBothIdentitiesAndCancellationNeverPublishes(t *testing.T) {
	for _, protocol := range []string{"masque", "wg"} {
		t.Run(protocol, func(t *testing.T) {
			t.Setenv("KTEST_WARP_DIR", t.TempDir())
			data := enrollmentFixture(t, time.Now().Add(time.Hour))
			routes := []enrollmentRoute{{"blocked", []string{"--ech", "cfg"}}, {"partial", nil}, {"carrier", []string{"--psiphon-reverse"}}}
			calls := 0
			run := func(ctx context.Context, bin string, args []string) error {
				calls++
				if enrollmentArg(args, "--register") != protocol {
					t.Fatal("wrong protocol", args)
				}
				flag := "--masque-config"
				if protocol == "wg" {
					flag = "--wg-config"
				}
				path := enrollmentArg(args, flag)
				if filepath.Dir(path) == warpDir() {
					t.Fatal("registration writes into saved identity")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("partial file reused across attempts")
				}
				if calls == 1 {
					return errors.New("blocked API")
				}
				if calls == 2 {
					return os.WriteFile(path, []byte("partial"), 0600)
				}
				return os.WriteFile(path, data, 0600)
			}
			var out bytes.Buffer
			if err := enrollWarpIdentity(context.Background(), plainTerm(&out), "unused", protocol, routes, run); err != nil {
				t.Fatal(err)
			}
			if calls != 3 {
				t.Fatal(calls)
			}
			entries, _ := os.ReadDir(warpDir())
			if len(entries) != 1 {
				t.Fatal("staging files remain", entries)
			}
			path := identityFile()
			if protocol == "wg" {
				path = wireguardIdentityFile()
			}
			os.Remove(path)
			ctx, cancel := context.WithCancel(context.Background())
			err := enrollWarpIdentity(ctx, plainTerm(&out), "unused", protocol, routes, func(_ context.Context, _ string, args []string) error {
				flag := "--masque-config"
				if protocol == "wg" {
					flag = "--wg-config"
				}
				os.WriteFile(enrollmentArg(args, flag), data, 0600)
				cancel()
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("cancelled enrollment published an identity")
			}
		})
	}
}

func TestEnrollmentRoutesIncludeECHAndIndependentCDNCarrier(t *testing.T) {
	base := t.TempDir()
	os.MkdirAll(filepath.Dir(psiphonCore(base)), 0700)
	os.WriteFile(psiphonCore(base), []byte("helper"), 0700)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	routes := enrollmentRoutes(context.Background(), base, l.Addr().String(), "CFG", "1.2.3.4")
	if len(routes) != 5 ||
		routes[0].label != "local proxy" || enrollmentArg(routes[0].args, "--upstream") != "socks5://"+l.Addr().String() ||
		routes[1].label != "direct WARP API (core edge fallback)" || len(routes[1].args) != 0 ||
		routes[2].label != "fragmented API HTTPS" ||
		routes[3].label != "ECH" || enrollmentArg(routes[3].args, "--ech") != "CFG" || enrollmentArg(routes[3].args, "--api-address") != "1.2.3.4" ||
		routes[4].label != "Psiphon CDN bootstrap" || enrollmentArg(routes[4].args, "--psiphon-mode") != "cdn" {
		t.Fatal(routes)
	}
}

func TestManagerDoesNotRepeatBlockedEnrollmentAndRemovalKeepsOtherFiles(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	var out bytes.Buffer
	m := &warpManager{t: plainTerm(&out), enrollTried: map[string]bool{"masque": true}}
	for _, flag := range []string{"--psiphon-only", "--tor-only"} {
		if err := m.prepareIdentity(context.Background(), aetherProfile{Args: []string{flag}}); err != nil {
			t.Fatal("standalone carrier required a WARP identity", err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := m.prepareIdentity(context.Background(), aetherProfile{}); err == nil || !strings.Contains(err.Error(), "already attempted") {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"masque.toml", "wg.toml", "keep.txt"} {
		os.WriteFile(filepath.Join(warpDir(), name), []byte("keep"), 0600)
	}
	if warpDisable(plainTerm(&out)) != 0 {
		t.Fatal("removal failed")
	}
	if b, err := os.ReadFile(filepath.Join(warpDir(), "keep.txt")); err != nil || string(b) != "keep" {
		t.Fatal("unrelated file removed")
	}
}

func TestEnrollmentCancellationStopsItsCarrierChild(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows process-tree cancellation")
	}
	t.Setenv("KTEST_ENROLL_HELPER", "parent")
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv("KTEST_ENROLL_CHILD_PID", pidFile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runEnrollment(ctx, os.Args[0], []string{"-test.run=^TestEnrollmentProcessHelper$"}) }()
	var child *os.Process
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
waiting:
	for {
		select {
		case <-tick.C:
			data, err := os.ReadFile(pidFile)
			if err == nil {
				pid, err := strconv.Atoi(string(data))
				if err != nil {
					continue
				}
				child, err = os.FindProcess(pid)
				if err != nil {
					t.Fatal(err)
				}
				defer child.Kill()
				break waiting
			}
		case err := <-done:
			t.Fatalf("helper exited before starting its carrier: %v", err)
		case <-deadline:
			t.Fatal("carrier did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation reported success")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("registration did not stop")
	}
	ended := make(chan struct{})
	go func() { child.Wait(); close(ended) }()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("carrier child survived cancellation")
	}
}

// Separate process used by the cancellation regression; never contacts a network.
func TestEnrollmentProcessHelper(t *testing.T) {
	switch os.Getenv("KTEST_ENROLL_HELPER") {
	case "parent":
		cmd := exec.Command(os.Args[0], "-test.run=^TestEnrollmentProcessHelper$")
		cmd.Env = append(os.Environ(), "KTEST_ENROLL_HELPER=child")
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
	case "child":
		if err := os.WriteFile(os.Getenv("KTEST_ENROLL_CHILD_PID"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(1)
		}
		time.Sleep(time.Minute)
	}
}

// No local carrier or VPN is required to attempt the native API's edge fallback.
func TestEnrollmentNoProxyIncludesDirectAndFragmentedAttempts(t *testing.T) {
	routes := enrollmentRoutes(context.Background(), t.TempDir(), "", "cfg", "104.18.0.6")
	if len(routes) < 3 || routes[0].label != "direct WARP API (core edge fallback)" ||
		len(routes[0].args) != 0 || routes[1].label != "fragmented API HTTPS" ||
		routes[2].label != "ECH" {
		t.Fatalf("independent API fallback missing: %+v", routes)
	}
}
