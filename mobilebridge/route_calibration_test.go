package mobilebridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/routeplan"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestManualRouteDiagnosticsDoNotReuseFreshProfile(t *testing.T) {
	dir := t.TempDir()
	targets, err := loadRouteTargets(dir)
	if err != nil {
		t.Fatal(err)
	}
	config := smartproxy.Config{Upstreams: []smartproxy.Upstream{{Name: "fixed", Addr: "127.0.0.1:1"}}}
	profile := &routeplan.Profile{Version: 1, CompletedAt: time.Now().UTC(), Default: "fixed", TargetsKey: routeProfileKey(targets, config, dir),
		Selections: []routeplan.Selection{{TargetID: targets[0].ID, URL: targets[0].URL, Method: "fixed", Assessment: "https_verified"}}}
	if err := routeplan.Save(dir, profile); err != nil {
		t.Fatal(err)
	}
	// An explicit manual test must not substitute old observations, even when
	// its new work is canceled before the first measurement.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := runRouteDiagnostics(ctx, &config, dir)
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("manual test reused a stale result: %+v, %v", got, err)
	}
}

func TestProfileIdentityIgnoresChildPortsButIncludesExternalExit(t *testing.T) {
	targets := []routeTarget{{ID: "x", URL: "https://x.com/"}}
	config := smartproxy.Config{Upstreams: []smartproxy.Upstream{{Name: "ByeDPI", Addr: "127.0.0.1:1000"}, {Name: "Foreign exit", Addr: "127.0.0.1:2000", Exit: true}}}
	before := routeProfileKey(targets, config, "")
	config.Upstreams[0].Addr = "127.0.0.1:3000"
	if routeProfileKey(targets, config, "") != before {
		t.Fatal("new child port invalidated a fixed method")
	}
	config.Upstreams[1].Addr = "127.0.0.1:4000"
	if routeProfileKey(targets, config, "") == before {
		t.Fatal("changed external exit reused an unrelated observation")
	}
}

func TestRouteStatusCannotLeakProfileAcrossPrivateDirectories(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	routeTestMu.Lock()
	old := routeTestState
	routeTestState = routeTestReport{privateDir: first, Profile: &routeplan.Profile{Default: "private observation"}}
	routeTestMu.Unlock()
	t.Cleanup(func() { routeTestMu.Lock(); routeTestState = old; routeTestMu.Unlock() })
	raw, err := RouteTestStatus(second, "balanced")
	if err != nil {
		t.Fatal(err)
	}
	var report routeTestReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil || report.Profile != nil {
		t.Fatalf("status reused another private directory: %s, %v", raw, err)
	}
}

func TestManualRouteTestAndScansAreRejectedDuringActiveSession(t *testing.T) {
	proxyMu.Lock()
	old := activeProxy
	activeProxy = &proxySession{}
	proxyMu.Unlock()
	t.Cleanup(func() { proxyMu.Lock(); activeProxy = old; proxyMu.Unlock() })
	if err := StartRouteTest("balanced", "", "", t.TempDir(), false); err == nil {
		t.Fatal("manual test changed a live session")
	}

	if err := StartCDNScanToFile("cloudflare", 10, t.TempDir()); err == nil {
		t.Fatal("CDN scan ignored the connected-session guard")
	}
	if err := StartCDNScanForProvider("cloudflare", 10, 1); err == nil {
		t.Fatal("legacy CDN scan entrypoint ignored the connected-session guard")
	}
}

func TestManualRouteTestRejectsHeldStartupGate(t *testing.T) {
	proxyStartMu.Lock()
	defer proxyStartMu.Unlock()
	if err := StartRouteTest("balanced", "", "", t.TempDir(), false); err == nil {
		t.Fatal("manual test raced an unpublished startup")
	}
}

func TestRouteProbeTLSVerifiesExistingPublicCAWithoutItsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, androidFrontCADirectory)
	ca, err := front.Create(caDir, []string{"probe.youtube.com"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("probe.youtube.com")
	if err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(filepath.Join(caDir, front.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	// The diagnostic trust pool must use the existing public certificate alone.
	// The fixture retains the in-memory signer only to serve its local TLS leaf.
	if err := os.Remove(filepath.Join(caDir, front.KeyFile)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	upstream := smartproxy.Upstream{Name: "Front fixture", Takeover: func(context.Context, string, string, []byte) (smartproxy.Session, error) {
		t.Error("building diagnostic roots invoked the takeover")
		return nil, errors.New("unexpected takeover")
	}}
	for _, tc := range []struct {
		name     string
		upstream smartproxy.Upstream
		trusted  bool
	}{
		{"ordinary route cannot trust app CA", smartproxy.Upstream{Name: "ordinary"}, false},
		{"takeover trusts existing public CA", upstream, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := routeProbeTLS(tc.upstream, dir)
			if config == nil || config.InsecureSkipVerify || config.MinVersion < tls.VersionTLS12 {
				t.Fatalf("diagnostic TLS verification was weakened: %+v", config)
			}
			if tc.trusted && config.RootCAs == nil {
				t.Fatal("takeover diagnostic omitted its existing public CA roots")
			}
			config = config.Clone()
			config.ServerName = "probe.youtube.com"
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", server.Listener.Addr().String(), config)
			if err == nil {
				conn.Close()
			}
			if tc.trusted {
				if err != nil {
					t.Fatalf("existing CA did not verify the local takeover certificate: %v", err)
				}
			} else {
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Fatalf("ordinary route unexpectedly trusted the app CA, or failed for another reason: %v", err)
				}
			}
		})
	}
	// Trusting this CA must not bypass verification of the requested hostname.
	config := routeProbeTLS(upstream, dir)
	config.ServerName = "outside.example"
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", server.Listener.Addr().String(), config)
	if err == nil {
		conn.Close()
		t.Fatal("diagnostic accepted a certificate for the wrong hostname")
	}
	var hostname x509.HostnameError
	if !errors.As(err, &hostname) {
		t.Fatalf("wrong-host fixture did not reach hostname verification: %v", err)
	}
	certAfter, err := os.ReadFile(filepath.Join(caDir, front.CertFile))
	if err != nil || string(certAfter) != string(certBefore) {
		t.Fatalf("diagnostic changed the existing public CA: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(caDir, front.KeyFile)); !os.IsNotExist(err) {
		t.Fatalf("diagnostic regenerated or accessed an unexpected private key file: %v", err)
	}
}

func TestRouteProbeTLSDoesNotGenerateMissingOrRepairInvalidCA(t *testing.T) {
	upstream := smartproxy.Upstream{Name: "Front fixture", Takeover: func(context.Context, string, string, []byte) (smartproxy.Session, error) {
		t.Error("building diagnostic roots invoked the takeover")
		return nil, errors.New("unexpected takeover")
	}}
	for _, partial := range []bool{false, true} {
		name := "missing"
		if partial {
			name = "invalid public certificate"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			caDir := filepath.Join(dir, androidFrontCADirectory)
			const original = "invalid CA fixture; do not replace"
			if partial {
				if err := os.Mkdir(caDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(caDir, front.CertFile), []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
			}
			config := routeProbeTLS(upstream, dir)
			if config == nil || config.InsecureSkipVerify || config.RootCAs != nil {
				t.Fatalf("unavailable CA caused invented trust or bypassed verification: %+v", config)
			}
			if !partial {
				if _, err := os.Lstat(caDir); !os.IsNotExist(err) {
					t.Fatalf("diagnostic generated missing CA storage: %v", err)
				}
				return
			}
			cert, err := os.ReadFile(filepath.Join(caDir, front.CertFile))
			if err != nil || string(cert) != original {
				t.Fatalf("diagnostic repaired or replaced an invalid public CA: %v", err)
			}
			entries, err := os.ReadDir(caDir)
			if err != nil || len(entries) != 1 || entries[0].Name() != front.CertFile {
				t.Fatalf("diagnostic generated extra CA material: %v, %v", entries, err)
			}
		})
	}
}

func TestRouteProfileKeyChangesWithExistingPublicCA(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	for _, privateDir := range []string{dir, other} {
		if _, err := front.Create(filepath.Join(privateDir, androidFrontCADirectory), []string{"youtube.com"}); err != nil {
			t.Fatal(err)
		}
	}
	targets := []routeTarget{{ID: "youtube", Name: "YouTube", URL: "https://www.youtube.com/generate_204", Fronting: true}}
	config := smartproxy.Config{Upstreams: []smartproxy.Upstream{{Name: "Front fixture", Takeover: func(context.Context, string, string, []byte) (smartproxy.Session, error) {
		t.Error("computing a cache key invoked the takeover")
		return nil, errors.New("unexpected takeover")
	}}}}
	before := routeProfileKey(targets, config, dir)
	if routeProfileKey(targets, config, dir) != before {
		t.Fatal("unchanged public CA produced an unstable profile key")
	}
	plain := smartproxy.Config{Upstreams: []smartproxy.Upstream{{Name: "ordinary"}}}
	plainBefore := routeProfileKey(targets, plain, dir)
	// Simulate a different public trust anchor in this isolated fixture. No
	// production CA-generation/replacement API is invoked by the diagnostic.
	newPublic, err := os.ReadFile(filepath.Join(other, androidFrontCADirectory, front.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, androidFrontCADirectory, front.CertFile), newPublic, 0600); err != nil {
		t.Fatal(err)
	}
	if routeProfileKey(targets, config, dir) == before {
		t.Fatal("changed public CA reused a fronting profile measured under another trust anchor")
	}
	if routeProfileKey(targets, plain, dir) != plainBefore {
		t.Fatal("public CA change invalidated an unrelated ordinary-route profile")
	}
}

func TestBalancedProfileKeyChangesWhenUnderlyingAndroidNetworkChanges(t *testing.T) {
	routeNetworkMu.Lock()
	previous := routeNetworkToken
	routeNetworkMu.Unlock()
	t.Cleanup(func() {
		routeNetworkMu.Lock()
		routeNetworkToken = previous
		routeNetworkMu.Unlock()
	})
	targets := []routeTarget{{ID: "x", Name: "X", URL: "https://x.com/"}}
	config := smartproxy.Config{Upstreams: []smartproxy.Upstream{{Name: "Go direct"}}}
	if err := SetRouteNetworkToken("wifi:123456"); err != nil {
		t.Fatal(err)
	}
	first := routeProfileKey(targets, config, "")
	if err := SetRouteNetworkToken("cellular:456789"); err != nil {
		t.Fatal(err)
	}
	second := routeProfileKey(targets, config, "")
	if first == second {
		t.Fatal("cellular and Wi-Fi reused one cached route plan")
	}
	if err := SetRouteNetworkToken("wifi:123456"); err != nil || routeProfileKey(targets, config, "") != first {
		t.Fatal("same underlying network should preserve plan identity")
	}
	if err := SetRouteNetworkToken(""); err == nil {
		t.Fatal("empty network identity was accepted")
	}
}
