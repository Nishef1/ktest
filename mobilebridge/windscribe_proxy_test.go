package mobilebridge

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/connectionpolicy"
	"github.com/Nishef1/ktest/internal/coreprocess"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// fakeWindscribeCores starts real loopback children from the test helper in
// place of the hash-pinned packaged ByeDPI.
func fakeWindscribeCores(t *testing.T) {
	t.Helper()
	t.Setenv("KTEST_LOCAL_CORE_HELPER", "1")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launchLocalCores = func(ctx context.Context, _ string, _ bool) (*localCoreSet, error) {
		return startLocalCores(ctx, bin, []byedpi.Strategy{{Label: "byedpi one"}, {Label: "byedpi two"}})
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	saved := windscribeHTTPAddress
	windscribeHTTPAddress = address
	t.Cleanup(func() {
		launchLocalCores = launchAndroidLocalCores
		windscribeHTTPAddress = saved
	})
}

func TestWindscribeProxyStartsLocalOnlyWithFixedHTTPListener(t *testing.T) {
	StopProxy()
	defer StopProxy()
	fakeWindscribeCores(t)
	data, err := StartAndroidWindscribeProxy(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var report proxyReport
	if err := json.Unmarshal([]byte(data), &report); err != nil || !report.Running || report.Mode != "windscribe" {
		t.Fatalf("Windscribe proxy did not start: %s (%v)", data, err)
	}
	if report.HTTP != WindscribeHTTPProxy() {
		t.Fatalf("HTTP listener %q moved from the profile's fixed %q", report.HTTP, WindscribeHTTPProxy())
	}
	if report.Upstream != "" || report.Native || report.Fronting || report.XrayReady {
		t.Fatalf("Windscribe gained an exit, fronting or Xray: %+v", report)
	}
	conn, err := net.Dial("tcp", report.HTTP)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	proxyMu.Lock()
	methods := activeProxy.core.Proxy.WindscribeMethods()
	proxyMu.Unlock()
	want := len(smartproxy.DesyncUpstreams()) + 2
	if len(methods) != want {
		t.Fatalf("expected %d local methods, got %d", want, len(methods))
	}
	for _, m := range methods {
		if strings.HasPrefix(m.Name, "plain") {
			t.Fatalf("plain route offered: %s", m.Name)
		}
	}
	if err := AttachVpnTun(0); err == nil {
		t.Fatal("Windscribe mode attached the KTest VPN")
	}
	StopProxy()
	if coreprocess.Count() != 0 {
		t.Fatal("disconnect left ByeDPI children")
	}
}

func TestWindscribeProxyRejectsExitsFrontingAndMissingCores(t *testing.T) {
	StopProxy()
	defer StopProxy()
	fakeWindscribeCores(t)
	dir := t.TempDir()
	cases := map[string]func() (string, error){
		"exit": func() (string, error) { return startProxy("windscribe", "127.0.0.1:1080", nil, dir) },
		"native": func() (string, error) {
			return startProxy("windscribe", "", &nativeOptions{}, dir)
		},
		"fronting": func() (string, error) { return startProxyWithFronting("windscribe", "", nil, dir, dir) },
		"no cores": func() (string, error) { return StartProxy("windscribe") },
		"no dir":   func() (string, error) { return StartAndroidWindscribeProxy("") },
	}
	for name, start := range cases {
		if _, err := start(); err == nil {
			t.Fatalf("%s: Windscribe mode started", name)
		}
		var report proxyReport
		if err := json.Unmarshal([]byte(ProxyStatus()), &report); err != nil || report.Running {
			t.Fatalf("%s: rejected start published a connection: %+v (%v)", name, report, err)
		}
	}
	if coreprocess.Count() != 0 {
		t.Fatal("rejected start left ByeDPI children")
	}
}

func TestWindscribePolicyRejectsPlainAndExitRoutes(t *testing.T) {
	for name, u := range map[string]smartproxy.Upstream{
		"plain": smartproxy.PlainUpstreams()[0],
		"exit":  {Name: "exit", Addr: "127.0.0.1:1080", Exit: true, AIEligible: true},
		"relay": {Name: "relay", Addr: "127.0.0.1:1081"},
	} {
		cfg := smartproxy.Config{Upstreams: append(smartproxy.DesyncUpstreams(), u)}
		connectionpolicy.Configure("windscribe", &cfg, nil)
		if _, err := smartproxy.New(cfg); err == nil {
			t.Fatalf("Windscribe policy accepted a %s route", name)
		}
	}
}
