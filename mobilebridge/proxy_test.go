package mobilebridge

import (
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestBalancedConnectDoesNotRequireOrProbeCalibrationTargets(t *testing.T) {
	StopProxy()
	defer StopProxy()
	dir := t.TempDir()
	if err := writeRouteTargets(dir, nil); err != nil {
		t.Fatal(err)
	}
	data, err := startProxyWithNativeCores("balanced", "", nil, "", "", dir)
	if err != nil {
		t.Fatalf("ordinary connection was blocked by diagnostic targets: %v", err)
	}
	var report proxyReport
	if err := json.Unmarshal([]byte(data), &report); err != nil || !report.Running || report.TCPAttempts != 0 {
		t.Fatalf("connect tested or froze routes: %s, %v", data, err)
	}
}

func TestProxyStartsAndStopsWithRealLoopbackListeners(t *testing.T) {
	defer StopProxy()
	if _, err := StartProxy("tor"); err == nil {
		t.Fatal("unsupported mode should never be reported connected")
	}
	data, err := StartProxy("balanced")
	if err != nil {
		t.Fatal(err)
	}
	var status proxyReport
	if err := json.Unmarshal([]byte(data), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Running || status.Coverage != "proxy" || status.Mode != "balanced" {
		t.Fatalf("unexpected status: %+v", status)
	}
	for _, addr := range []string{status.Socks, status.HTTP} {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("listener not loopback: %q (%v)", addr, err)
		}
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	if _, err := StartProxy("fast"); err == nil {
		t.Fatal("mode change without disconnect must fail")
	}
	StopProxy()
	if got := ProxyStatus(); !json.Valid([]byte(got)) {
		t.Fatalf("invalid status: %s", got)
	}
	if _, err := StartProxy("fast"); err != nil {
		t.Fatal(err)
	}
}

func TestStopCancelsUpstreamVerificationBeforeItCanPublishSession(t *testing.T) {
	StopProxy()
	defer StopProxy()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		close(accepted)
		_, _ = io.Copy(io.Discard, client) // stall SOCKS greeting until canceled
	}()
	finished := make(chan error, 1)
	go func() { _, err := StartProxyWithUpstream("aether", listener.Addr().String()); finished <- err }()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream verification did not start")
	}
	var status proxyReport
	if err := json.Unmarshal([]byte(ProxyStatus()), &status); err != nil {
		t.Fatal(err)
	}
	if status.Running || status.Phase != "verifying_upstream" {
		t.Fatalf("incorrect startup state: %+v", status)
	}
	StopProxy()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled start succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StopProxy did not cancel blocked SOCKS verification")
	}
	if _, err := StartProxy("fast"); err != nil {
		t.Fatalf("canceled start prevented reconnect: %v", err)
	}
}

func TestServerlessDNSUsesOnlyPinnedLoopbackSOCKS(t *testing.T) {
	original, custom, err := mobileDNSRoute("balanced", "", nil, "8.8.8.8")
	if err != nil || original != "" || custom != "8.8.8.8" {
		t.Fatalf("changed ordinary mode DNS settings: %q %q %v", original, custom, err)
	}
	if _, _, err := mobileDNSRoute("serverless", "", nil, "8.8.8.8"); err == nil {
		t.Fatal("Serverless accepted missing local core")
	}
	good := &localCoreSet{upstreams: []smartproxy.Upstream{{Addr: "127.0.0.1:19001"}}}
	original, custom, err = mobileDNSRoute("serverless", "", good, "8.8.8.8")
	if err != nil || original != "127.0.0.1:19001" || custom != "" {
		t.Fatalf("Serverless bypassed its pinned local DNS route: %q %q %v", original, custom, err)
	}
	bad := &localCoreSet{upstreams: []smartproxy.Upstream{{Addr: "8.8.8.8:10808"}}}
	if _, _, err := mobileDNSRoute("serverless", "", bad, ""); err == nil {
		t.Fatal("Serverless DNS allowed a remote SOCKS endpoint")
	}
}
