package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/wstunnel"
)

func TestProbeAndCDNOptionsFailBeforeNetworkWork(t *testing.T) {
	for _, args := range [][]string{
		{"-target", "152.233.50.178", "-rounds", "0"},
		{"-entry", "127.0.0.1"},
		{"-target", "152.233.50.178", "-transport", "invalid"},
		{"-target", "152.233.50.178", "-verify-vpn"},
	} {
		var out bytes.Buffer
		if code := runWindscribeTestContext(context.Background(), args, plainTerm(&out)); code != 2 {
			t.Fatalf("invalid options %v returned %d", args, code)
		}
	}
	for _, args := range [][]string{{"-provider", "unknown"}, {"-windscribe-cdn", "https://bad.example"}, {"-sni", "python.org"}, {"-provider", "google", "-windscribe-cdn", "own.example"}} {
		if code := runQuickScanContext(context.Background(), args); code != 2 {
			t.Fatalf("invalid CDN options %v returned %d", args, code)
		}
	}
}

func TestCarrierProbeSeparatesTCPAndTLSFailures(t *testing.T) {
	blocked := errors.New("blocked")
	cfg := wstunnel.Config{Addr: "192.0.2.1:443", Host: "192.0.2.1", Timeout: time.Second, Dial: func(context.Context, string) (net.Conn, error) { return nil, blocked }}
	r := probeWSCarrier(context.Background(), "wstunnel", cfg)
	if r.tcp || r.tls || r.websocket || r.stage != "tcp" {
		t.Fatalf("TCP failure counted as later success: %+v", r)
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	cfg.Addr, cfg.Host, cfg.Dial = srv.Listener.Addr().String(), "test.example", directDial
	cfg.VerifyPeer = func([]*x509.Certificate) error { return errors.New("untrusted test peer") }
	r = probeWSCarrier(context.Background(), "wstunnel", cfg)
	if !r.tcp || r.tls || r.websocket || r.stage != "tls" {
		t.Fatalf("TLS rejection counted as carrier success: %+v", r)
	}
}

func TestCarrierProbeRequiresRealUpgradeAndSendsNoVPNPayload(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprint(upgrade), func(t *testing.T) {
			received := make(chan byte, 1)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !upgrade {
					http.Error(w, "not a websocket", http.StatusBadGateway)
					return
				}
				c, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
				_ = rw.Flush()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				var header [2]byte
				if _, err := io.ReadFull(rw, header[:]); err == nil {
					received <- header[0] & 15
				}
			}))
			defer srv.Close()
			cfg := wstunnel.Config{Addr: srv.Listener.Addr().String(), Host: "test.example", SNI: "python.org", Dial: directDial, Timeout: time.Second}
			r := probeWSCarrier(context.Background(), "wstunnel", cfg)
			if !r.tcp || !r.tls || r.websocket != upgrade {
				t.Fatalf("wrong transport boundary: %+v", r)
			}
			if !upgrade && r.stage != "websocket" {
				t.Fatalf("HTTP failure not identified: %+v", r)
			}
			if upgrade {
				select {
				case op := <-received:
					if op != 8 {
						t.Fatalf("probe sent application/VPN data opcode %d", op)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("probe did not close its connection")
				}
			}
		})
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	r := probeWSCarrier(context.Background(), "stealth", wstunnel.Config{Addr: srv.Listener.Addr().String(), Dial: directDial, Timeout: time.Second})
	if !r.tcp || !r.tls || r.websocket {
		t.Fatalf("Stealth must prove TLS only: %+v", r)
	}
}

func TestProbeSNIInputIsBoundedAndDeduplicated(t *testing.T) {
	names, err := parseProbeSNIs("Python.org,none,python.org,pypi.org")
	if err != nil || !reflect.DeepEqual(names, []string{"python.org", "", "pypi.org"}) {
		t.Fatalf("names=%v error=%v", names, err)
	}
	for _, raw := range []string{"", "127.0.0.1", "https://python.org", "python.org\r\nx: y", "bad.$(id).org", "foo..org", "a.-bad.org"} {
		if _, err := parseProbeSNIs(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	var tooMany []string
	for i := 0; i < 13; i++ {
		tooMany = append(tooMany, fmt.Sprintf("s%d.example", i))
	}
	if _, err := parseProbeSNIs(strings.Join(tooMany, ",")); err == nil {
		t.Fatal("unbounded SNI list accepted")
	}
}

func TestProbeLocationKeepsExactProviderNode(t *testing.T) {
	c := newWSNodeCatalog()
	if err := c.replace("global", []byte(globalNodeFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	n, eps, err := selectWSProbeNode(c, "Example - A")
	if err != nil || n.TCP != "203.0.113.100" || len(eps) != 2 {
		t.Fatalf("wrong location: %+v %v %v", n, eps, err)
	}
	regional := strings.ReplaceAll(regionalNodeFixture, "203.0.113.100", "203.0.113.101")
	regional = strings.ReplaceAll(regional, "Example - A", "Example - B")
	if err := c.replace("regional", []byte(regional), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectWSProbeNode(c, "Example"); err == nil {
		t.Fatal("ambiguous locations silently substituted")
	}
	if _, _, err := selectWSProbeNode(c, "203.0.113.102"); err == nil {
		t.Fatal("invented an unknown node")
	}
	if err := c.replace("global", []byte(globalNodeFixture), time.Now().Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectWSProbeNode(c, "203.0.113.100"); err == nil {
		t.Fatal("used expired server mapping")
	}
}

func TestVPNDataProofRequiresStableReportedAndMeasuredExit(t *testing.T) {
	before := wsCLIStatus{state: windscribeConnected, protocol: "TCP:443", ip: "152.233.50.185"}
	if err := validateWSDataResult(before, before, tracePublicIP("ip=152.233.50.185\nloc=US")); err != nil {
		t.Fatal(err)
	}
	for _, measured := range []string{"", "10.0.0.1", "152.233.50.177"} {
		if err := validateWSDataResult(before, before, measured); err == nil {
			t.Fatalf("accepted unverified exit %q", measured)
		}
	}
	for _, after := range []wsCLIStatus{
		{state: windscribeDisconnected, protocol: before.protocol, ip: before.ip},
		{state: windscribeConnected, protocol: before.protocol, ip: "152.233.50.186"},
		{state: windscribeConnected, protocol: "WireGuard:443", ip: before.ip},
		{state: windscribeConnected, protocol: before.protocol, ip: before.ip, err: errors.New("CLI unavailable")},
	} {
		if err := validateWSDataResult(before, after, before.ip); err == nil {
			t.Fatalf("accepted unstable/unavailable CLI status: %+v", after)
		}
	}
}
