package mobilebridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestEndpointCheckTrustsOnlyItsActiveFrontingCA(t *testing.T) {
	dir := t.TempDir()
	var hosts []string
	for _, target := range quickcheck.Targets() {
		u, _ := url.Parse(target.URL)
		hosts = append(hosts, u.Hostname())
	}
	ca, err := front.Create(filepath.Join(dir, androidFrontCADirectory), hosts)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return ca.Leaf(hello.ServerName)
	}}
	server.StartTLS()
	defer server.Close()
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "system roots", true: "active fronting"}[enabled], func(t *testing.T) {
			proxy, err := smartproxy.New(smartproxy.Config{
				Upstreams: []smartproxy.Upstream{{Name: "local TLS fixture", Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
				}}},
				Resolve: func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			core, err := connectionsession.Start(context.Background(), proxy, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer core.Stop()
			proxyMu.Lock()
			previous := activeProxy
			activeProxy = &proxySession{socks: core.SOCKS, frontDir: dir}
			if enabled {
				activeProxy.fronter = front.New(front.Config{CA: ca, Families: front.DefaultFamilies()})
			}
			proxyMu.Unlock()
			defer func() { proxyMu.Lock(); activeProxy = previous; proxyMu.Unlock() }()
			raw, err := CheckRoute()
			if err != nil {
				t.Fatal(err)
			}
			var report routeCheck
			if err := json.Unmarshal([]byte(raw), &report); err != nil {
				t.Fatal(err)
			}
			want := 0
			if enabled {
				want = len(quickcheck.Targets())
			}
			if report.Verified != want || report.Attempted != len(quickcheck.Targets()) {
				t.Fatalf("unexpected certificate trust: %+v", report)
			}
			if enabled && !strings.Contains(report.Note, "other Android apps may reject") {
				t.Fatal("internal CA trust was presented as proof for other apps")
			}
		})
	}
}
