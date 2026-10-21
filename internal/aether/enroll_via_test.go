package aether

import (
	"context"
	"net"
	"testing"
)

func TestParseEnrollmentProxyAcceptsOnlyLocalSOCKS(t *testing.T) {
	for raw, want := range map[string]string{
		"127.0.0.1:10808":          "socks5://127.0.0.1:10808",
		" socks5://127.0.0.1:2080": "socks5://127.0.0.1:2080",
		"socks5h://localhost:1080": "socks5://127.0.0.1:1080",
		"[::1]:1080":               "socks5://[::1]:1080",
		"http://127.0.0.1:10809/":  "http://127.0.0.1:10809",
	} {
		if got, err := ParseEnrollmentProxy(raw); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "10808", "https://127.0.0.1:10809", "192.168.1.5:1080", "example.com:1080", "127.0.0.1:0", "127.0.0.1:x"} {
		if got, err := ParseEnrollmentProxy(raw); err == nil {
			t.Errorf("%q accepted as %q", raw, got)
		}
	}
}

func TestViaProxyRouteRequiresAListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	route, err := ViaProxyRoute(context.Background(), addr)
	if err != nil || len(route.Args) != 2 || route.Args[1] != "socks5://"+addr {
		t.Fatalf("route = %+v, %v", route, err)
	}
	l.Close()
	if _, err := ViaProxyRoute(context.Background(), addr); err == nil {
		t.Fatal("a closed port was accepted as a proxy")
	}
}
