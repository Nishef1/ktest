package smartproxy

import "testing"

func TestOrderSkipsDirectRoutesOfTheWrongAddressFamily(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "dual"}, {Name: "v6", Network: "tcp6"}, {Name: "v4", Network: "tcp4"},
		{Name: "socks6", Network: "tcp6", Addr: "127.0.0.1:1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	names := func(host string) map[string]bool {
		out := map[string]bool{}
		for _, u := range p.order(host, "443") {
			out[u.Name] = true
		}
		return out
	}
	if got := names("1.1.1.1"); got["v6"] || !got["dual"] || !got["v4"] || !got["socks6"] {
		t.Fatalf("IPv4 literal routes: %v", got)
	}
	if got := names("2606:4700::1111"); got["v4"] || !got["v6"] || !got["dual"] {
		t.Fatalf("IPv6 literal routes: %v", got)
	}
	if got := names("example.com"); len(got) != 4 {
		t.Fatalf("hostname must keep every family: %v", got)
	}
}
