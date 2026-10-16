package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// frontCheck is one family tried through its fronts.
type frontCheck struct {
	family  string
	site    string
	results []front.ProbeResult
}

func (c frontCheck) working() int {
	n := 0
	for _, r := range c.results {
		if r.Err == nil {
			n++
		}
	}
	return n
}

// probeFronts asks every family, through each of its fronts, for one page. It
// needs no certificate on this machine: the probe speaks to the edge directly.
func probeFronts(ctx context.Context) []frontCheck {
	resolve := smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: smartproxy.NewDoH([]smartproxy.DoHEndpoint{echDoHEndpoint()}, nil, nil)})
	f := front.New(front.Config{Resolve: resolve, DialTimeout: 6 * time.Second})
	sites := []struct{ site, path string }{
		{"www.youtube.com", "/generate_204"},
		{"www.instagram.com", "/"},
		{"www.reddit.com", "/"},
		{"x.com", "/"},
	}
	out := make([]frontCheck, len(sites))
	var wg sync.WaitGroup
	for i, s := range sites {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := f.Probe(ctx, s.site, s.path)
			fam := ""
			if len(res) > 0 {
				fam = res[0].Family
			}
			out[i] = frontCheck{family: fam, site: s.site, results: res}
		}()
	}
	wg.Wait()
	return out
}

// printFronts renders the probe and the state of the local CA.
func printFronts(u *term, checks []frontCheck) {
	u.Println("")
	u.Println("  " + u.Bold("Domain fronting") + u.Dim(" → the page is requested under a different server name; no certificate needed to test"))
	anyOK := false
	for _, c := range checks {
		n := c.working()
		k := toneOK
		switch {
		case n == 0:
			k = toneFail
		case n < len(c.results):
			k = toneWarn
		}
		if n > 0 {
			anyOK = true
		}
		u.Line(k, "%-26s %d of %d fronts answer", c.family+" ("+c.site+")", n, len(c.results))
		for _, r := range c.results {
			if r.Err == nil {
				u.Note("%s  HTTP %d  %s", r.Front, r.Status, shortDur(r.Took))
			} else {
				u.Note("%s  %s", r.Front, frontErr(r.Err))
			}
		}
	}
	ca, trusted := loadFrontCA()
	switch {
	case ca != nil && trusted:
		u.Line(toneOK, "%-26s trusted by this system; Connect uses fronting", "ktest CA")
	case ca != nil:
		u.Line(toneWarn, "%-26s created but not trusted yet (`ktest ca -install`)", "ktest CA")
	case anyOK:
		u.Line(toneInfo, "%-26s not created. Fronting works here: `ktest ca -install` enables it", "ktest CA")
	default:
		u.Line(toneInfo, "%-26s not created (no front answered, so it would not help on this network)", "ktest CA")
	}
}

// frontErr names the stage that failed, which is what tells a blocked address
// (tcp), a filtered server name (handshake) and poisoned DNS (address) apart.
func frontErr(err error) string {
	msg := err.Error()
	stage := ""
	switch {
	case strings.HasPrefix(msg, "tcp connect"):
		stage = "tcp: "
	case strings.HasPrefix(msg, "handshake"):
		stage = "TLS handshake: "
	case strings.HasPrefix(msg, "address"):
		stage = "address: "
	}
	return stage + shortErr(err)
}

// echDoHEndpoint is Cloudflare's DNS-over-HTTPS service reached through
// Encrypted Client Hello from ktest itself.
func echDoHEndpoint() smartproxy.DoHEndpoint {
	f := front.New(front.Config{})
	return smartproxy.DoHEndpoint{
		URL: "https://cloudflare-dns.com/dns-query", Accept: "application/dns-json",
		DialTLS: func(ctx context.Context) (net.Conn, error) {
			return f.DialECH(ctx, "cloudflare-dns.com", []string{"http/1.1"})
		},
	}
}

// printECHDoH shows whether encrypted DNS works through ECH where the plain
// resolvers are filtered, which is what gives every path real addresses.
func printECHDoH(ctx context.Context, u *term) {
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	began := time.Now()
	ips, err := smartproxy.NewDoH([]smartproxy.DoHEndpoint{echDoHEndpoint()}, nil, nil)(cctx, "www.youtube.com")
	if err != nil {
		u.Line(toneWarn, "%-26s no answer (%s)", "Encrypted DNS over ECH", frontErr(err))
		return
	}
	u.Line(toneOK, "%-26s www.youtube.com -> %s  %s", "Encrypted DNS over ECH", ips[0], shortDur(time.Since(began)))
}
