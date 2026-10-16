package main

import (
	"context"
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
	resolve := smartproxy.NewTrusted(smartproxy.TrustedOptions{})
	f := front.New(front.Config{Resolve: resolve, DialTimeout: 6 * time.Second})
	sites := []struct{ site, path string }{
		{"www.youtube.com", "/generate_204"},
		{"www.instagram.com", "/"},
		{"www.reddit.com", "/"},
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
				u.Note("%s  %s", r.Front, shortErr(r.Err))
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
