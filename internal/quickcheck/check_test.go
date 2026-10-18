package quickcheck

import (
	"context"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeIdentifiesItselfToServicesThatRejectGenericGoClients(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.UserAgent()
		if !strings.Contains(ua, "KTest") || !strings.Contains(ua, "https://github.com/Nishef1/ktest") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	r := checkTarget(context.Background(), srv.Client(), Target{"identified probe", srv.URL, http.MethodHead, 204})
	if !r.Success || r.Status != 204 {
		t.Fatalf("probe was refused because it did not identify itself: %+v", r)
	}
}

func TestClosedProxyFailsRatherThanClaimingAccess(t *testing.T) {
	// A closed loopback SOCKS listener must never produce an apparent success.
	results := Run(context.Background(), 1, 500*time.Millisecond)
	if len(results) != len(Targets()) {
		t.Fatalf("got %d results", len(results))
	}
	for _, r := range results {
		if r.Success || r.Detail == "" {
			t.Fatalf("false positive: %+v", r)
		}
	}
}

func TestStartupTargetsNeverContactAIOrFollowAccountRedirects(t *testing.T) {
	rules, _ := smartproxy.NewAIDomainRules("")
	for _, target := range Targets() {
		u, err := url.Parse(target.URL)
		if err != nil || u.Scheme != "https" || rules.Match(u.Hostname()) {
			t.Fatalf("unsafe direct-control target: %+v", target)
		}
		if target.Method != http.MethodHead && target.Want != 204 {
			t.Fatalf("large-page probe: %+v", target)
		}
	}
	var followed atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Error("probe used client cookies")
		}
		if r.URL.Path == "/account" {
			followed.Add(1)
		}
		w.Header().Set("Location", "/account")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	u, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "must-not-be-sent"}})
	results := runTargets(context.Background(), client, []Target{{"redirect", srv.URL, http.MethodHead, 0}}, time.Second)
	if len(results) != 1 || results[0].Status != 302 || followed.Load() != 0 {
		t.Fatalf("followed account redirect: %+v", results)
	}
}

func TestRepresentativeChecksShareBudgetAndLimitConcurrency(t *testing.T) {
	var active, peak, hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		hits.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("probe sent account credentials")
		}
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	var targets []Target
	for _, path := range []string{"/slow", "/a", "/b", "/c", "/d"} {
		targets = append(targets, Target{path, srv.URL + path, http.MethodHead, 204})
	}
	began := time.Now()
	results := runTargets(context.Background(), srv.Client(), targets, 300*time.Millisecond)
	if time.Since(began) > time.Second || peak.Load() > 3 || hits.Load() != 5 {
		t.Fatalf("elapsed=%s peak=%d hits=%d", time.Since(began), peak.Load(), hits.Load())
	}
	if results[0].Success {
		t.Fatal("silent target passed")
	}
	for _, r := range results[1:] {
		if !r.Success || !r.Reachable {
			t.Fatalf("slow target blocked a fast sibling: %+v", r)
		}
	}
}

func TestServiceRefusalAndUncheckedControlAreNotBypassProof(t *testing.T) {
	a := Compare([]Result{{Target: "restricted", Reachable: true, Status: 403}, {Target: "unmeasured-control", Success: true}}, []Result{{Target: "unmeasured-control", Skipped: true}})
	if a[0].Kind != "service_response" || a[1].Kind != "baseline_unknown" {
		t.Fatal(a)
	}
}

func TestCancelledProbeProducesNoSuccess(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	results := Run(ctx, 10808, time.Second)
	for _, r := range results {
		if r.Success {
			t.Fatalf("cancelled probe succeeded: %+v", r)
		}
	}
}

func TestTikTokAndTelegramWebAreDistinctOptInTargets(t *testing.T) {
	seen := make(map[string]Target)
	for _, target := range Targets() {
		if _, duplicate := seen[target.Name]; duplicate {
			t.Fatalf("duplicate quickcheck target: %s", target.Name)
		}
		seen[target.Name] = target
	}
	for name, site := range map[string]string{
		"TikTok": "www.tiktok.com",
		"Telegram": "telegram.org",
		"Telegram Web": "web.telegram.org",
	} {
		target, ok := seen[name]
		if !ok {
			t.Fatalf("missing opt-in target %s", name)
		}
		u, err := url.Parse(target.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() != site || target.Method != http.MethodHead {
			t.Fatalf("unexpected test target %s: %+v", name, target)
		}
	}
}
