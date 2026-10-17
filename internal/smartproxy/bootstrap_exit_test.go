package smartproxy

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCarrierInIranCanCarryWindscribeButNeverProtectedAI(t *testing.T) {
	var hits atomic.Int32
	rules, _ := NewAIDomainRules("")
	checks := 0
	p, err := New(Config{ExitOnly: rules.Match, Upstreams: []Upstream{{Name: "WARP transport", Addr: fakeSocks(t, destination(t), true, &hits), Exit: true, AIEligible: false}}, VerifyCarrier: func(context.Context, Upstream) error { checks++; return nil }, OnEvent: func(e Event) {
		if e.OK || !e.TCPOnly {
			t.Error("carrier SOCKS acknowledgement advertised as application/VPN success")
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for range 2 {
		c, err := p.DialExitCarrier(ctx, "windscribe.com", "443")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if checks != 1 || hits.Load() != 2 {
		t.Fatal("carrier lease was not shared", checks, hits.Load())
	}
	before := hits.Load()
	for _, host := range []string{"chatgpt.com", "claude.ai", "gemini.google.com"} {
		if c, err := p.DialExitCarrier(ctx, host, "443"); err == nil {
			c.Close()
			t.Fatal("IR carrier allowed AI", host)
		}
	}
	if hits.Load() != before {
		t.Fatal("AI attempted the non-foreign carrier")
	}
}

func TestWindscribeForeignCarrierRefreshesExpiredLeaseEvenForNonAIHosts(t *testing.T) {
	rules, _ := NewAIDomainRules("")
	checks := 0
	p, err := New(Config{ExitOnly: rules.Match, Upstreams: []Upstream{{Name: "WARP", Addr: "127.0.0.1:1", Exit: true, AIEligible: true}}, VerifyExit: func(context.Context, Upstream) error { checks++; return errors.New("IR or unknown") }})
	if err != nil {
		t.Fatal(err)
	}
	p.ups[0].verifiedUntil.Store(0)
	if conn, err := p.DialVerifiedExit(context.Background(), "windscribe.com", "443"); err == nil {
		conn.Close()
		t.Fatal("expired egress allowed")
	} else if !strings.Contains(err.Error(), "IR or unknown") {
		t.Fatal("dial ran before exit refresh", err)
	}
	if checks != 1 {
		t.Fatal("lease was not refreshed", checks)
	}
}

func TestDeadWindscribeCarrierCanRecoverWithoutUnpinningAIIdentity(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{{Name: "old carrier", Exit: true, AIEligible: true}}})
	if err != nil {
		t.Fatal(err)
	}
	p.bootstrapPinned = "old carrier"
	p.aiPinned = "old carrier"
	p.Remove("old carrier")
	if p.bootstrapPinned != "" {
		t.Fatal("dead outer carrier blocked Windscribe recovery")
	}
	if p.aiPinned != "old carrier" {
		t.Fatal("AI identity silently rotated")
	}
}
