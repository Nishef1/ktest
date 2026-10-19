package smartproxy

import (
	"context"
	"net"
	"testing"
)

func TestLocalCarrierCannotUseItsOwnForeignExitOrTriggerDiscovery(t *testing.T) {
	p, _ := New(Config{Upstreams: []Upstream{{Name: "plain"}, {Name: "ByeDPI", Addr: "127.0.0.1:10001", LocalBypass: true}, {Name: "imported Xray", Addr: "127.0.0.1:10002"}, {Name: "exit", Addr: "127.0.0.1:10003", Exit: true, AIEligible: true}, {Name: "untrusted dial", Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("foreign custom dial used")
		return nil, nil
	}}, {Name: "takeover", Takeover: func(context.Context, string, string, []byte) (Session, error) { return nil, nil }}},
		ExitOnly: func(string) bool { return true }, EnsureExit: func(context.Context) error { t.Fatal("recursive discovery"); return nil }})
	cfg := p.LocalCarrierConfig()
	if cfg.EnsureExit != nil || cfg.VerifyExit != nil || cfg.OnEvent != nil || !cfg.RejectExits || !cfg.RecoverIPHostSNI {
		t.Fatal("carrier inherited foreign discovery or application telemetry")
	}
	if len(cfg.Upstreams) != 2 || cfg.Upstreams[0].Name != "plain" || cfg.Upstreams[1].Name != "ByeDPI" {
		t.Fatalf("carrier included nonlocal paths: %+v", cfg.Upstreams)
	}
	if cfg.ExitOnly("api.cloudflareclient.com") || !cfg.ExitOnly("chatgpt.com") {
		t.Fatal("strict app policy blocked transport bootstrap or leaked protected traffic")
	}
	carrier, _ := New(cfg)
	if err := carrier.Add(Upstream{Name: "late foreign exit", Exit: true}); err == nil {
		t.Fatal("private carrier accepted its own foreign exit")
	}
}
