package smartproxy

import "testing"

func TestExitRequiredUsesCarrierButNeverForAI(t *testing.T) {
	p, err := New(Config{
		Upstreams:    []Upstream{{Name: "direct"}, {Name: "carrier", Addr: "127.0.0.1:9", Exit: true}},
		ExitOnly:     func(host string) bool { return host == "chatgpt.com" },
		ExitRequired: func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	names := func(host string) []string {
		var out []string
		for _, u := range p.order(host, "443") {
			out = append(out, u.Name)
		}
		return out
	}
	if got := names("example.org"); len(got) != 1 || got[0] != "carrier" {
		t.Fatalf("ordinary site routes = %v, want only the carrier", got)
	}
	if got := names("chatgpt.com"); len(got) != 0 {
		t.Fatalf("AI site routes = %v, want none without a foreign exit", got)
	}
	if !p.HasWorkingExit() || p.HasVerifiedExit() {
		t.Fatal("an Iran-located carrier is working but must not count as a foreign exit")
	}
}
