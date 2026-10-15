package systemtun

import (
	"encoding/json"
	"testing"
)

func TestSafePolicyConfig(t *testing.T) {
	buf, err := BuildConfig(10808, "Ethernet")
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Inbounds []struct {
			AutoRoute   bool `json:"auto_route"`
			StrictRoute bool `json:"strict_route"`
			Stack       string `json:"stack"`
		} `json:"inbounds"`
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(buf, &root); err != nil {
		t.Fatal(err)
	}
	if len(root.Inbounds) != 1 || !root.Inbounds[0].AutoRoute || !root.Inbounds[0].StrictRoute || root.Inbounds[0].Stack != "gvisor" {
		t.Fatalf("unsafe tun config: %s", buf)
	}
	if len(root.Route.Rules) < 5 || root.Route.Final != "socks" {
		t.Fatalf("missing route safeguards: %s", buf)
	}
	if root.Route.Rules[1]["action"] != "reject" || root.Route.Rules[3]["outbound"] != "physical" {
		t.Fatalf("missing loop guard or physical outbound: %s", buf)
	}
}
func TestMissingInterfaceRejected(t *testing.T) {
	if _, err := BuildConfig(10808, ""); err == nil {
		t.Fatal("must require an explicit physical interface")
	}
}
