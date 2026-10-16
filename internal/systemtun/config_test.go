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
			AutoRoute   bool   `json:"auto_route"`
			StrictRoute bool   `json:"strict_route"`
			Stack       string `json:"stack"`
		} `json:"inbounds"`
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
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

func TestSystemConfigKeepsOwnProcessesOutOfTheTunnelAndMapsNamesBack(t *testing.T) {
	buf, err := BuildSystemConfig(Options{SocksPort: 10800, PhysicalNIC: "Ethernet", DirectProcesses: []string{"ktest.exe", "xray.exe"}})
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Final   string           `json:"final"`
		} `json:"dns"`
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(buf, &root); err != nil {
		t.Fatal(err)
	}
	// The exemption must come before DNS hijacking, or the proxy's own name
	// lookups would be answered with fake addresses and loop.
	if root.Route.Rules[0]["outbound"] != "physical" || root.Route.Rules[0]["process_name"] == nil {
		t.Fatalf("own processes must be the first rule: %s", buf)
	}
	hijack, block, private := -1, -1, -1
	for i, r := range root.Route.Rules {
		if r["action"] == "hijack-dns" {
			hijack = i
		}
		if cidr, ok := r["ip_cidr"].([]any); ok && len(cidr) == 1 && cidr[0] == "10.10.34.0/24" {
			block = i
		}
		if r["ip_is_private"] == true {
			private = i
		}
	}
	if hijack < 1 {
		t.Fatalf("DNS hijack missing or before the exemption: %s", buf)
	}
	// The block-page range must reach the proxy before the private-range rule
	// sends it to the LAN, where it would just show the block page.
	if block < 0 || private < 0 || block > private {
		t.Fatalf("block-page range must precede the private rule (block %d, private %d)", block, private)
	}
	if root.Route.Final != "ktest" || root.DNS.Final != "local" {
		t.Fatalf("final routes: %s", buf)
	}
	fake := false
	for _, s := range root.DNS.Servers {
		fake = fake || s["type"] == "fakeip"
	}
	if !fake {
		t.Fatalf("no fake-IP server: %s", buf)
	}
}

func TestSystemConfigRefusesToLoop(t *testing.T) {
	if _, err := BuildSystemConfig(Options{SocksPort: 10800, PhysicalNIC: "Ethernet"}); err == nil {
		t.Fatal("a tunnel without exempt processes would loop")
	}
	if _, err := BuildSystemConfig(Options{SocksPort: 0, PhysicalNIC: "Ethernet", DirectProcesses: []string{"x"}}); err == nil {
		t.Fatal("bad port accepted")
	}
}
