package revive

import (
	"encoding/json"
	"testing"
)

func TestDNSBootstrapPreservesOriginalFallback(t *testing.T) {
	source := []byte("[{\"remarks\":\"Serverless-v52-fragB\",\"dns\":{\"servers\":[{\"address\":\"fakedns\",\"domains\":[\"domain:ir\"]},{\"tag\":\"no-filter-dns\",\"address\":\"https://cloudflare-dns.com/dns-query\",\"timeoutMs\":12000,\"finalQuery\":true},{\"tag\":\"domestic-dns\",\"address\":\"localhost\",\"domains\":[\"domain:ir\"],\"finalQuery\":true}]},\"inbounds\":[{\"protocol\":\"mixed\"}]}]")
	out, err := SelectProfile(source, "B")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	var dns struct {
		Servers []map[string]any
	}
	if err := json.Unmarshal(root["dns"], &dns); err != nil {
		t.Fatal(err)
	}
	ss := dns.Servers
	if len(ss) != 5 || ss[1]["address"] != "localhost" ||
		ss[2]["address"] != "https://dns.google/dns-query" ||
		ss[2]["finalQuery"] != false ||
		ss[3]["address"] != "https://cloudflare-dns.com/dns-query" ||
		ss[3]["timeoutMs"] != float64(4500) {
		t.Fatalf("invalid DNS chain: %+v", ss)
	}
	for _, d := range ss[1]["domains"].([]any) {
		if d == "domain:youtube.com" {
			t.Fatal("do not route YouTube to the local resolver by default")
		}
	}
}

func TestMissingDNSRemainsMissing(t *testing.T) {
	out, err := SelectProfile([]byte("{\"remarks\":\"fragB\",\"inbounds\":[{\"protocol\":\"mixed\"}]}"), "B")
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(out, &data); err != nil {
		t.Fatal(err)
	}
	if len(data["dns"]) != 0 {
		t.Fatal("DNS invented for an unrelated config")
	}
}
