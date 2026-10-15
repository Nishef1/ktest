package revive

import (
	"encoding/json"
	"strings"
	"testing"
)

const sample = `[
{"remarks":"Serverless-v52-fragA","inbounds":[{"protocol":"mixed","port":10808}],"outbounds":[{"protocol":"freedom"}]},
{"remarks":"Serverless-v52-fragB","inbounds":[{"protocol":"mixed","port":9999,"listen":"0.0.0.0"}],"outbounds":[{"protocol":"freedom"}]}
]`

func TestSelectBOfflineAndLoopback(t *testing.T) {
	b, err := SelectProfile([]byte(sample), "B")
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Remarks  string `json:"remarks"`
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root.Remarks != "Serverless-v52-fragB" || len(root.Inbounds) != 1 ||
		root.Inbounds[0].Listen != "127.0.0.1" || root.Inbounds[0].Port != 10808 {
		t.Fatalf("unsafe or wrong profile: %+v", root)
	}
}

func TestRejectWrongProfileAndUnexpectedInbound(t *testing.T) {
	if _, err := SelectProfile([]byte(sample), "C"); err == nil {
		t.Fatal("unknown variant accepted")
	}
	if _, err := SelectProfile([]byte(`{"remarks":"fragB","inbounds":[{"protocol":"socks"}]}`), "B"); err == nil {
		t.Fatal("unexpected inbound accepted")
	}
	if _, err := SelectProfile([]byte(`{"remarks":"fragB","inbounds":[{"protocol":"mixed"},{"protocol":"mixed"}]}`), "B"); err == nil {
		t.Fatal("multiple listeners accepted")
	}
	if _, err := SelectProfile([]byte(`// comment
{"remarks":"fragB"}`), "B"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestVersionGate(t *testing.T) {
	if err := CheckVersion("Xray 26.10.1 (Xray, Penetrates Everything.)"); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion("Xray 26.6.27"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Xray 26.6.26", "Xray 25.10.10", "something else"} {
		if err := CheckVersion(s); err == nil {
			t.Fatalf("old or invalid version accepted: %s", strings.TrimSpace(s))
		}
	}
}
