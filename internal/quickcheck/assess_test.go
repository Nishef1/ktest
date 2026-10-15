package quickcheck

import "testing"

func TestCompareRefusesWindscribeFalsePositive(t *testing.T) {
	proxy := []Result{{Target: "YouTube", Success: true}, {Target: "Google", Success: true}}
	direct := []Result{{Target: "YouTube", Success: true}, {Target: "Google", Success: true}}
	a := Compare(proxy, direct, false)
	if a[0].Kind != "already_open" || a[1].Kind != "already_open" {
		t.Fatal(a)
	}
	// Split-tunnel VPN can carry only the proxy process, so comparing direct
	// alone is insufficient. A detected VPN must always invalidate attribution.
	direct[0].Success = false
	a = Compare(proxy, direct, true)
	if a[0].Kind != "vpn_confounded" || a[1].Kind != "vpn_confounded" {
		t.Fatal(a)
	}
}

func TestCompareCandidateOnlyWhenDirectFailsAndVPNAbsent(t *testing.T) {
	proxy := []Result{{Target: "YouTube", Success: true}, {Target: "Google", Success: false, Detail: "timeout"}}
	direct := []Result{{Target: "YouTube", Success: false}}
	a := Compare(proxy, direct, false)
	if a[0].Kind != "candidate" || a[1].Kind != "unavailable" {
		t.Fatal(a)
	}
}
