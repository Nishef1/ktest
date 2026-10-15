package quickcheck

import "testing"

func TestCompareRefusesWindscribeFalsePositive(t *testing.T) {
	proxy := []Result{{Target: "YouTube", Success: true}, {Target: "Google", Success: true}}
	direct := []Result{{Target: "YouTube", Success: true}, {Target: "Google", Success: true}}
	a := Compare(proxy, direct)
	if a[0].Kind != "already_open" || a[1].Kind != "already_open" {
		t.Fatal(a)
	}

}

func TestCompareCandidateOnlyWhenDirectFailsAndVPNAbsent(t *testing.T) {
	proxy := []Result{{Target: "YouTube", Success: true}, {Target: "Google", Success: false, Detail: "timeout"}}
	direct := []Result{{Target: "YouTube", Success: false}}
	a := Compare(proxy, direct)
	if a[0].Kind != "candidate" || a[1].Kind != "unavailable" {
		t.Fatal(a)
	}
}

func TestDirectlyReachableGoogleFailureIsProxyRegression(t *testing.T) {
	viaProxy := []Result{{Target: "Google", Success: false, Detail: "DNS timeout"}}
	direct := []Result{{Target: "Google", Success: true}}
	assessment := Compare(viaProxy, direct)
	if assessment[0].Kind != "proxy_regression" {
		t.Fatalf("Google directly works, proxy is broken: %v", assessment)
	}
}
