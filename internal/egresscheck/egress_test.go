package egresscheck

import "testing"

func TestPolicyRejectsIranRussiaOrUnknownCountry(t *testing.T) {
	for _, tc := range []struct {
		trace string
		ok    bool
	}{
		{"ip=93.184.215.14\nloc=US", true},
		{"ip=93.184.215.14\nloc=IR", false},
		{"ip=93.184.215.14\nloc=RU", false},
		{"ip=93.184.215.14\nloc=XX", false},
		{"ip=127.0.0.1\nloc=US", false},
	} {
		_, _, err := ParseForeignTrace(tc.trace)
		if (err == nil) != tc.ok {
			t.Errorf("%q: want ok %t, got %v", tc.trace, tc.ok, err)
		}
	}
}

func TestProviderResponsesRespectFamilyAndPublicIP(t *testing.T) {
	for _, tc := range []struct {
		format, family, body string
		ok                   bool
	}{
		{"geojs", "ipv4", `{"ip":"93.184.215.14","country":"IR"}`, true},
		{"geojs", "ipv6", `{"ip":"2606:4700::123","country":"DE"}`, true},
		{"ipapi", "ipv6", `{"ip":"93.184.215.14","country_code":"US"}`, false},
		{"ipapi", "ipv4", `{"ip":"93.184.215.14","country_code":"US"}`, true},
		{"geojs", "both", `{"ip":"10.10.34.35","country":"IR"}`, false},
		{"geojs", "both", `{"ip":"93.184.215.14","country":"XX"}`, false},
		{"geojs", "both", `<html>blocked</html>`, false},
		{"trace", "ipv4", "ip=93.184.215.14\nloc=DE", true},
	} {
		if _, _, err := parseProvider([]byte(tc.body), tc.format, tc.family); (err == nil) != tc.ok {
			t.Errorf("%s %s: expected ok=%v, got %v", tc.format, tc.family, tc.ok, err)
		}
	}
}
