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
