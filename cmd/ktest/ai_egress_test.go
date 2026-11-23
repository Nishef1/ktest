package main

import "testing"

func TestParseForeignTrace(t *testing.T) {
	for _, tc := range []struct {
		trace string
		good  bool
	}{
		{"ip=93.184.215.14\nloc=US\n", true},
		{"ip=9.9.9.9\nloc=DE\n", true},
		{"ip=93.184.215.14\nloc=IR\n", false},
		{"ip=203.0.113.99\nloc=US\n", false},
		{"ip=93.184.215.14\nloc=XX\n", false},
		{"ip=10.1.2.3\nloc=US\n", false},
		{"ip=127.0.0.1\nloc=US\n", false},
		{"ip=invalid\nloc=US\n", false},
		{"ip=93.184.215.14\n", false},
	} {
		_, _, err := parseForeignTrace(tc.trace)
		if (err == nil) != tc.good {
			t.Errorf("trace %q expected good %v, error %v", tc.trace, tc.good, err)
		}
	}
}
