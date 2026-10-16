package main

import "testing"

func TestParseForeignTrace(t *testing.T) {
 for _,tc:=range []struct{ trace string; good bool }{
  {"ip=203.0.113.99\nloc=US\n", true},
  {"ip=198.51.100.3\nloc=DE\n", true},
  {"ip=203.0.113.99\nloc=IR\n", false},
  {"ip=203.0.113.99\nloc=XX\n", false},
  {"ip=10.1.2.3\nloc=US\n", false},
  {"ip=127.0.0.1\nloc=US\n", false},
  {"ip=invalid\nloc=US\n", false},
  {"ip=203.0.113.99\n", false},
 }{
  _,_,err:=parseForeignTrace(tc.trace)
  if (err==nil)!=tc.good {t.Errorf("trace %q expected good %v, error %v",tc.trace,tc.good,err)}
 }
}
