package front

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// A server that does not speak ECH must see the dummy configuration as a
// well-formed one it cannot use: the client falls back to the public name,
// verifies the certificate for it and reports an ECH rejection. That is the
// first half of the bootstrap; the retry configuration only a real Cloudflare
// edge returns is exercised live (see docs/WINDOWS.md).
func TestDummyECHConfigIsWellFormedAndRejectedCleanly(t *testing.T) {
	e := startEdge(t, CloudflareECH)
	f := New(Config{Roots: e.roots})
	connect := func() (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", e.ln.Addr().String())
	}
	_, err := f.tryECH(context.Background(), Front{ECH: CloudflareECH}, "x.com", []string{"http/1.1"}, connect)
	var rej *tls.ECHRejectionError
	if !errors.As(err, &rej) {
		t.Fatalf("want an ECH rejection, got %v", err)
	}
	if sni, _ := e.sniSeen.Load().(string); sni != CloudflareECH {
		t.Fatalf("the wire carried %q, want the public name %q", sni, CloudflareECH)
	}
	if f.echConfig(CloudflareECH) != nil {
		t.Fatal("a configuration nobody holds a key for must not be cached")
	}
}

func TestShuffledKeepsTheElements(t *testing.T) {
	in := []string{"a", "b", "c", "d"}
	out := shuffled(in)
	if len(out) != 4 || in[0] != "a" {
		t.Fatalf("%v %v", in, out)
	}
	seen := map[string]bool{}
	for _, s := range out {
		seen[s] = true
	}
	if len(seen) != 4 {
		t.Fatalf("%v", out)
	}
}

func TestCloudflareFamilyCoversXAndKnowsItsOwnDomainsAreConstrained(t *testing.T) {
	fams := DefaultFamilies()
	for _, h := range []string{"x.com", "api.x.com", "twitter.com", "pbs.twimg.com", "t.co", "discord.com"} {
		all := LookupAll(fams, h)
		covered := false
		for _, fam := range all {
			covered = covered || fam.Name == "cloudflare"
		}
		if !covered {
			t.Errorf("%s: %v", h, all)
		}
	}
	if len(LookupAll(fams, "notx.com")) != 0 {
		t.Fatal("look-alike matched")
	}
	// A CA made before the Cloudflare family existed lacks its domains.
	old := []string{"google.com", "youtube.com"}
	missing := Uncovered(fams, old)
	found := false
	for _, d := range missing {
		if d == "x.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("x.com not reported as uncovered: %v", missing)
	}
	if len(Uncovered(fams, PermittedDomains(fams))) != 0 {
		t.Fatal("a fresh CA must cover everything")
	}
}

func TestClientAbortIsNotARefusal(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, errors.New("read tcp 127.0.0.1:1: wsarecv: forcibly closed (reset)"), errors.New("i/o timeout")} {
		if !clientAborted(err) {
			t.Errorf("%v should count as the application going away", err)
		}
	}
	for _, err := range []error{errors.New("remote error: tls: unknown certificate authority"), errors.New("remote error: tls: bad certificate"), errors.New("tls: client offered only unsupported versions")} {
		if clientAborted(err) {
			t.Errorf("%v is a refusal", err)
		}
	}
}

func TestAcceptedSessionDoesNotEraseRefusalTotals(t *testing.T) {
	f := New(Config{})
	f.refusedOne()
	f.acceptedOne()
	if a, r := f.Stats(); a != 1 || r != 1 {
		t.Fatalf("accepted=%d refused=%d", a, r)
	}
}

func TestHTTPStatusPrefixDoesNotMisclassifyCDNFailures(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int
	}{
		{"HTTP/1.1 200 OK\r\n", 200},
		{"HTTP/1.1 403 Forbidden\r\n", 403},
		{"HTTP/1.1 421 Misdirected Request\r\n", 421},
		{"HTTP/2 binary response", 0},
		{"", 0},
	} {
		var prefix httpStatusPrefix
		_, _ = prefix.Write([]byte(tc.input[:min(len(tc.input), 4)]))
		_, _ = prefix.Write([]byte(tc.input[min(len(tc.input), 4):]))
		if got := prefix.status(); got != tc.want {
			t.Fatalf("prefix %q produced %d, want %d", tc.input, got, tc.want)
		}
	}
}
