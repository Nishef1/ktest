package dnscheck

import (
	"context"
	"strings"
	"testing"
)

func TestCanceledDNSNeverClaimsSuccess(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if check(ctx, "udp", "127.0.0.1:1") {
		t.Fatal("cancelled DNS query must not succeed")
	}
}

func TestResultNeverEquatesPingWithDNS(t *testing.T) {
	text := (Result{}).Format()
	if !strings.Contains(text, "UDP=false TCP=false") || !strings.Contains(text, "TXT") {
		t.Fatal(text)
	}
}
