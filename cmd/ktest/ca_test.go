package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/front"
)

func TestFronterStaysOffWithoutATrustedCA(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	u := plainTerm(&bytes.Buffer{})

	f, note := newFronter(connectOptions{noFront: true}, nil, u, nil, nil)
	if f != nil || !strings.Contains(note, "-no-front") {
		t.Fatalf("noFront: %v %q", f, note)
	}
	f, note = newFronter(connectOptions{}, nil, u, nil, nil)
	if f != nil || !strings.Contains(note, "ktest ca -install") {
		t.Fatalf("no CA: %v %q", f, note)
	}
	// A CA exists but nothing trusts it: still off, unless forced.
	if _, err := front.Create(caDir()+"/x", []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestCAStatusDescribesTheNextStep(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir()+"/ca")
	var out bytes.Buffer
	caStatus(plainTerm(&out))
	if !strings.Contains(out.String(), "ktest ca -install") {
		t.Fatalf("no next step:\n%s", out.String())
	}
	if _, err := loadOrCreateCA(caDir()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	caStatus(plainTerm(&out))
	if !strings.Contains(out.String(), "Not trusted") || !strings.Contains(out.String(), "44 domains") && !strings.Contains(out.String(), "domains") {
		t.Fatalf("status:\n%s", out.String())
	}
	f, note := newFronter(connectOptions{}, nil, plainTerm(&out), nil, nil)
	if f != nil || !strings.Contains(note, "does not trust") {
		t.Fatalf("untrusted CA must keep fronting off: %v %q", f, note)
	}
	f, _ = newFronter(connectOptions{forceFront: true}, nil, plainTerm(&out), nil, nil)
	if f == nil {
		t.Fatal("-front must force it on")
	}
}
