package aether

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestManagedAetherLogHelper(t *testing.T) {
	if os.Getenv("KTEST_AETHER_LOG_HELPER") != "1" {
		return
	}
	fmt.Printf("filter=%s reprovision=%s", os.Getenv("RUST_LOG"), os.Getenv("AETHER_REPROVISION"))
	os.Exit(0)
}

func TestManagedLoggingSurvivesInheritedRustFilter(t *testing.T) {
	t.Setenv("KTEST_AETHER_LOG_HELPER", "1")
	t.Setenv("RUST_LOG", "warn")
	t.Setenv("AETHER_REPROVISION", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The test executable accepts -test.run, rather than Aether's CLI. An
	// argument after -- is still passed to the managed runner's logging policy.
	var output bytes.Buffer
	err := Run(ctx, os.Args[0], []string{"-test.run=^TestManagedAetherLogHelper$", "--", "--log-level", "info"}, &output)
	if err != nil || !strings.Contains(output.String(), "filter= reprovision=0") {
		t.Fatalf("shell logging overrides managed diagnostics: %v %s", err, output.String())
	}
	if os.Getenv("RUST_LOG") != "warn" || os.Getenv("AETHER_REPROVISION") != "1" {
		t.Fatal("managed launch changed the parent's environment")
	}
}
