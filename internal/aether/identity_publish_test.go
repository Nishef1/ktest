package aether

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAndroidHardlinkDeniedFallsBackToExclusiveIdentityPublish(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage.toml")
	want := testWGIdentity(t, dir, "stage.toml", "new-device")
	target := filepath.Join(dir, "wg.toml")
	denied := func(_, _ string) error { return &os.LinkError{Op: "link", Err: os.ErrPermission} }
	created, err := publishStagedIdentity(stage, target, "wg", denied)
	if err != nil || !created {
		t.Fatalf("Android hardlink denial prevented saving registered key: created=%t error=%v", created, err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("published credential was not preserved exactly: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved key must be private 0600: %v / %v", info, err)
	}
	created, err = publishStagedIdentity(stage, target, "wg", denied)
	if created || err != nil {
		t.Fatalf("second enrollment must reuse already valid key: %t / %v", created, err)
	}
	got, err = os.ReadFile(target)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("a second registration overwrote an existing key: %v", err)
	}
}

func TestExclusiveFallbackNeverOverwritesMalformedExistingIdentity(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage.toml")
	_ = testWGIdentity(t, dir, "stage.toml", "candidate-device")
	target := filepath.Join(dir, "wg.toml")
	invalid := []byte("incomplete identity")
	if err := os.WriteFile(target, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	denied := func(_, _ string) error { return os.ErrPermission }
	created, err := publishStagedIdentity(stage, target, "wg", denied)
	if created || err == nil {
		t.Fatalf("malformed old key must fail closed, not be replaced: created=%t error=%v", created, err)
	}
	actual, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(actual, invalid) {
		t.Fatalf("old invalid key was changed: %v", err)
	}
}

func TestPublishValidatesBeforeExclusiveCreation(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "invalid.toml")
	if err := os.WriteFile(stage, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "wg.toml")
	called := false
	_, err := publishStagedIdentity(stage, target, "wg", func(_, _ string) error {
		called = true
		return os.ErrPermission
	})
	if err == nil || called {
		t.Fatalf("invalid key unexpectedly published: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid credential created a destination file: %v", err)
	}
}
