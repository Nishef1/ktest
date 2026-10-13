package access

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEngineVerifiesDigestAndBuildsArgs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "local-stub")
	bytes := []byte("test-only external binary; not executed")
	if err := os.WriteFile(file, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(bytes)
	cfg := EngineConfig{Binary: file, SHA256: hex.EncodeToString(hash[:]), Bridge: "127.0.0.1:40443", Target: "127.0.0.1:443", FakeSNI: "front.example", Fingerprint: "firefox", Injector: "active"}
	got, err := CheckEngine(cfg)
	want := []string{"-listen", "127.0.0.1:40443", "-connect", "127.0.0.1:443", "-fake-sni", "front.example", "-utls", "firefox", "-injector", "active"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%v err=%v", got, err)
	}
	cfg.SHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := CheckEngine(cfg); err == nil {
		t.Fatal("mismatch should prevent external execution")
	}
}

func TestEngineOptionsRejectUnsafeInputs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "test-stub")
	b := []byte("test-only")
	_ = os.WriteFile(file, b, 0600)
	h := sha256.Sum256(b)
	cfg := EngineConfig{Binary: file, SHA256: hex.EncodeToString(h[:]), Bridge: "127.0.0.1:40443", Target: "example.com:443", FakeSNI: "front.example", Fingerprint: "firefox", Injector: "active"}
	cfg.FakeSNI = "not valid\nfoo"
	if _, err := CheckEngine(cfg); err == nil {
		t.Fatal("invalid fake-sni")
	}
	cfg.FakeSNI = "front.example"
	cfg.Target = "example.com:80"
	if _, err := CheckEngine(cfg); err == nil {
		t.Fatal("non-443 target accepted")
	}
}
