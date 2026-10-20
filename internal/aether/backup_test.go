package aether

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func testWGIdentity(t *testing.T, dir, filename, device string) []byte {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	data := []byte("device_id = \"" + device + "\"\naccess_token = \"secret-token\"\nipv4 = \"172.16.0.2\"\nwg_private_key = \"" + key + "\"\nwg_peer_public_key = \"" + key + "\"\n")
	if err := os.MkdirAll(dir, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dir, filename), data, 0600); err != nil { t.Fatal(err) }
	if err := CheckIdentity(filepath.Join(dir, filename), "wg"); err != nil { t.Fatalf("test identity invalid: %v", err) }
	return data
}

func TestEncryptedIdentityBackupSurvivesMoveAndDoesNotExposeKeys(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "original")
	plain := testWGIdentity(t, source, "wg.toml", "device-a")
	testWGIdentity(t, source, "wg-secondary.toml", "device-inner")
	backup, err := BackupIdentityBundle(source, "a separate memorable password")
	if err != nil { t.Fatal(err) }
	if bytes.Contains(backup, plain) || bytes.Contains(backup, []byte("secret-token")) {
		t.Fatal("plaintext credentials leaked into portable backup")
	}
	newDir := filepath.Join(root, "restored")
	inserted, err := RestoreIdentityBundle(newDir, "a separate memorable password", backup)
	if err != nil || len(inserted) != 2 { t.Fatalf("restore: %v files=%v", err, inserted) }
	got, err := os.ReadFile(filepath.Join(newDir, "wg.toml"))
	if err != nil || !bytes.Equal(got, plain) { t.Fatalf("identity bytes not preserved: %v", err) }
	inserted, err = RestoreIdentityBundle(newDir, "a separate memorable password", backup)
	if err != nil || len(inserted) != 0 { t.Fatalf("repeated restore overwrote keys: %v files=%v", err, inserted) }
}

func TestIdentityBackupRejectsBadPasswordTamperingAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	original := testWGIdentity(t, dir, "wg.toml", "device-original")
	encrypted, err := BackupIdentityBundle(dir, "a secure password of 12 chars")
	if err != nil { t.Fatal(err) }
	another := filepath.Join(t.TempDir(), "another")
	if _, err := RestoreIdentityBundle(another, "incorrect secret password", encrypted); err == nil {
		t.Fatal("bad password accepted")
	}
	mutated := append([]byte(nil), encrypted...)
	for i := range mutated {
		if mutated[i] >= 'a' && mutated[i] <= 'z' { mutated[i] = 'Z'; break }
	}
	if _, err := RestoreIdentityBundle(another, "a secure password of 12 chars", mutated); err == nil {
		t.Fatal("modified backup accepted")
	}
	testWGIdentity(t, another, "wg.toml", "keep-this-device")
	existing, _ := os.ReadFile(filepath.Join(another, "wg.toml"))
	if _, err := RestoreIdentityBundle(another, "a secure password of 12 chars", encrypted); err != nil { t.Fatal(err) }
	now, _ := os.ReadFile(filepath.Join(another, "wg.toml"))
	if !bytes.Equal(existing, now) || bytes.Equal(now, original) { t.Fatal("valid destination was overwritten") }
}

func TestMigrateLegacyAndroidKeysWithoutReplacingCurrent(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "automatic-exits")
	current := filepath.Join(root, "aether")
	testWGIdentity(t, legacy, "wg.toml", "legacy-device")
	migrated, err := MigrateIdentityFiles(current, legacy)
	if err != nil || len(migrated) != 1 { t.Fatalf("migration failed %v %v", migrated, err) }
	before, _ := os.ReadFile(filepath.Join(current, "wg.toml"))
	testWGIdentity(t, legacy, "wg.toml", "different-legacy-device")
	migrated, err = MigrateIdentityFiles(current, legacy)
	if err != nil || len(migrated) != 0 { t.Fatalf("migration unexpectedly overwrote: %v %v", migrated, err) }
	after, _ := os.ReadFile(filepath.Join(current, "wg.toml"))
	if !bytes.Equal(before, after) { t.Fatal("old saved device was replaced") }
}
