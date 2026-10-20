package aether

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	backupVersion = 1
	backupMaxSize = 8 << 20
)

// IdentityFiles are the only credential files eligible for transfer. Runtime
// logs and unrelated app data never enter a backup.
var IdentityFiles = map[string]string{
	"masque.toml": "masque",
	"wg.toml": "wg",
	"masque-secondary.toml": "masque",
	"wg-secondary.toml": "wg",
	"masque-gool.toml": "wg",
}

type backupEnvelope struct {
	Version int `json:"version"`
	Salt string `json:"salt"`
	Nonce string `json:"nonce"`
	Data string `json:"data"`
}

type backupContents struct {
	Files map[string]string `json:"files"`
}

func identityBytes(dir, name, protocol string) ([]byte, error) {
	path := filepath.Join(dir, name)
	meta, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !meta.Mode().IsRegular() || meta.Size() > 1<<20 {
		return nil, errors.New("identity must be a regular file of at most 1 MiB")
	}
	if err := CheckIdentity(path, protocol); err != nil { return nil, err }
	return os.ReadFile(path)
}

// BackupIdentityBundle creates an authenticated, password-encrypted portable
// file. The raw keys stay in app-private storage, not in Android's document
// provider or the terminal. A user-chosen password is never written to disk.
func BackupIdentityBundle(dir, password string) ([]byte, error) {
	if len(password) < 12 {
		return nil, errors.New("backup password must contain at least 12 characters")
	}
	files := map[string]string{}
	for name, protocol := range IdentityFiles {
		data, err := identityBytes(dir, name, protocol)
		if errors.Is(err, os.ErrNotExist) { continue }
		if err != nil { return nil, fmt.Errorf("cannot back up %s: %w", name, err) }
		files[name] = string(data)
	}
	if len(files) == 0 { return nil, errors.New("no valid WARP identities exist yet; connect or register first") }
	plain, err := json.Marshal(backupContents{Files: files})
	if err != nil { return nil, err }
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil { return nil, err }
	if _, err := rand.Read(nonce); err != nil { return nil, err }
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil { return nil, err }
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	ciphertext := gcm.Seal(nil, nonce, plain, []byte("ktest-aether-backup-v1"))
	encoded := base64.StdEncoding.EncodeToString
	return json.Marshal(backupEnvelope{Version: backupVersion, Salt: encoded(salt), Nonce: encoded(nonce), Data: encoded(ciphertext)})
}

// publishIdentity avoids replacing even an invalid existing identity. The
// staged file is validated first, then hard-linked into its final filename;
// this fails with EEXIST if another process published an identity meanwhile.
func publishIdentity(dir, name, protocol string, data []byte) (bool, error) {
	target := filepath.Join(dir, name)
	if _, err := os.Lstat(target); err == nil {
		if err := CheckIdentity(target, protocol); err != nil {
			return false, fmt.Errorf("existing %s is invalid; no backup file was written over it: %w", name, err)
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil { return false, err }
	stage, err := os.CreateTemp(dir, ".identity-")
	if err != nil { return false, err }
	defer os.Remove(stage.Name())
	if err := stage.Chmod(0600); err != nil { stage.Close(); return false, err }
	if _, err := stage.Write(data); err != nil { stage.Close(); return false, err }
	if err := stage.Sync(); err != nil { stage.Close(); return false, err }
	if err := stage.Close(); err != nil { return false, err }
	if err := CheckIdentity(stage.Name(), protocol); err != nil { return false, err }
	if err := os.Link(stage.Name(), target); err != nil {
		if errors.Is(err, os.ErrExist) && CheckIdentity(target, protocol) == nil { return false, nil }
		return false, fmt.Errorf("cannot publish %s without overwriting existing data: %w", name, err)
	}
	return true, nil
}

// RestoreIdentityBundle validates every credential before publishing any of
// them. Invalid, mismatched or unsupported backups never delete current keys.
func RestoreIdentityBundle(dir, password string, encoded []byte) ([]string, error) {
	if len(encoded) == 0 || len(encoded) > backupMaxSize {
		return nil, errors.New("backup file is empty or too large")
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Version != backupVersion {
		return nil, errors.New("unsupported or malformed WARP backup")
	}
	decode := base64.StdEncoding.DecodeString
	salt, es := decode(envelope.Salt)
	nonce, en := decode(envelope.Nonce)
	data, ed := decode(envelope.Data)
	if es != nil || en != nil || ed != nil || len(salt) != 16 || len(nonce) != 12 {
		return nil, errors.New("corrupt backup metadata")
	}
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil { return nil, err }
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	plain, err := gcm.Open(nil, nonce, data, []byte("ktest-aether-backup-v1"))
	if err != nil { return nil, errors.New("incorrect backup password or corrupted data") }
	var contents backupContents
	if json.Unmarshal(plain, &contents) != nil || len(contents.Files) == 0 || len(contents.Files) > len(IdentityFiles) {
		return nil, errors.New("invalid backup credential inventory")
	}
	// Prevalidate in private temp files. A failed inventory must not leave a
	// newly imported subset that changes which WARP device a mode chooses.
	if err := os.MkdirAll(dir, 0700); err != nil { return nil, err }
	for name, value := range contents.Files {
		protocol, ok := IdentityFiles[name]
		if !ok || len(value) > 1<<20 { return nil, errors.New("backup contains unsupported credential files") }
		tmp, err := os.CreateTemp(dir, ".validate-")
		if err != nil { return nil, err }
		_, writeErr := io.WriteString(tmp, value)
		closeErr := tmp.Close()
		if writeErr != nil || closeErr != nil { os.Remove(tmp.Name()); return nil, errors.New("cannot validate backup credentials") }
		checkErr := CheckIdentity(tmp.Name(), protocol)
		os.Remove(tmp.Name())
		if checkErr != nil { return nil, fmt.Errorf("backup contains invalid %s: %w", name, checkErr) }
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			if err := CheckIdentity(filepath.Join(dir, name), protocol); err != nil {
				return nil, fmt.Errorf("cannot restore over invalid existing %s: %w", name, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) { return nil, err }
	}
	var installed []string
	for name, value := range contents.Files {
		added, err := publishIdentity(dir, name, IdentityFiles[name], []byte(value))
		if err != nil { return installed, err }
		if added { installed = append(installed, name) }
	}
	return installed, nil
}

// MigrateIdentityFiles reconciles the previous Android Balanced/Fast path with
// standalone Aether's existing path. Valid destination keys always win, so an
// upgrade does not silently replace the user's working WARP identity.
func MigrateIdentityFiles(destination, legacy string) ([]string, error) {
	if filepath.Clean(destination) == filepath.Clean(legacy) { return nil, nil }
	var migrated []string
	for name, protocol := range IdentityFiles {
		data, err := identityBytes(legacy, name, protocol)
		if errors.Is(err, os.ErrNotExist) { continue }
		if err != nil {
			if strings.Contains(err.Error(), "cannot") { continue }
			// Old malformed identities are left in place, never imported.
			continue
		}
		added, err := publishIdentity(destination, name, protocol, data)
		if err != nil { return migrated, err }
		if added { migrated = append(migrated, name) }
	}
	return migrated, nil
}
