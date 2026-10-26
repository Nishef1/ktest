package aether

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// publishStagedIdentity publishes an already validated WARP key without ever
// replacing an existing key. Hard links offer an atomic publish on filesystems
// that allow them, but Android app-private storage can reject link(2) with
// EPERM. O_CREATE|O_EXCL is the safe no-overwrite fallback: no storage or
// permissions change is required from the Android user.
//
// The fallback removes its own incomplete file on a normal write/sync error.
// A device crash during copying can leave a partial file; it is deliberately
// never silently deleted or replaced on a later run. Such a file needs an
// explicit repair, not a new WARP device registered over existing data.
func publishStagedIdentity(stagePath, targetPath, protocol string, hardlink func(string, string) error) (bool, error) {
	if err := CheckIdentity(stagePath, protocol); err != nil {
		return false, fmt.Errorf("staged identity invalid: %w", err)
	}
	stat, err := os.Lstat(stagePath)
	if err != nil {
		return false, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 1<<20 {
		return false, errors.New("staged identity must be a regular bounded file")
	}
	if err := os.Chmod(stagePath, 0o600); err != nil {
		return false, err
	}
	if err := hardlink(stagePath, targetPath); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrExist) {
		return existingPublishedIdentity(targetPath, protocol)
	}

	// If link(2) was blocked (Android SELinux/FS policy, unsupported links,
	// cross-device operation), publishing by exclusive creation still works on
	// app-private storage and cannot overwrite another registration's key.
	source, err := os.Open(stagePath)
	if err != nil {
		return false, err
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return existingPublishedIdentity(targetPath, protocol)
	}
	if err != nil {
		return false, fmt.Errorf("exclusive identity creation failed: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(targetPath)
		}
	}()
	n, writeErr := io.Copy(target, io.LimitReader(source, (1<<20)+1))
	if writeErr != nil || n > 1<<20 {
		_ = target.Close()
		if writeErr != nil {
			return false, writeErr
		}
		return false, errors.New("staged identity is too large")
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		return false, err
	}
	if err := target.Close(); err != nil {
		return false, err
	}
	if err := CheckIdentity(targetPath, protocol); err != nil {
		return false, fmt.Errorf("published identity failed validation: %w", err)
	}
	complete = true
	return true, nil
}

func existingPublishedIdentity(path, protocol string) (bool, error) {
	if err := CheckIdentity(path, protocol); err != nil {
		return false, fmt.Errorf("existing identity left untouched: %w", err)
	}
	return false, nil
}
