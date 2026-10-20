package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Nishef1/ktest/internal/aether"
	xterm "golang.org/x/term"
)

// The password never appears in command-line arguments or shell history.
func readWarpBackupPassword(confirm bool) (string, error) {
	if !xterm.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("encrypted WARP backup needs an interactive terminal for hidden password entry")
	}
	fmt.Fprint(os.Stderr, "Backup password (12+ characters): ")
	first, err := xterm.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(first) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat backup password: ")
		second, err := xterm.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", errors.New("passwords do not match")
		}
	}
	return string(first), nil
}

func runWarpBackup(path string, restore bool, u *term) int {
	if path == "" {
		u.Line(toneFail, "Select a backup filename")
		return 2
	}
	password, err := readWarpBackupPassword(!restore)
	if err != nil {
		u.Line(toneFail, "%v", err)
		return 1
	}
	if restore {
		in, err := os.Open(path)
		if err != nil {
			u.Line(toneFail, "%v", err)
			return 1
		}
		data, err := io.ReadAll(io.LimitReader(in, (8<<20)+1))
		closeErr := in.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			u.Line(toneFail, "backup cannot be read: %v", err)
			return 1
		}
		imported, err := aether.RestoreIdentityBundle(warpDir(), password, data)
		if err != nil {
			u.Line(toneFail, "restore refused: %v", err)
			return 1
		}
		u.Line(toneOK, "%d identities restored; existing valid keys kept.", len(imported))
		return 0
	}
	encoded, err := aether.BackupIdentityBundle(warpDir(), password)
	if err != nil {
		u.Line(toneFail, "backup refused: %v", err)
		return 1
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		u.Line(toneFail, "cannot create backup (will not overwrite): %v", err)
		return 1
	}
	_, err = out.Write(encoded)
	if syncErr := out.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		u.Line(toneFail, "backup write failed: %v", err)
		return 1
	}
	u.Line(toneOK, "Encrypted WARP backup saved at %s. Keep the password somewhere safe.", path)
	return 0
}
