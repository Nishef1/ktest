package aether

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/Nishef1/ktest/internal/coreprocess"
)

// IdentityVerdict is what a WARP gateway said about a saved MASQUE key.
type IdentityVerdict int

const (
	// IdentityUnknown: no gateway was reached far enough to judge the key,
	// which says nothing about the key (the network may be filtering).
	IdentityUnknown IdentityVerdict = iota
	IdentityAccepted
	// IdentityRejected: TLS to the gateway completed and the gateway refused
	// this device's key. A key file can be intact offline and still be dead
	// server-side; such a key never connects, however good the network is.
	IdentityRejected
)

// ProbeGateways are MASQUE gateways that answer H2 on 443 (Aether's
// MASQUE_SEEDS / verified gateways); one that answers is enough to judge.
var ProbeGateways = []string{"162.159.198.1:443", "162.159.198.2:443", "162.159.197.1:443"}

var (
	probeAccepted = regexp.MustCompile(`connect-ip status: 2\d\d|tunnel validated`)
	probeRejected = regexp.MustCompile(`connect-ip status: 4\d\d|ALERT_ACCESS_DENIED|ALERT_CERTIFICATE_UNKNOWN|ALERT_BAD_CERTIFICATE`)
	probeTLS      = regexp.MustCompile(`\[h2\] tls established`)
)

// ClassifyIdentityLine reads one line of a forced-peer core log. A rejection
// counts only after TLS to the gateway completed, so a filtered network is
// never mistaken for a dead key.
func ClassifyIdentityLine(line string, tlsSeen bool) (verdict IdentityVerdict, tls bool) {
	tls = tlsSeen || probeTLS.MatchString(line)
	switch {
	case probeAccepted.MatchString(line):
		return IdentityAccepted, tls
	case tls && probeRejected.MatchString(line):
		return IdentityRejected, tls
	}
	return IdentityUnknown, tls
}

// ProbeMasqueIdentity asks real gateways, over MASQUE H2 with a forced peer
// (no scan), whether the key in masquePath is accepted. The core runs on a
// private copy of the key so the saved file is never rewritten.
func ProbeMasqueIdentity(ctx context.Context, binary, masquePath string) (IdentityVerdict, error) {
	dir, err := os.MkdirTemp("", "ktest-identity-")
	if err != nil {
		return IdentityUnknown, err
	}
	defer os.RemoveAll(dir)
	key, err := os.ReadFile(masquePath)
	if err != nil {
		return IdentityUnknown, err
	}
	copyPath := filepath.Join(dir, "masque.toml")
	if err := os.WriteFile(copyPath, key, 0o600); err != nil {
		return IdentityUnknown, err
	}
	for _, peer := range ProbeGateways {
		verdict, err := probeOnce(ctx, binary, dir, copyPath, peer)
		if err != nil || verdict != IdentityUnknown {
			return verdict, err
		}
	}
	return IdentityUnknown, nil
}

func probeOnce(parent context.Context, binary, dir, masquePath, peer string) (IdentityVerdict, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return IdentityUnknown, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	r, w := io.Pipe()
	cmd := coreprocess.Command(ctx, binary, "--masque", "--h2", "-4", "--peer", peer, "--startup-secs", "15",
		"--bind", "127.0.0.1:"+strconv.Itoa(port), "--config", filepath.Join(dir, "run.toml"),
		"--masque-config", masquePath, "--wg-config", filepath.Join(dir, "wg.toml"), "--log-level", "info")
	cmd.Env = append(os.Environ(), "AETHER_REPROVISION=0")
	cmd.Stdout, cmd.Stderr = w, w
	done := make(chan error, 1)
	go func() { done <- coreprocess.Run(cmd); w.Close() }()
	verdict, tls := IdentityUnknown, false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if verdict, tls = ClassifyIdentityLine(scanner.Text(), tls); verdict != IdentityUnknown {
			break
		}
	}
	cancel()
	go io.Copy(io.Discard, r)
	<-done
	if parent.Err() != nil {
		return IdentityUnknown, parent.Err()
	}
	if verdict == IdentityUnknown && !tls {
		return IdentityUnknown, nil
	}
	return verdict, nil
}

// SetAsideRejectedIdentity renames a key the gateways refused, so the next
// enrollment registers a fresh one. Nothing is deleted.
func SetAsideRejectedIdentity(path string) (string, error) {
	backup := fmt.Sprintf("%s.rejected-%s", path, time.Now().Format("20060102-150405"))
	return backup, os.Rename(path, backup)
}
