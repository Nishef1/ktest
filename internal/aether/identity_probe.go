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
	"strings"
	"time"
)

// IdentityVerdict is what a WARP gateway said about a saved MASQUE key.
type IdentityVerdict int

const (
	// IdentityUnknown: no gateway was reached far enough to judge the key,
	// which says nothing about the key (the network may be filtering).
	IdentityUnknown IdentityVerdict = iota
	IdentityAccepted
	// IdentityRejected: TLS completed and several gateways refused this
	// device's key while none accepted it. Observed 2026-10-20, such a
	// refusal can be temporary (the same key was accepted again an hour
	// later; concurrent use of one key or a limit after a large scan are
	// possible causes, not established). Callers set the key aside rather
	// than delete it.
	IdentityRejected
	// IdentityGatewayRefused: TLS completed but the gateway refused the
	// request in a way that does not name the credential (e.g. CONNECT-IP
	// 400, observed from 162.159.197.x for a key another gateway accepted).
	// It is never evidence against the key and never counts toward rejection.
	IdentityGatewayRefused
)

// ProbeGateways are MASQUE gateways that accepted a valid key over H2 on
// 443 from an Iranian ISP (2026-10-20). 162.159.197.x is left out: it
// answered CONNECT-IP 400 to a key that 162.159.198.x accepted, so it
// cannot judge a key. Gateways the core itself remembers are tried first.
var ProbeGateways = []string{"162.159.198.8:443", "162.159.198.76:443", "162.159.198.23:443", "162.159.198.189:443"}

// rejectQuorum: refusals from this many different gateways, and no
// acceptance, before a key is called dead; one gateway's refusal is noise.
const rejectQuorum = 2

var rememberedGateway = regexp.MustCompile(`"?(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})"?`)

// probePeers lists the gateways the core last connected through (its
// masque-lastconn.toml beside the key), then ProbeGateways, each once.
func probePeers(masquePath string) []string {
	var peers []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] && !strings.HasPrefix(p, "162.159.197.") {
			seen[p] = true
			peers = append(peers, p)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(filepath.Dir(masquePath), "masque-lastconn.toml")); err == nil && len(raw) < 64<<10 {
		for _, m := range rememberedGateway.FindAllStringSubmatch(string(raw), 8) {
			add(m[1])
		}
	}
	for _, p := range ProbeGateways {
		add(p)
	}
	if len(peers) > 6 {
		peers = peers[:6]
	}
	return peers
}

var (
	probeAccepted = regexp.MustCompile(`connect-ip status: 2\d\d|tunnel validated`)
	// Only refusals that name the credential: a TLS alert about the client
	// key/certificate after the handshake, or HTTP 401/403 to CONNECT-IP.
	probeRejected = regexp.MustCompile(`connect-ip status: 40[13]([^0-9]|$)|ALERT_ACCESS_DENIED|ALERT_CERTIFICATE_UNKNOWN|ALERT_BAD_CERTIFICATE|ALERT_CERTIFICATE_REVOKED|ALERT_CERTIFICATE_EXPIRED`)
	// Any other 4xx/5xx is a request or gateway problem, not a dead key.
	probeGatewayRefused = regexp.MustCompile(`connect-ip status: [45]\d\d`)
	probeTLS            = regexp.MustCompile(`\[h2\] tls established`)
)

// ClassifyIdentityLine reads one line of a forced-peer core log. A rejection
// counts only after TLS to the gateway completed, so a filtered network is
// never mistaken for a dead key, and only credential-specific refusals count:
// a request or gateway error (CONNECT-IP 400, 5xx) is IdentityGatewayRefused.
func ClassifyIdentityLine(line string, tlsSeen bool) (verdict IdentityVerdict, tls bool) {
	tls = tlsSeen || probeTLS.MatchString(line)
	switch {
	case probeAccepted.MatchString(line):
		return IdentityAccepted, tls
	case tls && probeRejected.MatchString(line):
		return IdentityRejected, tls
	case tls && probeGatewayRefused.MatchString(line):
		return IdentityGatewayRefused, tls
	}
	return IdentityUnknown, tls
}

// ProbeMasqueIdentity asks real gateways, over MASQUE H2 with a forced peer
// (no scan), whether the key in masquePath is accepted. The core runs on a
// private copy of the key so the saved file is never rewritten.
func ProbeMasqueIdentity(ctx context.Context, binary, masquePath string) (IdentityVerdict, error) {
	// Beside the key, in the private state directory: Android apps often
	// cannot write the system temp directory.
	dir, err := os.MkdirTemp(filepath.Dir(masquePath), ".identity-")
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
	rejected, silent := 0, 0
	for _, peer := range probePeers(masquePath) {
		verdict, tls, err := probeOnce(ctx, binary, dir, copyPath, peer)
		if err != nil {
			return IdentityUnknown, err
		}
		switch verdict {
		case IdentityAccepted:
			return IdentityAccepted, nil
		case IdentityRejected:
			if rejected++; rejected >= rejectQuorum {
				return IdentityRejected, nil
			}
		}
		// Gateways that never complete TLS mean a filtered path; more of
		// them cannot judge the key and only delay the real connection.
		if !tls {
			if silent++; silent >= 2 {
				return IdentityUnknown, nil
			}
		}
	}
	return IdentityUnknown, nil
}

// probePeerTimeout bounds one gateway; a refusal or acceptance normally
// arrives within a few seconds of TLS.
const probePeerTimeout = 20 * time.Second

func probeOnce(parent context.Context, binary, dir, masquePath, peer string) (IdentityVerdict, bool, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return IdentityUnknown, false, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	ctx, cancel := context.WithTimeout(parent, probePeerTimeout)
	defer cancel()
	r, w := io.Pipe()
	args := []string{"--masque", "--h2", "-4", "--peer", peer, "--startup-secs", "15",
		"--bind", "127.0.0.1:" + strconv.Itoa(port), "--config", filepath.Join(dir, "run.toml"),
		"--masque-config", masquePath, "--wg-config", filepath.Join(dir, "wg.toml"), "--log-level", "info"}
	done := make(chan error, 1)
	// Use the same managed environment as carrier startup. An inherited
	// RUST_LOG=warn hides the INFO-level acceptance/TLS markers below and
	// otherwise makes a working tunnel look inconclusive until timeout.
	go func() { done <- Run(ctx, binary, args, w); w.Close() }()
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
		return IdentityUnknown, tls, parent.Err()
	}
	return verdict, tls, nil
}

// SetAsideRejectedIdentity renames a key the gateways refused, so the next
// enrollment registers a fresh one. Nothing is deleted.
func SetAsideRejectedIdentity(path string) (string, error) {
	backup := fmt.Sprintf("%s.rejected-%s", path, time.Now().Format("20060102-150405"))
	return backup, os.Rename(path, backup)
}
