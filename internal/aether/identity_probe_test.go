package aether

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Lines captured from Aether v2.3.1 on 2026-10-20: a key Cloudflare refused,
// and a fresh key on the same gateway.
func TestClassifyIdentityLines(t *testing.T) {
	run := func(lines ...string) IdentityVerdict {
		verdict, tls := IdentityUnknown, false
		for _, line := range lines {
			if verdict, tls = ClassifyIdentityLine(line, tls); verdict != IdentityUnknown {
				return verdict
			}
		}
		return verdict
	}
	if v := run("[h2] connecting tcp to 162.159.198.76:443", "[h2] tls established; alpn=",
		"[-] MASQUE tunnel ended: other: [masque] tunnel failed before validation: masque: await response: [TLSV1_ALERT_ACCESS_DENIED]; reconnecting"); v != IdentityRejected {
		t.Fatalf("refused key = %v", v)
	}
	// 400 came from 162.159.197.x for a key 162.159.198.x accepted: a
	// request/gateway refusal, never evidence against the key.
	if v := run("[h2] tls established; alpn=", "[h2] connect-ip status: 400"); v != IdentityGatewayRefused {
		t.Fatalf("400 = %v", v)
	}
	if v := run("[h2] tls established; alpn=", "[h2] connect-ip status: 503"); v != IdentityGatewayRefused {
		t.Fatalf("503 = %v", v)
	}
	if v := run("[h2] tls established; alpn=", "[h2] connect-ip status: 403"); v != IdentityRejected {
		t.Fatalf("403 = %v", v)
	}
	if v := run("[h2] tls established; alpn=", "[h2] connect-ip status: 4031"); v == IdentityRejected {
		t.Fatalf("4031 matched 403: %v", v)
	}
	if v := run("[h2] tls established; alpn=", "[h2] connect-ip status: 200"); v != IdentityAccepted {
		t.Fatalf("fresh key = %v", v)
	}
	// Without a completed TLS handshake nothing is said about the key.
	if v := run("[h2] connecting tcp to 162.159.198.76:443", "tls: h2 tls handshake: TLS handshake failed [SSLV3_ALERT_CERTIFICATE_UNKNOWN]"); v != IdentityUnknown {
		t.Fatalf("filtered network judged the key: %v", v)
	}
}

func TestProbePeersPreferRememberedAndSkipNonJudgingRange(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "masque-lastconn.toml"), []byte("peer = \"162.159.198.50:443\"\nrecent = [\n    \"162.159.197.9:443\",\n    \"162.159.198.8:443\",\n]\n"), 0o600)
	peers := probePeers(filepath.Join(dir, "masque.toml"))
	if peers[0] != "162.159.198.50:443" {
		t.Fatalf("remembered gateway not first: %v", peers)
	}
	seen := map[string]int{}
	for _, p := range peers {
		seen[p]++
		if strings.HasPrefix(p, "162.159.197.") {
			t.Fatalf("162.159.197.x answers 400 to valid keys and cannot judge one: %v", peers)
		}
	}
	if seen["162.159.198.8:443"] != 1 || len(peers) > 6 {
		t.Fatalf("peers not de-duplicated or bounded: %v", peers)
	}
}
