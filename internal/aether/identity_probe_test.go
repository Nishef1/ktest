package aether

import "testing"

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
	if v := run("[h2] tls established; alpn=", "[h2] connect-ip status: 400"); v != IdentityRejected {
		t.Fatalf("400 = %v", v)
	}
	if v := run("[h2] tls established; alpn=", "[h2] connect-ip status: 200"); v != IdentityAccepted {
		t.Fatalf("fresh key = %v", v)
	}
	// Without a completed TLS handshake nothing is said about the key.
	if v := run("[h2] connecting tcp to 162.159.198.76:443", "tls: h2 tls handshake: TLS handshake failed [SSLV3_ALERT_CERTIFICATE_UNKNOWN]"); v != IdentityUnknown {
		t.Fatalf("filtered network judged the key: %v", v)
	}
}
