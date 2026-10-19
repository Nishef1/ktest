package mobilebridge

import (
	"strings"
	"testing"
)

func TestStageLogKeepsRedactedWarningsOnly(t *testing.T) {
	l := &stageLog{}
	l.Write([]byte("[2026-10-19T09:20:28.916Z WARN  aether::account] [!] enabling warp retry 1/4 in 0.5s: api: enabling warp: tls: handshake with api.cloudflareclient.com: TLS handshake failed\n"))
	l.Write([]byte("[2026-10-19T09:20:29.000Z INFO  aether] [+] identity ready: device=72bf778f-36a9-490d-86cd-e75cce54c61a ipv4=172.16.0.2\n"))
	l.Write([]byte("[2026-10-19T09:21:15.440Z WARN  aether] [-] last known-good gateway 162.159.199.1:443 no longer "))
	l.Write([]byte("responds; peer 2606:4700:103::2 device 72bf778f-36a9-490d-86cd-e75cce54c61a\n"))
	got := strings.Join(l.lines, "\n")
	if strings.Contains(got, "identity ready") || strings.Contains(got, "162.159") || strings.Contains(got, "2606:") || strings.Contains(got, "72bf778f") {
		t.Fatalf("stage log leaked info lines or identifiers:\n%s", got)
	}
	if len(l.lines) != 2 || !strings.HasPrefix(l.lines[0], "enabling warp retry") || !strings.Contains(l.last(), "<ip> no longer responds") {
		t.Fatalf("unexpected stage log:\n%s", got)
	}
}
