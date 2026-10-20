package main

import (
	"strings"
	"testing"
)

func TestAetherProgressShowsFragmentedNativeMilestonesWithoutCredentials(t *testing.T) {
	var shown []string
	w := &aetherProgress{show: func(s string) { shown = append(shown, s) }}
	for _, chunk := range []string{
		"[INFO aether] identity ready: device=private token=secret\n",
		"[INFO aether::prober] [*] scan mode=balanced ip=ipv4 candi",
		"dates=2011 ports=[443, 500] concurrency=16 per_probe=6s budget=120s\n",
		"[INFO aether] [+] selected MASQUE gateway 162.159.197.1:443 (rtt 120ms)\n",
		"[WARN aether] [-] scan deadline reached with no gateway\n",
	} {
		_, _ = w.Write([]byte(chunk))
	}
	if len(shown) != 3 || !strings.Contains(shown[0], "2011 candidates / 120s") ||
		!strings.Contains(shown[1], "162.159.197.1:443; HTTPS exit still unverified") ||
		!strings.Contains(w.stage(), "untested") {
		t.Fatalf("native scan stages were lost: %v", shown)
	}
	for _, s := range shown {
		if strings.Contains(s, "private") || strings.Contains(s, "secret") {
			t.Fatal("native identity leaked")
		}
	}
	if got := aetherMilestone("selected WireGuard endpoint token=secret"); got != "" {
		t.Fatalf("unvalidated endpoint reached UI: %s", got)
	}
}
