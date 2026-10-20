package main

import (
	"bytes"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/Nishef1/ktest/internal/aether"
)

var aetherScanLine = regexp.MustCompile(`scan mode=(\w+) ip=(\w+) candidates=(\d+).* budget=([0-9.]+s)`)

// Only known milestones reach the terminal. Native output can contain device
// identifiers, keys and paths, so never forward an arbitrary INFO line.
func aetherMilestone(line string) string {
	if m := aetherScanLine.FindStringSubmatch(line); m != nil {
		return "gateway scan: " + m[1] + " / " + m[2] + " / " + m[3] + " candidates / " + m[4] + " native budget"
	}
	for _, marker := range []string{"selected MASQUE gateway ", "selected WireGuard endpoint ", "using forced peer ", "verifying cached gateway ", "verifying cached WireGuard endpoint "} {
		if _, rest, ok := strings.Cut(line, marker); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				if endpoint, err := netip.ParseAddrPort(fields[0]); err == nil {
					return strings.TrimSpace(marker) + " " + endpoint.String() + "; HTTPS exit still unverified"
				}
			}
		}
	}
	if strings.Contains(line, "scan deadline reached with no gateway") || strings.Contains(line, "scan deadline reached with no endpoint") {
		return "native scan finished without a validated endpoint; remaining candidates are untested"
	}
	if aether.MASQUEScanFailed(line) {
		return "native scan found no usable MASQUE gateway; remaining candidates are untested"
	}
	return ""
}

type aetherProgress struct {
	mu         sync.Mutex
	partial    []byte
	last       string
	show       func(string)
	scanFailed func()
}

func (w *aetherProgress) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.partial = append(w.partial, p...)
	for {
		i := bytes.IndexByte(w.partial, '\n')
		if i < 0 {
			break
		}
		line := string(w.partial[:i])
		stage := aetherMilestone(line)
		w.partial = w.partial[i+1:]
		if stage != "" && stage != w.last {
			w.last = stage
			w.show(stage)
		}
		if w.scanFailed != nil && aether.MASQUEScanFailed(line) {
			w.scanFailed()
			w.scanFailed = nil
		}
	}
	if len(w.partial) > 8192 {
		w.partial = nil
	}
	return len(p), nil
}

func (w *aetherProgress) stage() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}
