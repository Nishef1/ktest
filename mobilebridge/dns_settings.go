package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/connectiondns"
)

var dnsOverrideMu sync.RWMutex
var dnsOverride string

// SetDNSOverride stores one validated user-selected resolver for the next
// session. An empty value restores the built-in adaptive encrypted DNS policy.
func SetDNSOverride(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		dnsOverrideMu.Lock()
		dnsOverride = ""
		dnsOverrideMu.Unlock()
		return nil
	}
	server, err := connectiondns.NormalizeServer(raw)
	if err != nil {
		return err
	}
	dnsOverrideMu.Lock()
	dnsOverride = server
	dnsOverrideMu.Unlock()
	return nil
}

func currentDNSOverride() string {
	dnsOverrideMu.RLock()
	defer dnsOverrideMu.RUnlock()
	return dnsOverride
}

// ScanDNS tests up to twelve user-supplied DNS IPs over UDP and TCP, then
// verifies TLS against addresses returned by each resolver. The best result is
// only recommended when DNS and a real HTTPS handshake both succeed.
func ScanDNS(raw string) (string, error) {
	servers, err := connectiondns.ParseServerList(raw)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make([]connectiondns.ProbeResult, len(servers))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, server := range servers {
		i, server := i, server
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = connectiondns.ProbeResult{Server: server, Error: "Scan timed out before this server was tested"}
				return
			}
			results[i] = connectiondns.ProbeServer(ctx, server)
		}()
	}
	wg.Wait()

	recommended := ""
	bestScore := int64(1<<62 - 1)
	for _, result := range results {
		if !result.Internet {
			continue
		}
		score := result.DNSLatencyMS + result.HTTPSLatencyMS
		if score < bestScore {
			bestScore, recommended = score, result.Server
		}
	}
	note := "DNS reachability alone is not proof of Internet. A recommendation requires a public DNS answer and a verified TLS handshake. UDP/TCP DNS is unencrypted."
	report := struct {
		Results     []connectiondns.ProbeResult `json:"results"`
		Recommended string                      `json:"recommended"`
		Note        string                      `json:"note"`
	}{results, recommended, note}
	encoded, err := json.Marshal(report)
	if err != nil {
		return "", errors.New("could not encode DNS scan results")
	}
	return string(encoded), nil
}
