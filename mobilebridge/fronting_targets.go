package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

type targetFrontingPreset struct {
	URL       string `json:"url"`
	SNI       string `json:"sni"`
	HTTPHost  string `json:"http_host"`
	Family    string `json:"family"`
	UsesECH   bool   `json:"uses_ech"`
	Supported bool   `json:"supported"`
	Note      string `json:"note"`
}

func targetPreset(rawURL string) (targetFrontingPreset, error) {
	u, err := targetURL(rawURL)
	if err != nil {
		return targetFrontingPreset{}, err
	}
	preset := targetFrontingPreset{URL: u.String(), HTTPHost: u.Host, Note: "Unsupported fronting family. Ordinary HTTPS diagnostics are available; an arbitrary URL does not establish shared-edge support."}
	protected, _ := smartproxy.NewAIDomainRules("")
	if protected.Match(u.Hostname()) {
		preset.Note = "Protected service: strict verified-exit routing is required; local fronting diagnostics are not permitted."
		return preset, nil
	}
	fam := front.Lookup(front.DefaultFamilies(), u.Hostname())
	if fam == nil {
		return preset, nil
	}
	preset.Family = fam.Name
	if u.Port() != "" && u.Port() != "443" {
		preset.Note = "Unsupported fronting port: known strategies use HTTPS port 443. Ordinary HTTPS diagnostics remain available."
		return preset, nil
	}
	if len(fam.Fronts) == 0 {
		return preset, nil
	}
	fr := fam.Fronts[0]
	preset.SNI = fr.SNI
	preset.UsesECH = fr.ECH != ""
	if preset.UsesECH {
		preset.SNI = fr.ECH
	}
	preset.Supported = true
	preset.Note = "Known family strategy, not a reachability guarantee. The HTTP Host remains the target; TLS is verified at the edge. Public service responses do not prove a controlled origin or account/media access."
	if preset.UsesECH {
		preset.Note += " Uses real Encrypted Client Hello with verified retry configuration and target TLS, not plain SNI substitution."
	}
	return preset, nil
}

// FrontingPreset describes an existing family strategy without network I/O or
// CA changes. Unsupported custom hosts still work as normal route-test targets.
func FrontingPreset(rawURL string) (string, error) {
	preset, err := targetPreset(rawURL)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(preset)
	return string(raw), err
}

type targetFrontingCandidate struct {
	edges.Candidate
	Method       string `json:"method"`
	SNI          string `json:"sni"`
	ECH          bool   `json:"ech"`
	HTTPHost     string `json:"http_host"`
	Family       string `json:"family"`
	ReceivedHTTP int    `json:"received_http"`
	BodyComplete int    `json:"body_complete"`
	BodyBytes    int64  `json:"body_bytes"`
}

type targetFrontingReport struct {
	Target     string                    `json:"target"`
	URL        string                    `json:"url"`
	TLSName    string                    `json:"tls_name"`
	HTTPHost   string                    `json:"http_host"`
	Proof      bool                      `json:"proof_required"`
	Supported  bool                      `json:"supported"`
	Candidates []targetFrontingCandidate `json:"candidates"`
	Incomplete bool                      `json:"incomplete"`
	Note       string                    `json:"note"`
}

func targetFrontingEdges(raw string) ([]string, error) {
	list := strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n' })
	if len(list) < 1 || len(list) > 12 {
		return nil, errors.New("comparison requires 1..12 explicit public edge IPs; this is separate from scan limits")
	}
	seen := map[string]bool{}
	for i, rawIP := range list {
		if !front.IsPublicEdgeIP(rawIP) {
			return nil, errors.New("comparison edges must be numeric public addresses, without ports or CIDRs")
		}
		ip := net.ParseIP(rawIP).String()
		if seen[ip] {
			return nil, errors.New("comparison edges must be distinct")
		}
		seen[ip] = true
		list[i] = ip
	}
	return list, nil
}

// TestTargetFronting uses front's actual TLS/ECH paths with no local MITM. It
// never loads a CA private key. All traffic is opt-in, bounded, and disallowed
// during proxy startup, calibration or an active connection.
func TestTargetFronting(privateDir, rawURL, edgeIPs string, rounds int) (string, error) {
	// Serialize admission with the existing startup gate, including the entire
	// probe lifetime, so a new connection cannot start between check and dial.
	if !proxyStartMu.TryLock() {
		return "", errors.New("proxy startup or a target operation is active")
	}
	defer proxyStartMu.Unlock()
	if _, err := realRouteDirectory(privateDir); err != nil {
		return "", err
	}
	if routeWorkActive() {
		return "", errors.New("disconnect and finish startup/calibration before active target tests")
	}
	if rounds < 1 || rounds > 3 {
		return "", errors.New("comparison rounds must be 1..3")
	}
	ips, err := targetFrontingEdges(edgeIPs)
	if err != nil {
		return "", err
	}
	preset, err := targetPreset(rawURL)
	if err != nil {
		return "", err
	}
	u, _ := targetURL(preset.URL)
	protected, _ := smartproxy.NewAIDomainRules("")
	if protected.Match(u.Hostname()) {
		return "", errors.New("protected service requires its verified-exit route; direct fronting test refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := front.New(front.Config{DialTimeout: 7 * time.Second})
	report := runTargetFronting(ctx, preset.URL, ips, rounds, f.ProbeAtEdge)
	raw, err := json.Marshal(report)
	return string(raw), err
}

type targetFrontRunner func(context.Context, string, string, string) []front.ProbeResult

func runTargetFronting(ctx context.Context, rawURL string, ips []string, rounds int, run targetFrontRunner) targetFrontingReport {
	preset, _ := targetPreset(rawURL)
	u, _ := targetURL(preset.URL)
	report := targetFrontingReport{Target: u.Hostname(), URL: preset.URL, TLSName: preset.SNI, HTTPHost: preset.HTTPHost, Supported: preset.Supported, Candidates: []targetFrontingCandidate{}, Note: preset.Note}
	if !preset.Supported {
		return report
	}
	report.Note += " Counts are per edge and exact strategy. HTTP 2xx requires a complete bounded response body (204 may be empty). Origin verification is not available for public X/YouTube; origin_verified stays zero. A transport control does not prove authenticated APIs or playable media."
	indexes := map[string]int{}
	var elapsed [][]int64
	for round := 0; round < rounds; round++ {
		for _, ip := range ips {
			if ctx.Err() != nil {
				report.Incomplete = true
				break
			}
			for _, result := range run(ctx, u.Hostname(), u.RequestURI(), ip) {
				method := front.MethodName(result.Family, result.Front)
				key := ip + "|" + method
				index, ok := indexes[key]
				if !ok {
					index = len(report.Candidates)
					indexes[key] = index
					sni := result.Front.SNI
					if result.Front.ECH != "" {
						sni = result.Front.ECH
					}
					report.Candidates = append(report.Candidates, targetFrontingCandidate{Candidate: edges.Candidate{IP: ip}, Method: method, SNI: sni, ECH: result.Front.ECH != "", HTTPHost: u.Host, Family: result.Family})
					elapsed = append(elapsed, nil)
				}
				candidate := &report.Candidates[index]
				candidate.Attempts++
				if result.TCPConnected {
					candidate.TCPConnected++
				}
				if result.TLSVerified {
					candidate.TLSVerified++
				}
				if result.TLSVerified && result.Status > 0 {
					candidate.ReceivedHTTP++
				}
				if result.TLSVerified && result.Err == nil && result.BodyComplete {
					candidate.BodyComplete++
					if result.Status >= 200 && result.Status < 300 {
						candidate.HTTP2xx++
					}
				}
				candidate.BodyBytes += result.BodyBytes
				candidate.LastHTTPStatus = result.Status
				candidate.LastError = ""
				if result.Err != nil {
					candidate.LastError = result.Err.Error()
				}
				elapsed[index] = append(elapsed[index], result.Took.Milliseconds())
			}
		}
		if report.Incomplete {
			break
		}
	}
	for i := range report.Candidates {
		candidate := &report.Candidates[i]
		times := elapsed[i]
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		candidate.MedianElapsedMS = times[len(times)/2]
		if len(times)%2 == 0 {
			candidate.MedianElapsedMS = (times[len(times)/2-1] + times[len(times)/2]) / 2
		}
		switch {
		case candidate.HTTP2xx == rounds && candidate.TLSVerified == rounds:
			candidate.Assessment = "http_2xx_unverified"
		case candidate.LastHTTPStatus >= 400 && candidate.TLSVerified > 0:
			candidate.Assessment = "service_refused"
		case candidate.ReceivedHTTP > 0 && candidate.BodyComplete < candidate.ReceivedHTTP:
			candidate.Assessment = "body_incomplete"
		case candidate.ReceivedHTTP > 0:
			candidate.Assessment = "http_response_unverified"
		case candidate.TLSVerified > 0:
			candidate.Assessment = "tls_only"
		case candidate.TCPConnected > 0:
			candidate.Assessment = "tcp_only"
		default:
			candidate.Assessment = "unreachable"
		}
	}
	if ctx.Err() != nil {
		report.Incomplete = true
		report.Note += " Comparison budget ended; counts include only attempted work."
	}
	return report
}
