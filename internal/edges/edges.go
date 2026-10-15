package edges

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/probe"
)

// Plan accepts a short, explicit list. It deliberately does not scan CIDRs.
type Plan struct {
	URL     string
	IPs     []string
	SNI     string
	Host    string
	Proof   bool
	Rounds  int
	Timeout time.Duration
}

type Candidate struct {
	IP               string `json:"ip"`
	Attempts         int    `json:"attempts"`
	TCPConnected     int    `json:"tcp_connected"`
	TLSVerified      int    `json:"tls_verified"`
	HTTP2xx          int    `json:"http_2xx"`
	OriginVerified   int    `json:"origin_verified"`
	MedianElapsedMS  int64  `json:"median_elapsed_ms"`
	Assessment       string `json:"assessment"`
	LastHTTPStatus   int    `json:"last_http_status,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

type Report struct {
	Target     string      `json:"target"`
	TLSName    string      `json:"tls_name"`
	Host       string      `json:"http_host"`
	Proof      bool        `json:"proof_required"`
	Candidates []Candidate `json:"candidates"`
	Note       string      `json:"note"`
}

type Runner func(context.Context, probe.Config) (probe.Result, error)

func Run(ctx context.Context, p Plan, runner Runner) (Report, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return Report{}, errors.New("a valid HTTPS URL with no user info is required")
	}
	if len(p.IPs) == 0 || len(p.IPs) > 12 || p.Rounds < 1 || p.Rounds > 3 {
		return Report{}, errors.New("provide 1..12 explicit IPs and 1..3 rounds")
	}
	if p.Timeout == 0 {
		p.Timeout = 6 * time.Second
	}
	if p.Timeout <= 0 || p.Timeout > 15*time.Second {
		return Report{}, errors.New("timeout must be between 1ns and 15s")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	sni := p.SNI
	if sni == "" {
		sni = u.Hostname()
	}
	host := p.Host
	if host == "" {
		host = u.Host
	}
	if strings.ContainsAny(sni, "\r\n/ @:") || strings.ContainsAny(host, "\r\n/ @") {
		return Report{}, errors.New("invalid TLS or HTTP host")
	}
	if runner == nil {
		runner = probe.Run
	}
	seen := make(map[string]bool)
	report := Report{Target: u.Hostname(), TLSName: sni, Host: host, Proof: p.Proof, Note: "TCP reachability and verified TLS do not establish domain fronting. Without controlled-origin proof, HTTP 2xx is unverified."}
	for _, raw := range p.IPs {
		raw = strings.TrimSpace(raw)
		ip := net.ParseIP(raw)
		if ip == nil {
			return Report{}, fmt.Errorf("not a single IP address: %q", raw)
		}
		key := ip.String()
		if seen[key] {
			return Report{}, fmt.Errorf("duplicate IP: %s", key)
		}
		seen[key] = true
		candidate := Candidate{IP: key}
		durations := make([]int64, 0, p.Rounds)
		for round := 0; round < p.Rounds; round++ {
			cfg := probe.Config{URL: p.URL, ConnectAddr: net.JoinHostPort(key, port), ServerName: sni,
				Host: host, Timeout: p.Timeout, MaxBodyBytes: 512, Proof: p.Proof}
			out, err := runner(ctx, cfg)
			if err != nil {
				return Report{}, err
			}
			candidate.Attempts++
			if out.TLSVersion != "" || out.Reachable || out.Phase == "tls" || out.Phase == "http" {
				candidate.TCPConnected++
			}
			if out.TLSVersion != "" {
				candidate.TLSVerified++
			}
			if out.Status >= 200 && out.Status < 300 && out.Error == "" {
				candidate.HTTP2xx++
			}
			if out.ProofStatus == "verified" && out.Success {
				candidate.OriginVerified++
			}
			candidate.LastHTTPStatus = out.Status
			candidate.LastError = out.Error
			durations = append(durations, out.ElapsedMS)
			if err = ctx.Err(); err != nil {
				return Report{}, err
			}
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		candidate.MedianElapsedMS = durations[len(durations)/2]
		switch {
		case p.Proof && candidate.OriginVerified == p.Rounds:
			candidate.Assessment = "origin_verified"
		case !p.Proof && candidate.HTTP2xx == p.Rounds && candidate.TLSVerified == p.Rounds:
			candidate.Assessment = "http_2xx_unverified"
		case candidate.TLSVerified > 0:
			candidate.Assessment = "tls_only"
		case candidate.TCPConnected > 0:
			candidate.Assessment = "tcp_only"
		default:
			candidate.Assessment = "unreachable"
		}
		report.Candidates = append(report.Candidates, candidate)
	}
	sort.SliceStable(report.Candidates, func(i, j int) bool {
		a, b := report.Candidates[i], report.Candidates[j]
		grade := func(c Candidate) int {
			switch c.Assessment {
			case "origin_verified":
				return 4
			case "http_2xx_unverified":
				return 3
			case "tls_only":
				return 2
			case "tcp_only":
				return 1
			}
			return 0
		}
		if grade(a) != grade(b) {
			return grade(a) > grade(b)
		}
		if a.OriginVerified != b.OriginVerified {
			return a.OriginVerified > b.OriginVerified
		}
		if a.HTTP2xx != b.HTTP2xx {
			return a.HTTP2xx > b.HTTP2xx
		}
		if a.TLSVerified != b.TLSVerified {
			return a.TLSVerified > b.TLSVerified
		}
		return a.MedianElapsedMS < b.MedianElapsedMS
	})
	return report, nil
}
