package experiment

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/Nishef1/ktest/internal/probe"
)

// Plan is a bounded, deterministic A/B trial. All supplied endpoints must be
// authorized test targets. No packet injection or system-level changes occur.
type Plan struct {
	Base   probe.Config
	Rounds int
}

type Variant struct {
	Name   string       `json:"name"`
	Config probe.Config `json:"-"`
}

type Sample struct {
	Round   int          `json:"round"`
	Variant string       `json:"variant"`
	Result  probe.Result `json:"result"`
}

type Summary struct {
	Variant         string         `json:"variant"`
	Attempts        int            `json:"attempts"`
	SuccessfulHTTP  int            `json:"successful_http"`
	VerifiedOrigin  int            `json:"verified_origin"`
	ReceivedHTTP    int            `json:"received_http"`
	MedianElapsedMS int64          `json:"median_elapsed_ms"`
	Outcomes        map[string]int `json:"outcomes"`
}

type Report struct {
	Samples    []Sample   `json:"samples"`
	Summary    []Summary  `json:"summary"`
	Assessment Assessment `json:"assessment"`
}

type Assessment struct {
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	NextCheck string `json:"next_check"`
}

type Runner func(context.Context, probe.Config) (probe.Result, error)

func Variants(base probe.Config) ([]Variant, error) {
	if strings.TrimSpace(base.URL) == "" {
		return nil, errors.New("url is required")
	}
	if base.ConnectAddr == "" && base.ServerName == "" && base.Host == "" {
		return nil, errors.New("compare needs at least one of -connect, -sni, -host")
	}
	variants := []Variant{{Name: "baseline", Config: probe.Config{URL: base.URL, Network: base.Network, Timeout: base.Timeout, MaxBodyBytes: base.MaxBodyBytes, RootCAs: base.RootCAs, Proof: base.Proof}}}
	// Add a pinned connection if supplied; all other variants build on this
	// same dial address, to make any SNI/Host comparison fair.
	anchor := variants[0].Config
	if base.ConnectAddr != "" {
		anchor.ConnectAddr = base.ConnectAddr
		variants = append(variants, Variant{Name: "pinned", Config: anchor})
	}
	if base.Host != "" {
		v := anchor
		v.Host = base.Host
		variants = append(variants, Variant{Name: "http_host", Config: v})
	}
	if base.ServerName != "" {
		v := anchor
		v.ServerName = base.ServerName
		variants = append(variants, Variant{Name: "tls_sni", Config: v})
	}
	if base.Host != "" && base.ServerName != "" {
		v := anchor
		v.Host = base.Host
		v.ServerName = base.ServerName
		variants = append(variants, Variant{Name: "combined", Config: v})
	}
	return variants, nil
}

func Run(ctx context.Context, plan Plan, runner Runner) (Report, error) {
	if plan.Rounds < 1 || plan.Rounds > 10 {
		return Report{}, errors.New("rounds must be 1..10")
	}
	variants, err := Variants(plan.Base)
	if err != nil {
		return Report{}, err
	}
	if runner == nil {
		runner = probe.Run
	}
	report := Report{Samples: make([]Sample, 0, len(variants)*plan.Rounds)}
	for round := 1; round <= plan.Rounds; round++ {
		// Alternate forward/backward ordering to reduce temporal position bias.
		for pos := 0; pos < len(variants); pos++ {
			idx := pos
			if round%2 == 0 {
				idx = len(variants) - 1 - pos
			}
			v := variants[idx]
			result, err := runner(ctx, v.Config)
			if err != nil {
				return Report{}, err
			}
			report.Samples = append(report.Samples, Sample{Round: round, Variant: v.Name, Result: result})
			if err = ctx.Err(); err != nil {
				return Report{}, err
			}
		}
	}
	for _, variant := range variants {
		summary := Summary{Variant: variant.Name, Outcomes: make(map[string]int)}
		durations := make([]int64, 0, plan.Rounds)
		for _, sample := range report.Samples {
			if sample.Variant != variant.Name {
				continue
			}
			summary.Attempts++
			if sample.Result.Reachable {
				summary.ReceivedHTTP++
			}
			if sample.Result.Success {
				summary.SuccessfulHTTP++
			}
			if sample.Result.ProofStatus == "verified" && sample.Result.Success {
				summary.VerifiedOrigin++
			}
			summary.Outcomes[classify(sample.Result)]++
			durations = append(durations, sample.Result.ElapsedMS)
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		if len(durations) > 0 {
			summary.MedianElapsedMS = durations[len(durations)/2]
			if len(durations)%2 == 0 {
				summary.MedianElapsedMS = (durations[len(durations)/2-1] + durations[len(durations)/2]) / 2
			}
		}
		report.Summary = append(report.Summary, summary)
	}
	report.Assessment = assess(report.Summary, plan.Base.Proof, plan.Rounds)
	return report, nil
}

func classify(r probe.Result) string {
	if r.ProofStatus == "missing" {
		return "proof_missing"
	}
	if r.ProofStatus == "mismatch" {
		return "proof_mismatch"
	}
	if r.Success {
		return "http_success"
	}
	if r.Reachable {
		if r.Error != "" {
			return "body_error"
		}
		switch r.Status {
		case 301, 302, 303, 307, 308:
			return "http_redirect"
		case 403:
			return "http_forbidden"
		case 421:
			return "http_misdirected"
		default:
			return "http_status_failure"
		}
	}
	if r.Error == "" {
		return "inconclusive"
	}
	switch r.Phase {
	case "dns":
		return "dns_error"
	case "tcp":
		return "tcp_error"
	case "tls":
		return "tls_error"
	case "http":
		return "http_error"
	default:
		return "transport_error"
	}
}

// Timings are observations from individual connections; the median is not
// a statistical confidence interval or an estimate of nationwide reachability.

// assess produces cautious next-step guidance, never a censorship-bypass claim.
func assess(summaries []Summary, proof bool, rounds int) Assessment {
	if !proof {
		return Assessment{"unverified", "HTTP status alone cannot establish that the requested origin responded", "Use -proof against an HTTPS echo endpoint under your control"}
	}
	if len(summaries) == 0 {
		return Assessment{"inconclusive", "No trials", "Check the experiment configuration"}
	}
	baseline := summaries[0]
	if baseline.VerifiedOrigin == rounds {
		return Assessment{"baseline_available", "The baseline already reaches the controlled origin in every round", "Investigate application-level failures before trying other transport methods"}
	}
	if rounds < 3 {
		return Assessment{"inconclusive", "Fewer than three trials cannot support a comparative candidate", "Run at least three matched rounds and repeat across times"}
	}
	for _, s := range summaries[1:] {
		if s.VerifiedOrigin == rounds && baseline.VerifiedOrigin == 0 {
			return Assessment{"candidate", "An alternate route verified the controlled origin while the baseline did not; causality and field stability remain unproven", "Repeat on multiple networks with negative controls; verify no DNS/IP policy changes"}
		}
	}
	allTCP := true
	for _, s := range summaries {
		if s.Outcomes["tcp_error"] != s.Attempts {
			allTCP = false
		}
	}
	if allTCP {
		return Assessment{"path_unreachable", "Every trial failed before TLS", "Compare TCP4/TCP6 and an independently reachable route; avoid guessing SNI fixes"}
	}
	return Assessment{"inconclusive", "No repeatable controlled-origin advantage across variants", "Classify each phase and test one hypothesis at a time"}
}
