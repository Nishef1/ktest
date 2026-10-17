package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/probe"
)

type cdnScan struct {
	Running      bool     `json:"running"`
	Canceled     bool     `json:"canceled"`
	Attempted    int      `json:"attempted"`
	Budget       int      `json:"budget"`
	Goal         int      `json:"goal"`
	VerifiedHTTP []string `json:"verified_http"`
	ReachedGoal  bool     `json:"reached_goal"`
	ElapsedMS    int64    `json:"elapsed_ms"`
	Error        string   `json:"error,omitempty"`
	Note         string   `json:"note"`
	Provider     string   `json:"provider"`
	Source       string   `json:"source,omitempty"`
}

var scanMu sync.Mutex
var scanState cdnScan
var scanCancel context.CancelFunc

// StartCDNScan invokes the same bounded Cloudflare candidate generator and
// HTTPS scanner as the CLI. Only a real user action should call this API.
// It neither downloads cores nor changes the active connection's routes.
func StartCDNScan(budget, goal int) error {
	return StartCDNScanForProvider("cloudflare", budget, goal)
}

func StartCDNScanForProvider(provider string, budget, goal int) error {
	if budget < 1 || budget > 300 {
		return errors.New("candidate budget must be 1..300")
	}
	if provider != "cloudflare" && provider != "akamai" && provider != "fastly" && provider != "google" {
		return errors.New("choose cloudflare, akamai, fastly or google")
	}
	if goal < 1 || goal > 10 || goal > budget {
		return errors.New("scan goal must be 1..10 and no larger than its candidate budget")
	}
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanState.Running {
		return errors.New("a CDN scan is already running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	scanCancel = cancel
	scanState = cdnScan{Running: true, Budget: budget, Goal: goal, Provider: provider,
		Note: "Verified HTTPS to the provider's test host only; this does not prove arbitrary fronting, VPN access, or a working DNS resolver. Provider discovery/DNS and HTTPS can be blocked independently."}
	started := time.Now()
	go func() {
		defer cancel()
		preset, err := edges.ScanCandidates(ctx, provider, budget)
		if err != nil {
			scanMu.Lock()
			scanState.Running, scanState.Error, scanCancel = false, err.Error(), nil
			scanMu.Unlock()
			return
		}
		scanMu.Lock()
		scanState.Source, scanState.Budget = preset.Source, len(preset.IPs)
		scanMu.Unlock()
		out, err := edges.ScanCDN(ctx, preset.IPs, preset.URL, goal, nil,
			func(ip string, r probe.Result, attempted, _ int) {
				scanMu.Lock()
				defer scanMu.Unlock()
				scanState.Attempted = attempted
				scanState.ElapsedMS = time.Since(started).Milliseconds()
				if r.Success && r.TLSVersion != "" && r.Status >= 200 && r.Status < 300 && r.Error == "" {
					scanState.VerifiedHTTP = append(scanState.VerifiedHTTP, ip)
				}
			})
		scanMu.Lock()
		defer scanMu.Unlock()
		scanState.Running = false
		scanState.ReachedGoal = out.ReachedGoal
		scanState.ElapsedMS = time.Since(started).Milliseconds()
		if err != nil {
			scanState.Error = err.Error()
		} else if ctx.Err() != nil && !scanState.Canceled {
			scanState.Error = ctx.Err().Error()
		}
		scanCancel = nil
	}()
	return nil
}

func CDNScanStatus() string {
	scanMu.Lock()
	defer scanMu.Unlock()
	raw, _ := json.Marshal(scanState)
	return string(raw)
}

func CancelCDNScan() {
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanCancel != nil {
		scanState.Canceled = true
		scanCancel()
	}
}
