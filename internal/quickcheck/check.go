package quickcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Result is application-level reachability, not an assertion that the public IP
// changed or that all destinations are accessible.
type Result struct {
	Target    string
	Status    int
	Success   bool
	Detail    string
	Reachable bool // verified HTTPS returned an HTTP status, including a refusal
	Skipped   bool // shared startup budget ended before this target was attempted
	Took      time.Duration
	BodyBytes int64
}

type Target struct {
	Name, URL, Method string
	Want              int // zero accepts 2xx/3xx as a connectivity check, never a login check
}

// No account/AI domains: direct controls must never contact those services.
func Targets() []Target {
	return []Target{
		{"YouTube", "https://www.youtube.com/generate_204", http.MethodGet, 204},
		{"Google", "https://www.google.com/generate_204", http.MethodGet, 204},
		{"Instagram", "https://www.instagram.com/", http.MethodHead, 0},
		{"Telegram", "https://telegram.org/", http.MethodHead, 0},
		{"Telegram Web", "https://web.telegram.org/a/", http.MethodHead, 0},
		{"TikTok", "https://www.tiktok.com/", http.MethodHead, 0},
		{"Discord", "https://discord.com/", http.MethodHead, 0},
		{"X", "https://x.com/", http.MethodHead, 0},
	}
}

func Run(ctx context.Context, socksPort int, timeout time.Duration) []Result {
	return RunWithTLS(ctx, socksPort, timeout, nil)
}

// RunWithTLS lets an explicit internal diagnostic trust its own constrained
// fronting CA. A nil config retains the ordinary system certificate checks.
// This does not change certificate trust for any other application.
func RunWithTLS(ctx context.Context, socksPort int, timeout time.Duration, config *tls.Config) []Result {
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	return runWithTLS(ctx, http.ProxyURL(proxy), timeout, config)
}

// RunDirect verifies ordinary-site controls without an HTTP/SOCKS proxy.
// The caller must account for any VPN/TUN already installed on the machine.
func RunDirect(ctx context.Context, timeout time.Duration) []Result {
	return run(ctx, nil, timeout)
}

func run(ctx context.Context, proxyFn func(*http.Request) (*url.URL, error), timeout time.Duration) []Result {
	return runWithTLS(ctx, proxyFn, timeout, nil)
}

func runWithTLS(ctx context.Context, proxyFn func(*http.Request) (*url.URL, error), timeout time.Duration, config *tls.Config) []Result {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if config == nil {
		config = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		config = config.Clone()
	}
	transport := &http.Transport{
		Proxy:                  proxyFn,
		TLSClientConfig:        config,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 32 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	return runTargets(ctx, client, Targets(), timeout)
}

// Three workers share one overall budget. A slow target cannot serialize the
// checks or add a full timeout for every extra site. GET bodies are capped;
// the other representatives use HEAD, no cookies and no redirect following.
func runTargets(parent context.Context, client *http.Client, targets []Target, budget time.Duration) []Result {
	probeClient := *client
	probeClient.Jar = nil
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &probeClient
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	out := make([]Result, len(targets))
	jobs := make(chan int, len(targets))
	for i, target := range targets {
		out[i] = Result{Target: target.Name, Skipped: true, Detail: "not checked: shared probe budget ended"}
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	workers := min(3, len(targets))
	if workers == 0 {
		return out
	}
	// Reserve time for every wave. Otherwise three silent first requests can
	// consume the entire shared budget and later sites never get an attempt.
	perTarget := budget / time.Duration((len(targets)+workers-1)/workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				attempt, stop := context.WithTimeout(ctx, perTarget)
				out[i] = checkTarget(attempt, client, targets[i])
				stop()
			}
		}()
	}
	wg.Wait()
	return out
}

// CheckTarget runs one explicit, isolated method/target calibration request.
// The caller owns its client transport and per-attempt deadline.
func CheckTarget(ctx context.Context, client *http.Client, target Target) Result {
	return checkTarget(ctx, client, target)
}

func checkTarget(ctx context.Context, client *http.Client, target Target) Result {
	began := time.Now()
	res := Result{Target: target.Name}
	req, err := http.NewRequestWithContext(ctx, target.Method, target.URL, nil)
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	req.Header.Set("Cache-Control", "no-store")
	// Wikimedia and other services reject the generic Go client User-Agent.
	// Identify the diagnostic instead of misreporting that refusal as a bad route.
	req.Header.Set("User-Agent", "KTest-Connectivity-Check/1.0 (+https://github.com/Nishef1/ktest)")
	response, err := client.Do(req)
	if err != nil {
		res.Detail = err.Error()
	} else {
		res.Reachable = true
		res.Status = response.StatusCode
		readBytes, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		res.BodyBytes = readBytes
		_ = response.Body.Close()
		res.Success = readErr == nil && (response.StatusCode == target.Want && target.Want != 0 || (target.Want == 0 && response.StatusCode >= 200 && response.StatusCode < 300))
		if res.Success {
			res.Detail = fmt.Sprintf("TLS verified; HTTP %d (%s connectivity probe)", res.Status, target.Method)
		} else if readErr != nil {
			res.Detail = fmt.Sprintf("TLS verified; HTTP %d; response body incomplete: %v", res.Status, readErr)
		} else {
			res.Detail = fmt.Sprintf("TLS verified; HTTP %d; service access not confirmed", res.Status)
		}
	}
	res.Took = time.Since(began)
	return res
}
