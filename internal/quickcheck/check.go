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
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	return run(ctx, http.ProxyURL(proxy), timeout)
}

// RunDirect verifies ordinary-site controls without an HTTP/SOCKS proxy.
// The caller must account for any VPN/TUN already installed on the machine.
func RunDirect(ctx context.Context, timeout time.Duration) []Result {
	return run(ctx, nil, timeout)
}

func run(ctx context.Context, proxyFn func(*http.Request) (*url.URL, error), timeout time.Duration) []Result {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	transport := &http.Transport{
		Proxy:                  proxyFn,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
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
	for w := 0; w < min(3, len(targets)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				out[i] = checkTarget(ctx, client, targets[i])
			}
		}()
	}
	wg.Wait()
	return out
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
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 256))
		_ = response.Body.Close()
		res.Success = response.StatusCode == target.Want || (target.Want == 0 && response.StatusCode >= 200 && response.StatusCode < 400)
		if res.Success {
			res.Detail = fmt.Sprintf("TLS verified; HTTP %d (%s connectivity probe)", res.Status, target.Method)
		} else {
			res.Detail = fmt.Sprintf("TLS verified; HTTP %d; service access not confirmed", res.Status)
		}
	}
	res.Took = time.Since(began)
	return res
}
