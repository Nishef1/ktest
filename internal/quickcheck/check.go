package quickcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Result is application-level reachability, not an assertion that the public IP
// changed or that all destinations are accessible.
type Result struct {
	Target  string
	Status  int
	Success bool
	Detail  string
}

func Run(ctx context.Context, socksPort int, timeout time.Duration) []Result {
	targets := []struct {
		Name string
		URL  string
		Want int
	}{
		{"YouTube", "https://www.youtube.com/generate_204", 204},
		{"Google", "https://www.google.com/generate_204", 204},
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxy),
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	out := make([]Result, 0, len(targets))
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		res := Result{Target: target.Name}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
		if err != nil {
			res.Detail = err.Error()
			out = append(out, res)
			continue
		}
		req.Header.Set("Cache-Control", "no-store")
		response, err := client.Do(req)
		if err != nil {
			res.Detail = err.Error()
		} else {
			res.Status = response.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 256))
			_ = response.Body.Close()
			res.Success = response.StatusCode == target.Want
			if res.Success {
				res.Detail = "TLS verified; expected HTTP 204 from target"
			} else {
				res.Detail = fmt.Sprintf("unexpected HTTP %d (expected %d); possible block, redirect, or service policy", res.Status, target.Want)
			}
		}
		out = append(out, res)
	}
	return out
}
