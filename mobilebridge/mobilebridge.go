// Package mobilebridge exposes a small, stable Go API to Android through gomobile.
// The diagnostic path deliberately does not alter VPN, DNS or proxy settings.
package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/pathdiag"
)

func Diagnose(rawURL string) (string, error) {
	return DiagnoseNetwork(rawURL, "tcp")
}

// DiagnoseNetwork exposes the CLI's IPv4/IPv6 selector without duplicating
// any DNS/TCP/TLS diagnostic logic in Android.
func DiagnoseNetwork(rawURL, network string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if len(rawURL) == 0 || len(rawURL) > 2048 {
		return "", errors.New("URL length is invalid")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil || u.Fragment != "" ||
		(u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return "", errors.New("use a valid HTTP(S) URL without credentials or fragments")
	}
	result, err := pathdiag.Run(context.Background(), pathdiag.Config{
		URL: rawURL, Network: network, Timeout: 8 * time.Second,
	})
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
