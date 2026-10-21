package aether

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Since cloudflare-ech.com was blocked (2026-10-21), the advice for a device
// without a WARP key is to register once through another working exit: a
// local proxy of another app (an "exit node"), or with another VPN on.
// Only a loopback address is accepted, so a typo can never send the
// registration to a remote host the user did not choose. Aether's --upstream
// takes SOCKS5 and HTTP proxies (v2.3.2 help).

// ParseEnrollmentProxy normalizes "127.0.0.1:10808", "socks5://127.0.0.1:10808"
// or "http://127.0.0.1:10809" to an --upstream URL and rejects anything else.
// A bare host:port means SOCKS5.
func ParseEnrollmentProxy(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("proxy address is empty")
	}
	scheme := "socks5"
	if i := strings.Index(raw, "://"); i >= 0 {
		switch s := strings.ToLower(raw[:i]); s {
		case "socks5", "socks5h", "socks":
		case "http":
			scheme = "http"
		default:
			return "", fmt.Errorf("only a SOCKS5 or HTTP proxy is supported, not %s", s)
		}
		raw = strings.TrimSuffix(raw[i+3:], "/")
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("use host:port, e.g. 127.0.0.1:10808: %w", err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("only a local proxy on this device (127.0.0.1) is accepted")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return scheme + "://" + net.JoinHostPort(ip.String(), port), nil
}

// ViaProxyRoute is a registration route through a user-chosen local proxy,
// after checking that something listens there.
func ViaProxyRoute(ctx context.Context, raw string) (EnrollmentRoute, error) {
	upstream, err := ParseEnrollmentProxy(raw)
	if err != nil {
		return EnrollmentRoute{}, err
	}
	addr := upstream[strings.Index(upstream, "://")+3:]
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return EnrollmentRoute{}, fmt.Errorf("nothing is listening on %s; start the other app's local proxy first", addr)
	}
	c.Close()
	return EnrollmentRoute{Label: "your local proxy " + upstream, Args: []string{"--upstream", upstream}, Timeout: 45 * time.Second}, nil
}

// DirectRoute registers over the device's current network; with another VPN
// on, that VPN carries it.
var DirectRoute = EnrollmentRoute{Label: "current network (or another active VPN)", Args: nil, Timeout: 45 * time.Second}
