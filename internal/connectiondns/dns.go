// Package connectiondns holds the DNS bootstrap shared by KTest's CLI and
// Android. It uses the existing Go DoH, trusted resolver, and ECH components.
package connectiondns

import (
    "context"
    "errors"
    "net"
    "strings"
    "time"

    "github.com/Nishef1/ktest/internal/front"
    "github.com/Nishef1/ktest/internal/smartproxy"
)

// ECHEndpoint is the exact Cloudflare encrypted-ClientHello DNS bootstrap
// formerly declared in the terminal-only front diagnostics.
func ECHEndpoint() smartproxy.DoHEndpoint {
    f := front.New(front.Config{})
    return smartproxy.DoHEndpoint{
        URL: "https://cloudflare-dns.com/dns-query",
        Accept: "application/dns-json",
        DialTLS: func(ctx context.Context) (net.Conn, error) {
            return f.DialECH(ctx, "cloudflare-dns.com", []string{"http/1.1"})
        },
    }
}

// MobileResolvers uses the same trusted resolver implementation as the CLI.
// Aether's verified external exit is strict: both HTTPS DNS and ordinary
// lookups must avoid Android's system resolver. Balanced/Fast can use the
// normal desktop system-first fallback policy for nonprotected destinations.
func MobileResolvers(mode, exitSOCKS string) (smartproxy.Resolver, smartproxy.Resolver, error) {
    strict := mode == "aether" || mode == "psiphon" || mode == "tor"
    exitSOCKS = strings.TrimSpace(exitSOCKS)
    if strict && exitSOCKS == "" {
        return nil, nil, errors.New("strict exit-only DNS requires an external verified SOCKS5 path")
    }
    var dial smartproxy.DialFunc
    if exitSOCKS != "" {
        dial = func(ctx context.Context, _, addr string) (net.Conn, error) {
            host, port, err := net.SplitHostPort(addr)
            if err != nil { return nil, err }
            return smartproxy.DialVia(ctx, exitSOCKS, host, port, 8*time.Second)
        }
    }
    endpoints := append([]smartproxy.DoHEndpoint(nil), smartproxy.DefaultDoH...)
    if !strict {
        // ECH bootstrap makes DNS possible even without a healthy default
        // resolver, but its own direct dial is not permitted in strict mode.
        endpoints = append(endpoints, ECHEndpoint())
    }
    var system func(context.Context, string, string) ([]net.IP, error)
    if strict {
        system = func(context.Context, string, string) ([]net.IP, error) {
            return nil, errors.New("system DNS disabled in foreign-exit-only mode")
        }
    }
    options := smartproxy.TrustedOptions{System: system,
        DoH: smartproxy.NewDoH(endpoints, dial, nil)}
    a := smartproxy.NewTrusted(options)
    options.DoH = smartproxy.NewDoHType(endpoints, dial, nil, "AAAA")
    options.IPv6 = true
    aaaa := smartproxy.NewTrusted(options)
    return a, aaaa, nil
}
