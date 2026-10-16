package smartproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Bogus reports addresses that a correct public answer never contains. A
// filtering resolver typically answers blocked names with a private block-page
// address (for example 10.10.34.x), so such an answer means "poisoned", not
// "the site lives there".
func Bogus(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0, v4[0] >= 240: // "this network", reserved, broadcast
			return true
		case v4[0] == 100 && v4[1]&0xC0 == 64: // 100.64.0.0/10 shared address space
			return true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2, v4[0] == 198 && v4[1] == 51 && v4[2] == 100, v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return true // documentation ranges
		}
	}
	return false
}

// ErrPoisoned means the system resolver returned only bogus addresses.
var ErrPoisoned = errors.New("system DNS answered with private or reserved addresses only (poisoned)")

// googleFamily are names served by Google's front ends. Any front end IP can
// answer for them, so when DNS is poisoned and encrypted DNS is unreachable the
// address of www.google.com (which filters leave alone) is a usable stand-in.
// Endpoints that do not actually serve the name simply lose the race.
var googleFamily = []string{
	"youtube.com", "youtu.be", "ytimg.com", "ggpht.com",
	"googleusercontent.com", "gstatic.com", "googleapis.com", "google.com",
	"youtube-nocookie.com", "withgoogle.com",
}

func inGoogleFamily(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range googleFamily {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// TrustedOptions configures NewTrusted.
type TrustedOptions struct {
	// System resolves with the operating system's resolver; nil uses net.
	System func(ctx context.Context, network, host string) ([]net.IP, error)
	// DoH is an encrypted resolver tried when the system answer is unusable.
	DoH Resolver
	// IPv6 asks for AAAA instead of A.
	IPv6 bool
	// Logf receives one line per fallback; nil is silent.
	Logf func(format string, args ...any)
}

// NewTrusted returns a cached resolver that never hands out a poisoned answer:
// system DNS first (fast, and fine for unblocked names), then encrypted DNS by
// IP literal, then the Google-family stand-in. Bogus addresses are discarded at
// every step.
func NewTrusted(o TrustedOptions) Resolver {
	network := "ip4"
	if o.IPv6 {
		network = "ip6"
	}
	system := o.System
	if system == nil {
		system = func(ctx context.Context, network, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIP(ctx, network, host)
			return addrs, err
		}
	}
	logf := func(f string, a ...any) {
		if o.Logf != nil {
			o.Logf(f, a...)
		}
	}
	good := func(ips []net.IP) []string {
		var out []string
		for _, ip := range ips {
			if !Bogus(ip) {
				out = append(out, ip.String())
			}
		}
		return out
	}
	// Encrypted DNS is itself filtered on many networks: after three failures
	// in a row it is skipped for five minutes instead of slowing every lookup.
	var (
		bmu         sync.Mutex
		dohFails    int
		dohOffUntil time.Time
	)
	dohAllowed := func() bool {
		bmu.Lock()
		defer bmu.Unlock()
		return time.Now().After(dohOffUntil)
	}
	dohResult := func(ok bool) {
		bmu.Lock()
		defer bmu.Unlock()
		if ok {
			dohFails = 0
			return
		}
		if dohFails++; dohFails >= 3 {
			dohFails, dohOffUntil = 0, time.Now().Add(5*time.Minute)
			logf("encrypted DNS keeps failing here; skipping it for 5 minutes")
		}
	}
	lookup := func(ctx context.Context, host string) ([]string, time.Duration, error) {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ips, err := system(sctx, network, host)
		cancel()
		if ok := good(ips); err == nil && len(ok) > 0 {
			return ok, 5 * time.Minute, nil
		}
		poisoned := err == nil && len(ips) > 0
		if poisoned {
			logf("%s: %v (%s)", host, ErrPoisoned, ips[0])
		}
		if o.DoH != nil && dohAllowed() {
			got, derr := o.DoH(ctx, host)
			dohResult(derr == nil && len(got) > 0)
			if derr == nil && len(got) > 0 {
				return got, 5 * time.Minute, nil
			}
			if derr != nil {
				logf("%s: encrypted DNS failed: %v", host, derr)
			}
		}
		if inGoogleFamily(host) {
			sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			stand, serr := system(sctx, network, "www.google.com")
			cancel()
			if ok := good(stand); serr == nil && len(ok) > 0 {
				logf("%s: using the address of www.google.com (Google front ends serve this name)", host)
				return ok, time.Minute, nil
			}
		}
		if poisoned {
			return nil, 0, ErrPoisoned
		}
		if err == nil {
			err = fmt.Errorf("%s: no usable address", host)
		}
		return nil, 0, err
	}
	return cachedResolver(lookup, 15*time.Second)
}
