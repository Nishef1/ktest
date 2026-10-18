package edges

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/probe"
)

// Official Cloudflare IPv4 prefixes (https://www.cloudflare.com/ips/).
var cloudflareIPv4 = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
	"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
	"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
}

// CloudflareCandidates returns a finite, unique sample of official provider
// addresses. Streaming callers should use ScanCandidateSource instead.
func CloudflareCandidates(max int) ([]string, error) {
	if max < 1 {
		return nil, errors.New("candidate budget must be positive")
	}
	next, err := cloudflareIterator(max)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0)
	for {
		ip, ok, err := next(context.Background())
		if err != nil {
			return nil, err
		}
		if !ok {
			return out, nil
		}
		out = append(out, ip)
	}
}

// CandidateIterator emits unique addresses and returns ok=false only when its
// selected inventory/budget is exhausted. It is consumed by one goroutine.
type CandidateIterator func(context.Context) (ip string, ok bool, err error)

func cloudflareIterator(budget int) (CandidateIterator, error) {
	type block struct {
		base         uint32
		size, cursor uint64
	}
	blocks := make([]block, 0, len(cloudflareIPv4))
	for _, raw := range cloudflareIPv4 {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid official IPv4 prefix")
		}
		blocks = append(blocks, block{base: binary.BigEndian.Uint32(p.Masked().Addr().AsSlice()), size: uint64(1) << uint(32-p.Bits())})
	}
	position, emitted := 0, 0
	return func(ctx context.Context) (string, bool, error) {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if budget > 0 && emitted >= budget {
			return "", false, nil
		}
		for checked := 0; checked < len(blocks); checked++ {
			b := &blocks[position]
			position = (position + 1) % len(blocks)
			for b.cursor < b.size {
				if err := ctx.Err(); err != nil {
					return "", false, err
				}
				// An odd multiplier permutes each power-of-two block without
				// storing a growing seen-IP set. Interleave blocks for dispersion.
				offset := (b.cursor*2654435761 + 1) % b.size
				b.cursor++
				addr := b.base + uint32(offset)
				if offset == 0 || offset == b.size-1 || addr&255 == 0 || addr&255 == 255 {
					continue
				}
				var ip [4]byte
				binary.BigEndian.PutUint32(ip[:], addr)
				emitted++
				return netip.AddrFrom4(ip).String(), true, nil
			}
		}
		return "", false, nil
	}, nil
}

// ScanOutcome explicitly describes verified HTTPS access to the test host,
// not successful fronting to some other origin.
type ScanOutcome struct {
	Attempted     int
	VerifiedHTTP  []string
	Unverified    int
	Duration      time.Duration
	Goal          int
	ReachedGoal   bool
	TotalVerified int
	Exhausted     bool
}

type ScanProgress func(ip string, result probe.Result, attempted, verified int)

// ScanCDN scans an explicit finite list. Goal zero disables success-based early
// stopping; a positive goal remains available to existing CLI callers.
func ScanCDN(ctx context.Context, ips []string, target string, goal int, runner Runner, report ScanProgress) (ScanOutcome, error) {
	if len(ips) == 0 {
		return ScanOutcome{}, errors.New("scan needs candidates")
	}
	seen := make(map[string]bool, len(ips))
	for _, raw := range ips {
		ip, err := netip.ParseAddr(raw)
		if err != nil || seen[ip.Unmap().String()] {
			return ScanOutcome{}, errors.New("scan needs unique individual IP addresses")
		}
		seen[ip.Unmap().String()] = true
	}
	i := 0
	return ScanCDNStream(ctx, func(ctx context.Context) (string, bool, error) {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if i == len(ips) {
			return "", false, nil
		}
		ip := ips[i]
		i++
		return ip, true, nil
	}, target, goal, runner, report)
}

// ScanCDNStream drains every started request, including canceled requests, to
// report. Memory and concurrency stay bounded even for a continuous source.
// VerifiedHTTP retains at most 100 addresses; TotalVerified counts all verified
// attempts from the unique source. Provider HTTPS does not establish fronting.
func ScanCDNStream(ctx context.Context, next CandidateIterator, target string, goal int, runner Runner, report ScanProgress) (ScanOutcome, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || next == nil || goal < 0 {
		return ScanOutcome{}, errors.New("scan needs an HTTPS target, source, and nonnegative goal")
	}
	if runner == nil {
		runner = probe.Run
	}
	start := time.Now()
	working, cancel := context.WithCancel(ctx)
	defer cancel()
	type finding struct {
		ip  string
		res probe.Result
	}
	queue := make(chan string)
	results := make(chan finding)
	const workers = 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range queue {
				if working.Err() != nil {
					return
				}
				network := "tcp4"
				if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
					network = "tcp6"
				}
				cfg := probe.Config{
					URL: target, ConnectAddr: net.JoinHostPort(ip, "443"),
					Timeout: 4 * time.Second, MaxBodyBytes: 128, Network: network,
				}
				requestCtx, requestCancel := context.WithTimeout(working, cfg.Timeout)
				res, err := runner(requestCtx, cfg)
				requestCancel()
				if err != nil {
					res.Success, res.Error = false, "probe failed"
				}
				results <- finding{ip: ip, res: res}
			}
		}()
	}
	type sourceEnd struct {
		exhausted bool
		err       error
	}
	sourceDone := make(chan sourceEnd, 1)
	go func() {
		defer close(queue)
		for {
			ip, ok, err := next(working)
			if err != nil || !ok {
				sourceDone <- sourceEnd{exhausted: err == nil && !ok, err: err}
				return
			}
			if net.ParseIP(ip) == nil {
				sourceDone <- sourceEnd{err: errors.New("source returned an invalid IP")}
				return
			}
			select {
			case queue <- ip:
			case <-working.Done():
				sourceDone <- sourceEnd{err: working.Err()}
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	out := ScanOutcome{Goal: goal}
	for found := range results {
		out.Attempted++
		ok := found.res.Success && found.res.TLSVersion != "" &&
			found.res.Status >= 200 && found.res.Status < 300 && found.res.Error == ""
		if ok {
			out.TotalVerified++
			if len(out.VerifiedHTTP) < 100 {
				out.VerifiedHTTP = append(out.VerifiedHTTP, found.ip)
			}
		} else {
			out.Unverified++
		}
		if report != nil {
			report(found.ip, found.res, out.Attempted, out.TotalVerified)
		}
		if goal > 0 && out.TotalVerified >= goal {
			cancel()
		}
	}
	out.ReachedGoal = goal > 0 && out.TotalVerified >= goal
	end := <-sourceDone
	out.Exhausted = end.exhausted && ctx.Err() == nil && !out.ReachedGoal
	out.Duration = time.Since(start)
	sort.Strings(out.VerifiedHTTP)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if out.ReachedGoal && errors.Is(end.err, context.Canceled) {
		return out, nil
	}
	return out, end.err
}
