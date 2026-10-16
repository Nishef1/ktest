package edges

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
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

// CloudflareCandidates returns no more than 300 unique, dispersed provider IPs.
// No arbitrary prefixes are generated or scanned.
func CloudflareCandidates(max int) ([]string, error) {
	if max < 1 || max > 300 {
		return nil, fmt.Errorf("candidate budget must be 1..300")
	}
	prefixes := make([]netip.Prefix, 0, len(cloudflareIPv4))
	for _, raw := range cloudflareIPv4 {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p.Masked())
	}
	out := make([]string, 0, max)
	for i := 0; i < max; i++ {
		p := prefixes[i%len(prefixes)]
		slot := i/len(prefixes) + 1
		slots := (max+len(prefixes)-1)/len(prefixes) + 1
		base := binary.BigEndian.Uint32(p.Addr().AsSlice())
		capacity := uint64(1) << uint(32-p.Bits())
		offset := uint32(1 + uint64(slot)*(capacity-2)/uint64(slots+1))
		addr := base + offset
		// Network (.0) and broadcast (.255) style endings are poor probes of a
		// real edge; nudge to a neighbouring host address inside the prefix.
		switch addr & 0xff {
		case 0:
			addr++
		case 0xff:
			addr--
		}
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], addr)
		out = append(out, netip.AddrFrom4(ip).String())
	}
	return out, nil
}

// ScanOutcome explicitly describes verified HTTPS access to the test host,
// not successful fronting to some other origin.
type ScanOutcome struct {
	Attempted    int
	VerifiedHTTP []string
	Unverified   int
	Duration     time.Duration
	Goal         int
	ReachedGoal  bool
}

type ScanProgress func(ip string, result probe.Result, attempted, verified int)

// ScanCDN performs bounded HTTPS tests against a single provider hostname.
// It stops upon ten verified TLS+HTTP responses or after its candidate budget.
func ScanCDN(ctx context.Context, ips []string, target string, goal int, runner Runner, report ScanProgress) (ScanOutcome, error) {
	if len(ips) == 0 || len(ips) > 300 || goal < 1 || goal > 10 {
		return ScanOutcome{}, fmt.Errorf("scan needs 1..300 candidates, goal 1..10")
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
		err error
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
				cfg := probe.Config{
					URL: target, ConnectAddr: net.JoinHostPort(ip, "443"),
					Timeout: 4 * time.Second, MaxBodyBytes: 128, Network: "tcp4",
				}
				res, err := runner(working, cfg)
				select {
				case results <- finding{ip: ip, res: res, err: err}:
				case <-working.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(queue)
		for _, ip := range ips {
			select {
			case queue <- ip:
			case <-working.Done():
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
		if found.err != nil {
			cancel()
			return out, found.err
		}
		out.Attempted++
		ok := found.res.Success && found.res.TLSVersion != "" &&
			found.res.Status >= 200 && found.res.Status < 300 && found.res.Error == ""
		if ok {
			out.VerifiedHTTP = append(out.VerifiedHTTP, found.ip)
		} else {
			out.Unverified++
		}
		if report != nil {
			report(found.ip, found.res, out.Attempted, len(out.VerifiedHTTP))
		}
		if len(out.VerifiedHTTP) >= goal {
			cancel()
			break
		}
	}
	out.ReachedGoal = len(out.VerifiedHTTP) >= goal
	out.Duration = time.Since(start)
	sort.Strings(out.VerifiedHTTP)
	return out, nil
}
