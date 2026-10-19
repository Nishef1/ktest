// Package cdnranges keeps the complete address inventory of the CDNs ktest
// scans and fronts through: Cloudflare, Fastly, Google, Akamai, Meta,
// CloudFront and Gcore.
//
// Three layers, newest wins per provider: the snapshot embedded at build time,
// an app-private cache refreshed from the providers' own lists, and nothing
// else. A refresh that looks truncated or poisoned (far fewer prefixes than
// the snapshot, bogon prefixes) is refused, so a filtered network cannot
// shrink the inventory. Providers without an official list (Akamai, Meta) are
// read from RIPEstat's announced prefixes of ASNs whose registered holder is
// that provider; official lists blocked from Iran (Fastly's API) fall back to
// the same ASN source.
package cdnranges

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Range is one provider's inventory.
type Range struct {
	V4      []string  `json:"v4"`
	V6      []string  `json:"v6,omitempty"`
	Updated time.Time `json:"updated"`
	Source  string    `json:"source"`
}

// Set is every provider's inventory.
type Set struct {
	Version   int               `json:"version"`
	Providers map[string]*Range `json:"providers"`
}

// Providers is the stable provider order shown to users.
var Providers = []string{"cloudflare", "fastly", "google", "akamai", "meta", "cloudfront", "gcore"}

// Known reports whether name is a provider with an inventory.
func Known(name string) bool {
	for _, p := range Providers {
		if p == name {
			return true
		}
	}
	return false
}

const cacheName = "cdn-ranges.json"

// MaxAge is how old the newest inventory may be before a refresh is due.
const MaxAge = 3 * 24 * time.Hour

//go:embed snapshot.json
var snapshotJSON []byte

var current atomic.Pointer[Set]
var loadOnce sync.Once

func snapshot() *Set {
	var s Set
	if err := json.Unmarshal(snapshotJSON, &s); err != nil || s.Version != 1 {
		return &Set{Version: 1, Providers: map[string]*Range{}}
	}
	return &s
}

// Current is the inventory in use: the embedded snapshot until Use or Load
// installs a newer one.
func Current() *Set {
	loadOnce.Do(func() {
		if current.Load() == nil {
			current.Store(snapshot())
		}
	})
	return current.Load()
}

// Use installs s as the current inventory.
func Use(s *Set) {
	loadOnce.Do(func() {})
	current.Store(s)
}

// Load merges the cache in dir over the embedded snapshot, installs and
// returns the result. A missing or invalid cache leaves the snapshot.
func Load(dir string) *Set {
	merged := merge(snapshot(), readCache(dir))
	Use(merged)
	return merged
}

func readCache(dir string) *Set {
	if dir == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(dir, cacheName))
	if err != nil {
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16<<20))
	var s Set
	if err != nil || json.Unmarshal(raw, &s) != nil || s.Version != 1 {
		return nil
	}
	return &s
}

// merge keeps, per provider, the newer valid inventory.
func merge(base, over *Set) *Set {
	out := &Set{Version: 1, Providers: map[string]*Range{}}
	for _, s := range []*Set{base, over} {
		if s == nil {
			continue
		}
		for name, r := range s.Providers {
			if !Known(name) || r == nil || len(r.V4) == 0 || time.Until(r.Updated) > time.Hour {
				continue
			}
			if old := out.Providers[name]; old == nil || r.Updated.After(old.Updated) {
				out.Providers[name] = r
			}
		}
	}
	return out
}

// Oldest is the update time of the stalest provider (zero when empty).
func (s *Set) Oldest() time.Time {
	var t time.Time
	for _, r := range s.Providers {
		if t.IsZero() || r.Updated.Before(t) {
			t = r.Updated
		}
	}
	return t
}

// Stale reports whether a refresh is due.
func (s *Set) Stale() bool {
	return len(s.Providers) < len(Providers) || time.Since(s.Oldest()) > MaxAge
}

// Prefixes returns a provider's IPv4 prefixes.
func (s *Set) Prefixes(provider string) []netip.Prefix {
	r := s.Providers[provider]
	if r == nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(r.V4))
	for _, raw := range r.V4 {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out
}

// Contains reports whether ip belongs to provider's inventory.
func (s *Set) Contains(provider, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	r := s.Providers[provider]
	if r == nil {
		return false
	}
	for _, list := range [][]string{r.V4, r.V6} {
		for _, raw := range list {
			if p, err := netip.ParsePrefix(raw); err == nil && p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// ProviderOf names the provider an address belongs to, or "".
func (s *Set) ProviderOf(ip string) string {
	for _, p := range Providers {
		if s.Contains(p, ip) {
			return p
		}
	}
	return ""
}

// Size is the number of usable host addresses in a provider's IPv4 inventory.
func (s *Set) Size(provider string) int {
	n := 0
	for _, p := range s.Prefixes(provider) {
		size := 1 << uint(32-p.Bits())
		switch {
		case size >= 256:
			n += size / 256 * 254
		case size > 2:
			n += size - 2
		default:
			n += size
		}
	}
	return n
}

// Iterator emits unique host addresses (never .0/.255) of a provider. It
// visits prefixes round-robin in a shuffled order, so even a short scan
// spreads over the whole inventory instead of one block. It is consumed by
// one goroutine. Budget zero means the whole inventory.
func (s *Set) Iterator(provider string, budget int, seed uint64) func(context.Context) (string, bool, error) {
	type block struct {
		base         uint32
		size, cursor uint64
	}
	var blocks []block
	for _, p := range s.Prefixes(provider) {
		blocks = append(blocks, block{base: binary.BigEndian.Uint32(p.Addr().AsSlice()), size: uint64(1) << uint(32-p.Bits())})
	}
	if seed != 0 {
		r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		r.Shuffle(len(blocks), func(i, j int) { blocks[i], blocks[j] = blocks[j], blocks[i] })
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
				offset := b.cursor
				b.cursor++
				// Within each /24 skip the network and broadcast octets.
				if b.size >= 4 && (offset%256 == 0 || offset%256 == 255) {
					continue
				}
				var raw [4]byte
				binary.BigEndian.PutUint32(raw[:], b.base+uint32(offset))
				emitted++
				return netip.AddrFrom4(raw).String(), true, nil
			}
		}
		return "", false, nil
	}
}

// Sample returns up to n addresses spread over a provider's inventory.
func (s *Set) Sample(provider string, n int) []string {
	next := s.Iterator(provider, n, rand.Uint64()|1)
	var out []string
	for {
		ip, ok, err := next(context.Background())
		if err != nil || !ok {
			return out
		}
		out = append(out, ip)
	}
}

// Save writes s atomically to the cache in dir.
func Save(dir string, s *Set) error {
	if dir == "" {
		return errors.New("no cache directory")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".cdn-ranges-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, cacheName))
}

// Report is the outcome of one refresh, per provider.
type Report struct {
	Provider string
	Prefixes int
	Source   string
	Err      error
}

func (r Report) String() string {
	if r.Err != nil {
		return fmt.Sprintf("%s: kept previous (%v)", r.Provider, r.Err)
	}
	return fmt.Sprintf("%s: %d prefixes from %s", r.Provider, r.Prefixes, r.Source)
}

// Refresh fetches every provider through client (which may route through a
// local proxy), merges what passed validation over the current inventory,
// saves it to dir and installs it. Providers that fail keep their previous
// inventory. It returns an error only when nothing could be refreshed.
func Refresh(ctx context.Context, client *http.Client, dir string) ([]Report, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	base := merge(snapshot(), readCache(dir))
	base = merge(base, Current())
	fresh := &Set{Version: 1, Providers: map[string]*Range{}}
	reports := make([]Report, len(Providers))
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, provider := range Providers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := fetchProvider(ctx, client, provider)
			if err == nil {
				err = plausible(r, base.Providers[provider])
			}
			reports[i] = Report{Provider: provider, Err: err}
			if err == nil {
				reports[i].Prefixes, reports[i].Source = len(r.V4)+len(r.V6), r.Source
				mu.Lock()
				fresh.Providers[provider] = r
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(fresh.Providers) == 0 {
		return reports, errors.New("no CDN inventory could be refreshed")
	}
	merged := merge(base, fresh)
	if dir != "" {
		if err := Save(dir, merged); err != nil {
			return reports, err
		}
	}
	Use(merged)
	return reports, nil
}

// RefreshIfStale refreshes only when the cache is due.
func RefreshIfStale(ctx context.Context, client *http.Client, dir string) ([]Report, bool, error) {
	if !Load(dir).Stale() {
		return nil, false, nil
	}
	reports, err := Refresh(ctx, client, dir)
	return reports, true, err
}

// plausible refuses a refresh that lost most of the known inventory: a block
// page, a truncated download or a filtered mirror must not shrink it.
func plausible(r, old *Range) error {
	if r == nil || len(r.V4) == 0 {
		return errors.New("no IPv4 prefixes")
	}
	if old != nil && len(old.V4) >= 10 && len(r.V4)*2 < len(old.V4) {
		return fmt.Errorf("only %d prefixes, previously %d; refusing to shrink", len(r.V4), len(old.V4))
	}
	return nil
}

// usable keeps public unicast prefixes no broader than /8 and aggregates
// duplicates and nested prefixes.
func usable(raw []string) (v4, v6 []string) {
	var ps []netip.Prefix
	for _, s := range raw {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			if a, aerr := netip.ParseAddr(strings.TrimSpace(s)); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				continue
			}
		}
		p = p.Masked()
		a := p.Addr()
		if !a.IsGlobalUnicast() || a.IsPrivate() || (a.Is4() && p.Bits() < 8) || (a.Is6() && p.Bits() < 19) {
			continue
		}
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Addr().Is4() != ps[j].Addr().Is4() {
			return ps[i].Addr().Is4()
		}
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	var kept []netip.Prefix
	for _, p := range ps {
		if n := len(kept); n > 0 && kept[n-1].Contains(p.Addr()) && kept[n-1].Bits() <= p.Bits() {
			continue
		}
		kept = append(kept, p)
	}
	for _, p := range kept {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	return v4, v6
}
