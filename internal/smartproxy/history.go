package smartproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type savedScore struct {
	Wins      int     `json:"wins"`
	Fails     int     `json:"fails"`
	LatencyMS float64 `json:"latency_ms"`
	Kind      string  `json:"kind,omitempty"`
}
type savedDestination struct {
	Winner  string                `json:"winner"`
	Updated time.Time             `json:"updated"`
	Routes  map[string]savedScore `json:"routes"`
	// Kind is the filtering the destination showed; Credited the family it
	// already contributed to the network priors.
	Kind     string `json:"kind,omitempty"`
	Credited string `json:"credited,omitempty"`
}

// savedPrior is the network-level lesson for one failure kind. The history
// file is already keyed by network (and mode), so these are per network.
type savedPrior struct {
	Sites   int            `json:"sites"`
	Wins    map[string]int `json:"wins,omitempty"`
	Losses  map[string]int `json:"losses,omitempty"`
	Updated time.Time      `json:"updated"`
}
type savedHistory struct {
	Version      int                         `json:"version"`
	Key          string                      `json:"key"`
	Destinations map[string]savedDestination `json:"destinations"`
	Priors       map[string]savedPrior       `json:"priors,omitempty"`
}

func historyDestination(host, port string) string {
	sum := sha256.Sum256([]byte(destinationKey(host, port)))
	return hex.EncodeToString(sum[:])
}

var errInvalidHistory = errors.New("invalid route history")

func readHistory(file string) (savedHistory, error) {
	var h savedHistory
	f, err := os.Open(file)
	if err != nil {
		return h, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &h) != nil || h.Version != 1 {
		return h, errInvalidHistory
	}
	return h, nil
}

func loadPriors(saved map[string]savedPrior) map[FailureKind]*familyPrior {
	out := map[FailureKind]*familyPrior{}
	for key, sp := range saved {
		kind := kindFromKey(key)
		if !kind.informative() || time.Since(sp.Updated) >= priorTTL || time.Until(sp.Updated) > time.Minute {
			continue
		}
		pr := &familyPrior{sites: sp.Sites, wins: map[string]int{}, losses: map[string]int{}, updated: sp.Updated}
		for f, n := range sp.Wins {
			pr.wins[f] = min(max(n, 0), priorCap)
		}
		for f, n := range sp.Losses {
			pr.losses[f] = min(max(n, 0), priorCap)
		}
		out[kind] = pr
	}
	return out
}

func (p *Proxy) loadHistory() {
	if p.cfg.HistoryFile == "" || p.cfg.HistoryKey == "" {
		return
	}
	h, err := readHistory(p.cfg.HistoryFile)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		if errors.Is(err, errInvalidHistory) {
			p.logf("Invalid route history preserved; live learning continues")
		}
		p.cfg.HistoryFile = ""
		return
	}
	if h.Key == p.cfg.HistoryKey {
		p.saved = h.Destinations
		p.priors = loadPriors(h.Priors)
	}
}

// HistorySummary reads a saved route history without starting a proxy and
// describes what it learned about this network's filtering (see
// Proxy.FilteringSummary). It is empty when the file is missing, invalid or
// belongs to another network.
func HistorySummary(file, key string) string {
	h, err := readHistory(file)
	if err != nil || h.Key != key {
		return ""
	}
	return summarizePriors(loadPriors(h.Priors))
}

// SaveHistory snapshots ranking hints only. It never persists sockets, exit
// eligibility, session identity pins, credentials or request payloads.
func (p *Proxy) SaveHistory() error {
	if p.cfg.HistoryFile == "" || p.cfg.HistoryKey == "" {
		return nil
	}
	p.mu.Lock()
	h := savedHistory{Version: 1, Key: p.cfg.HistoryKey, Destinations: map[string]savedDestination{}, Priors: map[string]savedPrior{}}
	for kind, pr := range p.priors {
		if pr.sites == 0 && len(pr.wins) == 0 && len(pr.losses) == 0 {
			continue
		}
		sp := savedPrior{Sites: pr.sites, Wins: map[string]int{}, Losses: map[string]int{}, Updated: pr.updated}
		if sp.Updated.IsZero() {
			sp.Updated = time.Now()
		}
		for f, n := range pr.wins {
			sp.Wins[f] = n
		}
		for f, n := range pr.losses {
			sp.Losses[f] = n
		}
		h.Priors[kindKeys[kind]] = sp
	}
	for key, s := range p.saved {
		h.Destinations[key] = s
	}
	for key, m := range p.mem {
		s := savedDestination{Winner: m.winner, Updated: m.updated, Routes: map[string]savedScore{},
			Kind: kindKeys[m.kind], Credited: m.credited}
		for name, score := range m.routes {
			if !score.rejected {
				s.Routes[name] = savedScore{score.wins, score.fails, score.ewmaMS, kindKeys[score.kind]}
			}
		}
		sum := sha256.Sum256([]byte(key))
		h.Destinations[hex.EncodeToString(sum[:])] = s
	}
	p.mu.Unlock()
	keys := make([]string, 0, len(h.Destinations))
	for key, s := range h.Destinations {
		if time.Since(s.Updated) >= p.cfg.MemoryTTL || time.Until(s.Updated) > time.Minute {
			delete(h.Destinations, key)
			continue
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return h.Destinations[keys[i]].Updated.After(h.Destinations[keys[j]].Updated) })
	for _, key := range keys[min(len(keys), 2048):] {
		delete(h.Destinations, key)
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("route history exceeds size limit")
	}
	if err = os.MkdirAll(filepath.Dir(p.cfg.HistoryFile), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p.cfg.HistoryFile), ".routes-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), p.cfg.HistoryFile)
}

// MaintainHistory is owned by the connection session, including its final
// flush. No disk I/O runs inside connection selection or while holding mu.
func (p *Proxy) MaintainHistory(ctx context.Context) {
	if p.cfg.HistoryFile == "" {
		return
	}
	timer := time.NewTicker(30 * time.Second)
	defer timer.Stop()
	var saved uint64
	flush := func() {
		p.mu.Lock()
		changed := p.historyUpdates
		p.mu.Unlock()
		if changed != saved {
			if err := p.SaveHistory(); err != nil {
				p.logf("Route history not saved: %v", err)
			} else {
				saved = changed
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-timer.C:
			flush()
		}
	}
}
