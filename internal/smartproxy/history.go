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
}
type savedDestination struct {
	Winner  string                `json:"winner"`
	Updated time.Time             `json:"updated"`
	Routes  map[string]savedScore `json:"routes"`
}
type savedHistory struct {
	Version      int                         `json:"version"`
	Key          string                      `json:"key"`
	Destinations map[string]savedDestination `json:"destinations"`
}

func historyDestination(host, port string) string {
	sum := sha256.Sum256([]byte(destinationKey(host, port)))
	return hex.EncodeToString(sum[:])
}

func (p *Proxy) loadHistory() {
	if p.cfg.HistoryFile == "" || p.cfg.HistoryKey == "" {
		return
	}
	f, err := os.Open(p.cfg.HistoryFile)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		p.cfg.HistoryFile = ""
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	var h savedHistory
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &h) != nil || h.Version != 1 {
		p.logf("Invalid route history preserved; live learning continues")
		p.cfg.HistoryFile = ""
		return
	}
	if h.Key == p.cfg.HistoryKey {
		p.saved = h.Destinations
	}
}

// SaveHistory snapshots ranking hints only. It never persists sockets, exit
// eligibility, session identity pins, credentials or request payloads.
func (p *Proxy) SaveHistory() error {
	if p.cfg.HistoryFile == "" || p.cfg.HistoryKey == "" {
		return nil
	}
	p.mu.Lock()
	h := savedHistory{Version: 1, Key: p.cfg.HistoryKey, Destinations: map[string]savedDestination{}}
	for key, s := range p.saved {
		h.Destinations[key] = s
	}
	for key, m := range p.mem {
		s := savedDestination{Winner: m.winner, Updated: m.updated, Routes: map[string]savedScore{}}
		for name, score := range m.routes {
			if !score.rejected {
				s.Routes[name] = savedScore{score.wins, score.fails, score.ewmaMS}
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
