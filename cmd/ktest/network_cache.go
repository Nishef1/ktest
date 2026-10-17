package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const networkCacheTTL = 24 * time.Hour

var networkCacheMu sync.Mutex

// Measurements are hints. Every new process still validates the live tunnel
// and the current exit before any protected traffic can use it.
type aetherMeasurement struct {
	ID             string    `json:"id"`
	Label          string    `json:"label"`
	Method         string    `json:"method"`
	Checked        time.Time `json:"checked"`
	State          string    `json:"state"`
	Attempts       int       `json:"attempts"`
	Successes      int       `json:"successes"`
	LatencyMS      float64   `json:"latency_ms,omitempty"`
	BytesPerSecond float64   `json:"bytes_per_second,omitempty"`
	ExitIP         string    `json:"exit_ip,omitempty"`
	Country        string    `json:"country,omitempty"`
	Failure        string    `json:"failure,omitempty"`
}

type networkProfile struct {
	Updated time.Time                    `json:"updated"`
	Core    string                       `json:"core"`
	Results map[string]aetherMeasurement `json:"results"`
}
type networkCache struct {
	Version  int                       `json:"version"`
	Networks map[string]networkProfile `json:"networks"`
}

func networkCacheFile() string { return filepath.Join(warpDir(), "network-measurements.json") }

func coreFingerprint(base string) string {
	f, err := os.Open(aetherBinary(base))
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func networkSignature(ctx context.Context) string {
	if key := os.Getenv("KTEST_NETWORK_ID"); key != "" {
		sum := sha256.Sum256([]byte(key))
		return hex.EncodeToString(sum[:16])
	}
	if ctx.Err() != nil {
		return ""
	}
	facts := networkFacts()
	if len(facts) == 0 {
		return ""
	}
	sort.Strings(facts)
	sum := sha256.Sum256([]byte(strings.Join(facts, "\n")))
	return hex.EncodeToString(sum[:16])
}

func readNetworkCache() (networkCache, error) {
	c := networkCache{Version: 1, Networks: map[string]networkProfile{}}
	f, err := os.Open(networkCacheFile())
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return c, err
	}
	if len(data) > 4<<20 {
		return c, errors.New("network cache exceeds size limit; file kept")
	}
	if err = json.Unmarshal(data, &c); err != nil || c.Version != 1 || c.Networks == nil {
		return networkCache{}, errors.New("invalid network cache; file kept")
	}
	return c, nil
}

func cachedNetwork(key, core string) (networkProfile, error) {
	networkCacheMu.Lock()
	defer networkCacheMu.Unlock()
	c, err := readNetworkCache()
	if err != nil {
		return networkProfile{}, err
	}
	p := c.Networks[key]
	if key == "" || core == "" || p.Core != core || time.Since(p.Updated) > networkCacheTTL || time.Until(p.Updated) > time.Minute {
		return networkProfile{}, nil
	}
	return p, nil
}

func saveMeasurement(key, core string, result aetherMeasurement) error {
	if key == "" || core == "" {
		return nil
	}
	networkCacheMu.Lock()
	defer networkCacheMu.Unlock()
	c, err := readNetworkCache()
	if err != nil {
		return err
	}
	p := c.Networks[key]
	if p.Core != core || p.Results == nil {
		p = networkProfile{Core: core, Results: map[string]aetherMeasurement{}}
	}
	p.Updated = time.Now()
	p.Results[result.ID] = result
	c.Networks[key] = p
	if len(c.Networks) > 16 {
		oldest := ""
		var at time.Time
		for k, v := range c.Networks {
			if k != key && (oldest == "" || v.Updated.Before(at)) {
				oldest, at = k, v.Updated
			}
		}
		delete(c.Networks, oldest)
	}
	return saveJSONFile(networkCacheFile(), c)
}

func measurementScore(r aetherMeasurement, mode ConnectionMode) float64 {
	carrierAllowed := mode == ModeWindscribeAether || mode == ModeFast || mode == ModeBalanced
	if (r.State != "verified" && !(carrierAllowed && r.State == "carrier")) || r.Attempts == 0 || r.Successes == 0 || r.LatencyMS <= 0 || (mode != ModeWindscribeAether && r.Successes < 2) {
		return 1e15
	}
	parse := parseForeignTrace
	if carrierAllowed && r.State == "carrier" {
		parse = parseExitTrace
	}
	if _, _, err := parse("ip=" + r.ExitIP + "\nloc=" + r.Country); err != nil {
		return 1e15
	}
	penalty := 1 - float64(r.Successes)/float64(r.Attempts)
	weight := 2000.0
	if mode == ModeFast {
		weight = 500
	}
	score := r.LatencyMS + penalty*weight
	if mode == ModeFast && r.BytesPerSecond > 0 {
		score /= 1 + min(2.0, r.BytesPerSecond/(1<<20))
	}
	return score
}

func measuredProfilesFirst(profiles []aetherProfile, history networkProfile, mode ConnectionMode) []aetherProfile {
	ordered := append([]aetherProfile(nil), profiles...)
	score := func(p aetherProfile) float64 {
		r, ok := history.Results[p.id()]
		if !ok || time.Since(r.Checked) > networkCacheTTL || time.Until(r.Checked) > time.Minute {
			return 1e12
		}
		if r.State != "verified" && r.State != "carrier" && time.Since(r.Checked) > 10*time.Minute {
			return 1e12
		}
		return measurementScore(r, mode)
	}
	sort.SliceStable(ordered, func(i, j int) bool { return score(ordered[i]) < score(ordered[j]) })
	// Mixed modes need both an ordinary-site winner and an AI-capable exit.
	if (mode == ModeFast || mode == ModeBalanced) && len(ordered) > 1 && history.Results[ordered[0].id()].State == "carrier" {
		for i := 1; i < len(ordered); i++ {
			if r := history.Results[ordered[i].id()]; r.State == "verified" && score(ordered[i]) < 1e12 {
				p := ordered[i]
				copy(ordered[2:i+1], ordered[1:i])
				ordered[1] = p
				break
			}
		}
	}
	return ordered
}

func printNetworkRecommendations(u *term, key, core string, profiles []aetherProfile) {
	history, err := cachedNetwork(key, core)
	if err != nil {
		u.Line(toneWarn, "Saved diagnosis unavailable: %v", err)
		return
	}
	if len(history.Results) == 0 {
		u.Note("No fresh diagnosis for this network/core. Run Diagnose > Aether comparison.")
		return
	}
	u.Note("Last network measurement: %s · cached ranking only; live exit verification is required", history.Updated.UTC().Format(time.RFC3339))
	for _, mode := range []ConnectionMode{ModeFast, ModeBalanced, ModeAether, ModeWindscribeAether} {
		eligible := profilesForMode(profiles, mode)
		ordered := measuredProfilesFirst(eligible, history, mode)
		if len(ordered) > 0 {
			r, ok := history.Results[ordered[0].id()]
			if ok && measurementScore(r, mode) < 1e12 {
				u.Line(toneInfo, "%s: %s · %.0fms · %d/%d samples · observed %s (%s)", mode, ordered[0].Label, r.LatencyMS, r.Successes, r.Attempts, r.ExitIP, r.Country)
			}
		}
	}
	u.Note("IP/country are neutral-probe observations, not a fixed IP promised for every website.")
}

func measurementFor(p aetherProfile) aetherMeasurement {
	return aetherMeasurement{ID: p.id(), Label: p.Label, Method: p.method(), Checked: time.Now(), State: "failed"}
}

func (r aetherMeasurement) detail() string {
	if r.State != "verified" && r.State != "carrier" {
		return r.State + ": " + r.Failure
	}
	s := fmt.Sprintf("%.0fms · %d/%d samples · observed %s (%s)", r.LatencyMS, r.Successes, r.Attempts, r.ExitIP, r.Country)
	if r.State == "carrier" {
		s += " · AI blocked on this carrier"
	}
	if r.BytesPerSecond > 0 {
		s += fmt.Sprintf(" · %.0f KiB/s small-transfer sample", r.BytesPerSecond/1024)
	}
	return s
}
