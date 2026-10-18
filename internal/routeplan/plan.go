// Package routeplan evaluates methods before a session and stores observations.
// It never starts a background refresh or changes an established session.
package routeplan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Target struct{ ID, Name, URL string }
type Method struct {
	Name     string
	General  bool
	Eligible func(Target) bool
}
type Sample struct {
	Success, Reachable, TLSVerified    bool
	Status                             int
	LatencyMS, TCPMS, TLSMS, BodyBytes int64
	Error                              string
}
type Result struct {
	TargetID   string `json:"target_id"`
	Target     string `json:"target"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	Attempts   int    `json:"attempts"`
	Successes  int    `json:"successes"`
	Responses  int    `json:"responses"`
	MedianMS   int64  `json:"median_ms"`
	JitterMS   int64  `json:"jitter_ms"`
	TCPMS      int64  `json:"tcp_ms"`
	TLSMS      int64  `json:"tls_ms"`
	Status     int    `json:"http_status"`
	Assessment string `json:"assessment"`
	Error      string `json:"error,omitempty"`
}
type Selection struct {
	TargetID   string `json:"target_id"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	Assessment string `json:"assessment"`
	MedianMS   int64  `json:"median_ms"`
	JitterMS   int64  `json:"jitter_ms"`
	Successes  int    `json:"successes"`
	Attempts   int    `json:"attempts"`
}
type Profile struct {
	Version     int         `json:"version"`
	CompletedAt time.Time   `json:"completed_at"`
	TargetsKey  string      `json:"targets_key"`
	Default     string      `json:"default"`
	Selections  []Selection `json:"selections"`
	Rows        []Result    `json:"rows"`
}
type Progress struct {
	Completed, Total      int
	Target, Method, Phase string
}
type Probe func(context.Context, Target, Method) Sample

const Lifetime = 24 * time.Hour

// Calibrate first isolates every eligible method/target pair. Up to three
// responsive finalists per destination receive two further independent trials.
// Only those repeated measurements can elect a stable route.
func Calibrate(ctx context.Context, targets []Target, methods []Method, probe Probe, progress func(Progress)) (*Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(targets) == 0 || len(methods) == 0 || probe == nil {
		return nil, errors.New("targets, methods and a probe are required")
	}
	p := &Profile{Version: 1}
	samples := make(map[int][]Sample)
	completed, total := 0, len(targets)*len(methods)
	report := func(target, method, phase string) {
		if progress != nil {
			progress(Progress{completed, total, target, method, phase})
		}
	}
	run := func(row int, target Target, method Method) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		report(target.Name, method.Name, "testing")
		s := probe(ctx, target, method)
		if err := ctx.Err(); err != nil {
			return err
		}
		samples[row] = append(samples[row], s)
		p.Rows[row] = summarize(p.Rows[row], samples[row])
		completed++
		report(target.Name, method.Name, "testing")
		return nil
	}
	for _, method := range methods {
		for _, target := range targets {
			row := Result{TargetID: target.ID, Target: target.Name, URL: target.URL, Method: method.Name, Assessment: "not_applicable"}
			p.Rows = append(p.Rows, row)
			if method.Eligible != nil && !method.Eligible(target) {
				completed++
				report(target.Name, method.Name, "testing")
				continue
			}
			if err := run(len(p.Rows)-1, target, method); err != nil {
				return nil, err
			}
		}
	}
	finalists := make(map[string][]int)
	for _, target := range targets {
		var rows []int
		for i, row := range p.Rows {
			if row.TargetID == target.ID && row.Responses > 0 {
				rows = append(rows, i)
			}
		}
		sort.SliceStable(rows, func(i, j int) bool { return better(p.Rows[rows[i]], p.Rows[rows[j]]) })
		rows = rows[:min(3, len(rows))]
		finalists[target.ID] = rows
		total += 2 * len(rows)
	}
	methodsByName := make(map[string]Method, len(methods))
	for _, method := range methods {
		methodsByName[method.Name] = method
	}
	for _, target := range targets {
		rows := finalists[target.ID]
		for _, row := range rows {
			for round := 0; round < 2; round++ {
				if err := run(row, target, methodsByName[p.Rows[row].Method]); err != nil {
					return nil, err
				}
			}
		}
		sort.SliceStable(rows, func(i, j int) bool { return better(p.Rows[rows[i]], p.Rows[rows[j]]) })
		selection := Selection{TargetID: target.ID, URL: target.URL, Assessment: "unreachable"}
		if len(rows) > 0 {
			best := p.Rows[rows[0]]
			if best.Responses > 0 {
				selection = Selection{target.ID, target.URL, best.Method, best.Assessment, best.MedianMS, best.JitterMS, best.Successes, best.Attempts}
			}
		}
		p.Selections = append(p.Selections, selection)
	}
	// An unknown destination gets one generic, non-takeover method selected
	// by observed coverage/reliability. It never launches a discovery race.
	bestScore := -1.0
	for _, method := range methods {
		if !method.General {
			continue
		}
		score := 0.0
		repeatedSuccess := false
		for _, row := range p.Rows {
			if row.Method != method.Name || row.Attempts == 0 {
				continue
			}
			score += 1000*float64(row.Successes)/float64(row.Attempts) + 100*float64(row.Responses)/float64(row.Attempts)
			repeatedSuccess = repeatedSuccess || (row.Successes == row.Attempts && row.Attempts >= 3)
			if row.Responses > 0 {
				score -= float64(row.MedianMS+row.JitterMS) / 100000
			}
		}
		if repeatedSuccess && score > 0 && score > bestScore {
			p.Default, bestScore = method.Name, score
		}
	}
	p.CompletedAt = time.Now().UTC()
	report("", "", "complete")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

func summarize(row Result, samples []Sample) Result {
	row.Attempts, row.Successes, row.Responses = len(samples), 0, 0
	var times []int64
	for _, s := range samples {
		row.Status, row.Error, row.TCPMS, row.TLSMS = s.Status, s.Error, s.TCPMS, s.TLSMS
		if s.Reachable && s.TLSVerified && s.Error == "" {
			row.Responses++
			times = append(times, s.LatencyMS)
			if s.Success && s.Status >= 200 && s.Status < 400 {
				row.Successes++
			}
		}
	}
	if len(times) > 0 {
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		row.MedianMS, row.JitterMS = times[len(times)/2], times[len(times)-1]-times[0]
	}
	switch {
	case row.Successes == row.Attempts && row.Attempts >= 3:
		row.Assessment = "https_verified"
	case row.Successes > 0:
		row.Assessment = "intermittent"
	case row.Responses > 0:
		row.Assessment = "service_refused"
	default:
		row.Assessment = "unreachable"
	}
	return row
}

func better(a, b Result) bool {
	aOK, bOK := float64(a.Successes)/float64(max(1, a.Attempts)), float64(b.Successes)/float64(max(1, b.Attempts))
	if aOK != bOK {
		return aOK > bOK
	}
	aResponse, bResponse := float64(a.Responses)/float64(max(1, a.Attempts)), float64(b.Responses)/float64(max(1, b.Attempts))
	if aResponse != bResponse {
		return aResponse > bResponse
	}
	if a.JitterMS != b.JitterMS {
		return a.JitterMS < b.JitterMS
	}
	return a.MedianMS < b.MedianMS
}

func (p *Profile) Fresh(now time.Time) bool {
	return p != nil && p.Version == 1 && !p.CompletedAt.IsZero() && !now.Before(p.CompletedAt) && now.Sub(p.CompletedAt) < Lifetime
}

func profilePath(dir string) (string, error) {
	if !filepath.IsAbs(dir) || filepath.Dir(dir) == dir {
		return "", errors.New("route profiles require an app-private absolute directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("route profile directory is missing or unsafe")
	}
	return filepath.Join(dir, "route-profile.json"), nil
}

func Save(dir string, p *Profile) error {
	path, err := profilePath(dir)
	if err != nil {
		return err
	}
	if p == nil || p.Version != 1 || p.CompletedAt.IsZero() {
		return errors.New("cannot save an incomplete route profile")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".route-profile-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if old, statErr := os.Lstat(path); statErr == nil && (!old.Mode().IsRegular() || old.Mode()&os.ModeSymlink != 0) {
		return errors.New("unsafe route profile file")
	}
	return os.Rename(file.Name(), path)
}

func Load(dir string) (*Profile, error) {
	path, err := profilePath(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 32<<20 {
		return nil, errors.New("unsafe or oversized route profile")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err = json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Version != 1 || p.CompletedAt.IsZero() {
		return nil, fmt.Errorf("unsupported or incomplete route profile")
	}
	return &p, nil
}

func LoadOrTest(ctx context.Context, dir, key string, force bool, now time.Time, run func() (*Profile, error)) (*Profile, bool, error) {
	if !force {
		cached, err := Load(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("route cache needs an explicit manual test: %w", err)
		}
		if cached != nil {
			if now.Before(cached.CompletedAt) {
				return nil, false, errors.New("device clock precedes the cached test; run an explicit manual test")
			}
			if cached.Fresh(now) {
				if cached.TargetsKey != key {
					return nil, false, errors.New("targets or methods changed; disconnect and run the Test button explicitly")
				}
				return cached, true, nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	p, err := run()
	if err != nil {
		return nil, false, err
	}
	if p == nil {
		return nil, false, errors.New("calibration returned no complete profile")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	p.TargetsKey = key
	if err = Save(dir, p); err != nil {
		return nil, false, err
	}
	return p, false, nil
}
