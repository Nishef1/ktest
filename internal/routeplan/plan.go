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
	"sync"
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
	// Totals accumulate earlier tests on the same network and targets
	// (older runs weigh less), so one noisy run cannot flip a selection.
	TotalAttempts  int `json:"total_attempts,omitempty"`
	TotalSuccesses int `json:"total_successes,omitempty"`
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
	// Kept means an earlier test's choice still worked and no other method
	// was clearly better, so it stayed selected.
	Kept bool `json:"kept,omitempty"`
}
type Profile struct {
	Version         int         `json:"version"`
	CompletedAt     time.Time   `json:"completed_at"`
	TargetsKey      string      `json:"targets_key"`
	TargetsRevision string      `json:"targets_revision,omitempty"`
	Default         string      `json:"default"`
	Selections      []Selection `json:"selections"`
	Rows            []Result    `json:"rows"`
	// Network identifies the network the test ran on (an opaque hash);
	// Runs counts the tests merged into this profile.
	Network string `json:"network,omitempty"`
	Runs    int    `json:"runs,omitempty"`
}
type Progress struct {
	Completed, Total      int
	Target, Method, Phase string
}
type Probe func(context.Context, Target, Method) Sample

const Lifetime = 24 * time.Hour

// Calibrate preserves the serial API used by earlier callers and tests.
// Android Balanced uses CalibrateWithWorkers for bounded preconnection work.
func Calibrate(ctx context.Context, targets []Target, methods []Method, probe Probe, progress func(Progress)) (*Profile, error) {
	return CalibrateWithWorkers(ctx, targets, methods, probe, progress, 1)
}

// CalibrateWithWorkers isolates each method/target sample and bounds concurrency.
// Cancellation prevents publishing an incomplete profile; no fallback method is
// silently invented when every HTTP probe is refused.
func CalibrateWithWorkers(ctx context.Context, targets []Target, methods []Method, probe Probe, progress func(Progress), workers int) (*Profile, error) {
	return CalibrateWithPrevious(ctx, targets, methods, probe, progress, workers, nil)
}

// CalibrateWithPrevious also gives each target's previously selected method
// the full repeated measurement, so it is compared with challengers on equal
// terms instead of losing to one lucky sample.
func CalibrateWithPrevious(ctx context.Context, targets []Target, methods []Method, probe Probe, progress func(Progress), workers int, previous *Profile) (*Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(targets) == 0 || len(methods) == 0 || probe == nil || workers < 1 || workers > 8 {
		return nil, errors.New("targets, methods, a probe, and 1..8 workers are required")
	}
	p := &Profile{Version: 1}
	samples := make(map[int][]Sample)
	var mu sync.Mutex
	completed, total := 0, len(targets)*len(methods)
	report := func(target, method, phase string) {
		mu.Lock()
		defer mu.Unlock()
		if progress != nil {
			progress(Progress{completed, total, target, method, phase})
		}
	}
	type task struct {
		row     int
		target  Target
		method  Method
		repeats int
	}
	execute := func(tasks []task) error {
		if len(tasks) == 0 {
			return ctx.Err()
		}
		queue := make(chan task)
		var wg sync.WaitGroup
		for w := 0; w < min(workers, len(tasks)); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for work := range queue {
					for round := 0; round < work.repeats; round++ {
						if ctx.Err() != nil {
							return
						}
						report(work.target.Name, work.method.Name, "testing")
						s := probe(ctx, work.target, work.method)
						if ctx.Err() != nil {
							return
						}
						mu.Lock()
						samples[work.row] = append(samples[work.row], s)
						p.Rows[work.row] = summarize(p.Rows[work.row], samples[work.row])
						completed++
						if progress != nil {
							progress(Progress{completed, total, work.target.Name, work.method.Name, "testing"})
						}
						mu.Unlock()
					}
				}
			}()
		}
		for _, work := range tasks {
			select {
			case queue <- work:
			case <-ctx.Done():
				close(queue)
				wg.Wait()
				return ctx.Err()
			}
		}
		close(queue)
		wg.Wait()
		return ctx.Err()
	}

	var first []task
	for _, method := range methods {
		for _, target := range targets {
			row := len(p.Rows)
			p.Rows = append(p.Rows, Result{TargetID: target.ID, Target: target.Name, URL: target.URL, Method: method.Name, Assessment: "not_applicable"})
			if method.Eligible != nil && !method.Eligible(target) {
				completed++
				report(target.Name, method.Name, "testing")
				continue
			}
			first = append(first, task{row: row, target: target, method: method, repeats: 1})
		}
	}
	if err := execute(first); err != nil {
		return nil, err
	}
	finalists := make(map[string][]int)
	for _, target := range targets {
		var rows []int
		for i, row := range p.Rows {
			// An HTTP refusal is evidence of a reachable service, not a viable route.
			if row.TargetID == target.ID && row.Successes > 0 {
				rows = append(rows, i)
			}
		}
		sort.SliceStable(rows, func(i, j int) bool { return better(p.Rows[rows[i]], p.Rows[rows[j]]) })
		incumbent := -1
		if old := previous.selection(target.ID); old != "" {
			for _, i := range rows {
				if p.Rows[i].Method == old {
					incumbent = i
				}
			}
		}
		rows = rows[:min(3, len(rows))]
		if incumbent >= 0 && !containsInt(rows, incumbent) {
			rows = append(rows, incumbent)
		}
		finalists[target.ID] = rows
		total += 2 * len(rows)
	}
	methodsByName := make(map[string]Method, len(methods))
	for _, method := range methods {
		methodsByName[method.Name] = method
	}
	var repeats []task
	for _, target := range targets {
		for _, row := range finalists[target.ID] {
			repeats = append(repeats, task{row: row, target: target, method: methodsByName[p.Rows[row].Method], repeats: 2})
		}
	}
	if err := execute(repeats); err != nil {
		return nil, err
	}
	for _, target := range targets {
		rows := finalists[target.ID]
		sort.SliceStable(rows, func(i, j int) bool { return better(p.Rows[rows[i]], p.Rows[rows[j]]) })
		selection := Selection{TargetID: target.ID, URL: target.URL, Assessment: "unreachable"}
		if len(rows) > 0 {
			best := p.Rows[rows[0]]
			if best.Assessment == "https_verified" && best.Successes == best.Attempts && best.Attempts >= 3 {
				selection = Selection{target.ID, target.URL, best.Method, best.Assessment, best.MedianMS, best.JitterMS, best.Successes, best.Attempts, false}
			} else {
				selection.Assessment = "no_stable_route"
			}
		}
		p.Selections = append(p.Selections, selection)
	}
	// Unknown sites receive a generic, non-takeover method only when that
	// method demonstrated at least one repeatedly successful HTTPS endpoint.
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

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (p *Profile) selection(targetID string) string {
	if p == nil {
		return ""
	}
	for _, s := range p.Selections {
		if s.TargetID == targetID {
			return s.Method
		}
	}
	return ""
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

// Usable means either an independently tested generic route or at least
// one exact target with repeated HTTPS success. A target-only plan has
// intentionally limited coverage: unknown hosts still fail closed.
func (p *Profile) Usable() bool {
	if p == nil {
		return false
	}
	if p.Default != "" {
		return true
	}
	for _, selection := range p.Selections {
		if selection.Method != "" && selection.Assessment == "https_verified" &&
			selection.Attempts >= 3 && selection.Successes == selection.Attempts {
			return true
		}
	}
	return false
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
	return LoadOrTestWithRevision(ctx, dir, key, "", force, now, run)
}

// An unchanged user target list allows automatic recalibration when a native
// method disappears or returns. Target edits and legacy profiles still require
// an explicit manual test, never silently changing the configured destinations.
func LoadOrTestWithRevision(ctx context.Context, dir, key, targetRevision string, force bool, now time.Time, run func() (*Profile, error)) (*Profile, bool, error) {
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
				if cached.TargetsKey == key && cached.Usable() {
					return cached, true, nil
				}
				// The same targets with an unusable profile simply retest; an
				// empty default must never be reused as if it were a route.
				if cached.TargetsKey != key && (targetRevision == "" || cached.TargetsRevision == "" || cached.TargetsRevision != targetRevision) {
					return nil, false, errors.New("targets changed; disconnect and run the Test button explicitly")
				}
				// Same targets, different available native methods or network:
				// recalibrate with the caller's bounded context instead of deadlocking
				// a connection on a now-missing optional route.
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
	// A new test of the same targets on the same network refines the last
	// one instead of replacing it (see Merge).
	if prev, loadErr := Load(dir); loadErr == nil && prev.TargetsKey == key && !now.Before(prev.CompletedAt) &&
		now.Sub(prev.CompletedAt) < MergeAge && (p.Network == "" || prev.Network == p.Network) {
		p = Merge(prev, p)
	}
	if !p.Usable() {
		return nil, false, errors.New("no target or generic route returned repeated verified HTTPS; unsuccessful observations were not cached")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	p.TargetsKey = key
	p.TargetsRevision = targetRevision
	if err = Save(dir, p); err != nil {
		return nil, false, err
	}
	return p, false, nil
}
