package routeplan

import (
	"context"
	"testing"
	"time"
)

func row(target, method string, ok, attempts int, ms int64) Result {
	return summarize(Result{TargetID: target, Target: target, Method: method}, samples(ok, attempts, ms))
}

func samples(ok, attempts int, ms int64) []Sample {
	var out []Sample
	for i := 0; i < attempts; i++ {
		out = append(out, Sample{Success: i < ok, Reachable: true, TLSVerified: true, Status: 200, LatencyMS: ms})
	}
	return out
}

func profileWith(sel, def string, rows ...Result) *Profile {
	p := &Profile{Version: 1, CompletedAt: time.Now().UTC(), Default: def, Rows: rows}
	for _, r := range rows {
		if r.Method == sel {
			p.Selections = []Selection{{TargetID: r.TargetID, Method: sel, Assessment: "https_verified", Successes: r.Successes, Attempts: r.Attempts}}
		}
	}
	return p
}

func TestMergeKeepsAWorkingChoiceAgainstANoisyChallenger(t *testing.T) {
	prev := profileWith("A", "A", row("t", "A", 3, 3, 400), row("t", "B", 1, 3, 380))
	// This run B happens to win narrowly; A still works every time.
	fresh := profileWith("B", "B", row("t", "A", 3, 3, 420), row("t", "B", 3, 3, 390))
	got := Merge(prev, fresh)
	if got.Selections[0].Method != "A" || !got.Selections[0].Kept || got.Default != "A" {
		t.Fatalf("flipped to a marginal challenger: %+v default %s", got.Selections, got.Default)
	}
	if got.Rows[1].TotalAttempts != 3+3-1 || got.Rows[1].TotalSuccesses != 3+1 {
		t.Fatalf("totals %+v", got.Rows[1])
	}
	if got.Runs != 2 {
		t.Fatalf("runs %d", got.Runs)
	}
}

func TestMergeAdoptsAClearlyFasterOrMoreReliableMethod(t *testing.T) {
	prev := profileWith("A", "", row("t", "A", 3, 3, 900))
	fresh := profileWith("B", "", row("t", "A", 3, 3, 950), row("t", "B", 3, 3, 300))
	if got := Merge(prev, fresh); got.Selections[0].Method != "B" || got.Selections[0].Kept {
		t.Fatalf("faster method not adopted: %+v", got.Selections)
	}
	// The earlier choice failed this run: replace it immediately.
	fresh = profileWith("B", "", row("t", "A", 1, 3, 400), row("t", "B", 3, 3, 500))
	if got := Merge(prev, fresh); got.Selections[0].Method != "B" {
		t.Fatalf("broken method kept: %+v", got.Selections)
	}
}

func TestRepeatedTestsConvergeInsteadOfAlternating(t *testing.T) {
	dir := t.TempDir()
	targets := []Target{{ID: "t", Name: "t", URL: "https://t.example/"}}
	methods := []Method{{Name: "A", General: true}, {Name: "B", General: true}}
	run := 0
	// Two equally good methods whose latencies swap every run.
	probe := func(_ context.Context, _ Target, m Method) Sample {
		ms := int64(400)
		if (m.Name == "A") == (run%2 == 1) {
			ms = 380
		}
		return Sample{Success: true, Reachable: true, TLSVerified: true, Status: 200, LatencyMS: ms}
	}
	var picks []string
	for run = 0; run < 4; run++ {
		p, _, err := LoadOrTestWithRevision(context.Background(), dir, "key", "rev", true, time.Now(), func() (*Profile, error) {
			prev, _ := Load(dir)
			return CalibrateWithPrevious(context.Background(), targets, methods, probe, nil, 1, prev)
		})
		if err != nil {
			t.Fatal(err)
		}
		picks = append(picks, p.Selections[0].Method+"/"+p.Default)
	}
	for _, p := range picks[1:] {
		if p != picks[0] {
			t.Fatalf("selection alternates between tests: %v", picks)
		}
	}
}
