package routeplan

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCalibrationTestsEveryEligiblePairAndChoosesStableRoute(t *testing.T) {
	targets := []Target{{ID: "x", Name: "X", URL: "https://api.example.org/"}}
	counts := map[string]int{}
	methods := []Method{{Name: "fast-flaky", General: true}, {Name: "stable", General: true}, {Name: "unsupported", Eligible: func(Target) bool { return false }}}
	p, err := Calibrate(context.Background(), targets, methods, func(_ context.Context, target Target, method Method) Sample {
		counts[method.Name]++
		if method.Name == "fast-flaky" && counts[method.Name] > 1 {
			return Sample{Error: "response stalled"}
		}
		latency := int64(80)
		if method.Name == "fast-flaky" {
			latency = 5
		}
		return Sample{Success: true, Reachable: true, TLSVerified: true, Status: 200, LatencyMS: latency, BodyBytes: 128}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || len(p.Selections) != 1 || p.Selections[0].Method != "stable" {
		t.Fatalf("selected speed without stability: %+v", p)
	}
	if counts["fast-flaky"] != 3 || counts["stable"] != 3 || counts["unsupported"] != 0 {
		t.Fatalf("initial method isolation or stability rounds missing: %v", counts)
	}
}

func TestRefusedServiceIsNotReportedAsOpened(t *testing.T) {
	p, err := Calibrate(context.Background(), []Target{{ID: "x", URL: "https://example.org/"}}, []Method{{Name: "route", General: true}},
		func(context.Context, Target, Method) Sample {
			return Sample{Reachable: true, TLSVerified: true, Status: 451, LatencyMS: 30}
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || len(p.Rows) != 1 || p.Rows[0].Successes != 0 || p.Rows[0].Assessment != "service_refused" {
		t.Fatalf("service refusal became a green site: %+v", p)
	}
}

func TestProfilePersistsForTwentyFourHoursWithoutRetesting(t *testing.T) {
	completed := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	p := &Profile{Version: 1, CompletedAt: completed, Default: "fixed", TargetsKey: "targets-v1"}
	dir := t.TempDir()
	if err := Save(dir, p); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Fresh(completed.Add(24*time.Hour-time.Nanosecond)) || loaded.Fresh(completed.Add(24*time.Hour)) {
		t.Fatal("profile did not honor its 24-hour boundary")
	}
	if loaded.Default != "fixed" || loaded.TargetsKey != "targets-v1" {
		t.Fatal("stored selection changed")
	}
}

func TestCanceledCalibrationNeverProducesACompleteProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err := Calibrate(ctx, []Target{{ID: "x", URL: "https://example.org/"}}, []Method{{Name: "route"}},
		func(context.Context, Target, Method) Sample {
			t.Fatal("canceled work probed a target")
			return Sample{}
		}, nil)
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled results became reusable: %+v %v", p, err)
	}
}

func TestFreshCacheDoesNotProbeAndChangedTargetsRequireManualTest(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	if err := Save(dir, &Profile{Version: 1, CompletedAt: now, TargetsKey: "same", Default: "cached"}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func() (*Profile, error) {
		calls++
		return &Profile{Version: 1, CompletedAt: now, TargetsKey: "same", Default: "new"}, nil
	}
	p, reused, err := LoadOrTest(context.Background(), dir, "same", false, now.Add(23*time.Hour), run)
	if err != nil || !reused || p.Default != "cached" || calls != 0 {
		t.Fatalf("cached connection launched tests: calls=%d reused=%v err=%v", calls, reused, err)
	}
	if _, _, err := LoadOrTest(context.Background(), dir, "changed", false, now.Add(time.Hour), run); err == nil || calls != 0 {
		t.Fatal("target edit bypassed the manual-test requirement")
	}
	if _, _, err := LoadOrTest(context.Background(), dir, "same", true, now.Add(time.Hour), run); err != nil || calls != 1 {
		t.Fatal("explicit manual retest was blocked")
	}
}

func TestDefaultNeedsRepeatedSuccessfulHTTPSNotJustARefusal(t *testing.T) {
	p, err := Calibrate(context.Background(), []Target{{ID: "x", URL: "https://example.org/"}}, []Method{{Name: "blocked", General: true}},
		func(context.Context, Target, Method) Sample {
			return Sample{Reachable: true, TLSVerified: true, Status: 403}
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Default != "" {
		t.Fatalf("a service refusal became the generic connected route: %s", p.Default)
	}
}

func TestIncompleteRunCannotReplaceCachedProfile(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrTest(context.Background(), dir, "new", true, time.Now(), func() (*Profile, error) { return nil, nil }); err == nil {
		t.Fatal("nil calibration result was accepted")
	}
}

func TestCancelAtCompletionDoesNotPublishAReusableProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := Calibrate(ctx, []Target{{ID: "x", URL: "https://example.org/"}}, []Method{{Name: "route", General: true}},
		func(context.Context, Target, Method) Sample {
			return Sample{Success: true, Reachable: true, TLSVerified: true, Status: 200}
		}, func(progress Progress) {
			if progress.Phase == "complete" {
				cancel()
			}
		})
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation at completion produced a reusable profile: %+v, %v", p, err)
	}
}
