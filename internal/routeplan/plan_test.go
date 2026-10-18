package routeplan

import (
	"context"
	"errors"
	"sync/atomic"
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


func TestCalibrationRejectsOnlyHTTPRefusalsAsSelectedRoute(t *testing.T) {
	p, err := Calibrate(context.Background(),
		[]Target{{ID: "x", Name: "X", URL: "https://x.example/"}},
		[]Method{{Name: "front", General: true}},
		func(context.Context, Target, Method) Sample {
			return Sample{Reachable: true, TLSVerified: true, Status: 403, LatencyMS: 15}
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Selections[0].Method != "" || p.Default != "" || p.Rows[0].Successes != 0 {
		t.Fatalf("HTTP refusal became a frozen winner: %+v", p)
	}
}

func TestConcurrentCalibrationKeepsIndependentSamples(t *testing.T) {
	var inFlight, peak atomic.Int32
	targets := []Target{
		{ID: "a", Name: "A", URL: "https://a.example/"},
		{ID: "b", Name: "B", URL: "https://b.example/"},
	}
	methods := []Method{{Name: "first", General: true}, {Name: "second", General: true}}
	p, err := CalibrateWithWorkers(context.Background(), targets, methods,
		func(context.Context, Target, Method) Sample {
			n := inFlight.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
			inFlight.Add(-1)
			return Sample{Success: true, Reachable: true, TLSVerified: true, Status: 200, LatencyMS: 15}
		}, nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() < 2 || len(p.Selections) != 2 {
		t.Fatalf("bounded parallelism not exercised: peak=%d selections=%+v", peak.Load(), p.Selections)
	}
	for _, row := range p.Rows {
		if row.Attempts != 3 || row.Successes != 3 || row.Assessment != "https_verified" {
			t.Fatalf("parallel calibration lost repeated observations: %+v", row)
		}
	}
}

func TestMethodChangeRecalibratesOnlyIfTargetsUnchanged(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	old := &Profile{Version: 1, CompletedAt: now, TargetsKey: "method-a", TargetsRevision: "targets-v1", Default: "a"}
	if err := Save(dir, old); err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func() (*Profile, error) {
		calls++
		return &Profile{Version: 1, CompletedAt: now, Default: "b"}, nil
	}
	if _, _, err := LoadOrTestWithRevision(context.Background(), dir, "method-b", "targets-v2", false, now, run); err == nil || calls != 0 {
		t.Fatal("edited targets triggered an unauthorized automatic calibration")
	}
	p, reused, err := LoadOrTestWithRevision(context.Background(), dir, "method-b", "targets-v1", false, now, run)
	if err != nil || reused || calls != 1 || p.Default != "b" || p.TargetsRevision != "targets-v1" {
		t.Fatalf("optional method disappearance was not recoverable: profile=%+v, reused=%v, err=%v", p, reused, err)
	}
}

func TestFailedCalibrationCannotOverwriteOrPoisonRouteCache(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	old := &Profile{Version: 1, CompletedAt: now.Add(-25*time.Hour), Default: "old", TargetsKey: "same"}
	if err := Save(dir, old); err != nil { t.Fatal(err) }
	_, _, err := LoadOrTestWithRevision(context.Background(), dir, "same", "v1", false, now, func() (*Profile,error) {
		return &Profile{Version: 1, CompletedAt: now, Rows: []Result{{Assessment:"service_refused"}}}, nil
	})
	if err == nil { t.Fatal("unsuccessful calibration incorrectly became a healthy profile") }
	cached, err := Load(dir)
	if err != nil || cached.Default != "old" { t.Fatalf("failed test overwrote old cache: %+v %v",cached,err) }
}

func TestInvalidFreshProfileRetriesInsteadOfReusingEmptyDefault(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	if err := Save(dir, &Profile{Version:1, CompletedAt:now, TargetsKey:"key", Default:""}); err != nil { t.Fatal(err) }
	calls := 0
	p, reused, err := LoadOrTestWithRevision(context.Background(),dir,"key","",false,now,func()(*Profile,error){
		calls++
		return &Profile{Version:1,CompletedAt:now,Default:"good"},nil
	})
	if err != nil || reused || calls != 1 || p.Default != "good" {
		t.Fatalf("invalid cached route got reused: %+v reused=%v err=%v",p,reused,err)
	}
}
