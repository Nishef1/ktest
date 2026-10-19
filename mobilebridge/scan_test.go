package mobilebridge

import (
	"context"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/probe"
)

func waitCDNScan(t *testing.T) cdnScan {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var state cdnScan
		if err := json.Unmarshal([]byte(CDNScanStatus()), &state); err != nil {
			t.Fatal(err)
		}
		if !state.Running {
			return state
		}
		time.Sleep(time.Millisecond)
	}
	CancelCDNScan()
	t.Fatal("scan did not finish")
	return cdnScan{}
}

func readScanCSV(t *testing.T) [][]string {
	t.Helper()
	path, err := CDNScanExportPath()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestCDNFileScanExportsEntireBudgetAndBoundsStatus(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	if err := startCDNScan("cloudflare", 517, 0, dir, nil,
		func(_ context.Context, cfg probe.Config) (probe.Result, error) {
			n := calls.Add(1)
			return probe.Result{Success: true, Reachable: true, TLSVersion: "TLS 1.3", Status: 204,
				ConnectMS: 7, TLSMS: 11, ElapsedMS: int64(600 - n)}, nil
		}); err != nil {
		t.Fatal(err)
	}
	s := waitCDNScan(t)
	if s.Error != "" || s.Attempted != 517 || s.TotalVerified != 517 || s.Goal != 0 || s.ReachedGoal || s.Unlimited || s.Exhausted {
		t.Fatalf("wrong finite-scan status: %+v", s)
	}
	if len(s.Results) != 100 || len(s.VerifiedHTTP) != 100 || s.Results[0].ElapsedMS != 83 || s.Results[99].ElapsedMS != 182 {
		t.Fatalf("fastest retained results not bounded/ranked: %+v", s.Results)
	}
	path, _ := CDNScanExportPath()
	if s.ExportPath != path || filepath.Ext(path) != ".csv" || !strings.HasPrefix(path, dir+string(filepath.Separator)) {
		t.Fatalf("export is not a private completed CSV: %q", path)
	}
	rows := readScanCSV(t)
	if len(rows) != 518 {
		t.Fatalf("CSV rows=%d, want header + 517 attempts", len(rows))
	}
	indices := map[string]int{}
	for i, name := range rows[0] {
		indices[name] = i
	}
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		ip := row[indices["ip"]]
		if seen[ip] || row[indices["tcp_ms"]] != "7" || row[indices["tls_ms"]] != "11" || row[indices["http_status"]] != "204" || row[indices["http_verified"]] != "true" {
			t.Fatalf("duplicate or lost measurement: %v", row)
		}
		seen[ip] = true
	}
	if got := loadVerifiedCDNEdges(dir, "cloudflare"); !reflect.DeepEqual(got, s.VerifiedHTTP) {
		t.Fatalf("persisted edges=%v want=%v", got, s.VerifiedHTTP)
	}
	if got := loadVerifiedCDNEdges(dir, "akamai"); len(got) != 0 {
		t.Fatalf("cross-provider cache leaked: %v", got)
	}
}

func TestCDNContinuousScanHasNoSessionDeadlineAndExportsCancellation(t *testing.T) {
	dir := t.TempDir()
	ready := make(chan struct{}, 6)
	var calls atomic.Int32
	discover := func(ctx context.Context, provider string, budget int) (edges.Preset, edges.CandidateIterator, error) {
		if _, ok := ctx.Deadline(); ok {
			t.Error("continuous scan has a hidden session deadline")
		}
		return edges.ScanCandidateSource(ctx, provider, budget)
	}
	if err := startCDNScan("cloudflare", 0, 0, dir, discover,
		func(ctx context.Context, _ probe.Config) (probe.Result, error) {
			calls.Add(1)
			ready <- struct{}{}
			<-ctx.Done()
			return probe.Result{Phase: "tcp", ElapsedMS: 30, Error: "context canceled: secret-token raw-response /private/path"}, nil
		}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CancelCDNScan(); waitCDNScan(t) })
	for range 6 {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("requests did not start")
		}
	}
	if path, err := CDNScanExportPath(); err == nil || path != "" {
		t.Fatalf("partial export exposed: %s %v", path, err)
	}
	var before, after cdnScan
	json.Unmarshal([]byte(CDNScanStatus()), &before)
	time.Sleep(25 * time.Millisecond)
	json.Unmarshal([]byte(CDNScanStatus()), &after)
	if after.ElapsedMS <= before.ElapsedMS || after.Attempted != 0 || !after.Unlimited || after.ExportPath != "" {
		t.Fatalf("idle elapsed/status did not advance: %+v -> %+v", before, after)
	}
	if err := StartCDNScanToFile("cloudflare", 10, dir); err == nil {
		t.Fatal("overlapping scan accepted")
	}
	CancelCDNScan()
	s := waitCDNScan(t)
	if !s.Canceled || s.Running || s.Exhausted || s.Error != "" || s.Attempted != 6 || calls.Load() != 6 {
		t.Fatalf("bad canceled snapshot: %+v", s)
	}
	rows := readScanCSV(t)
	if len(rows) != 7 {
		t.Fatalf("inflight canceled measurements lost: %v", rows)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw)+CDNScanStatus(), "secret-token") || strings.Contains(string(raw), "raw-response") || strings.Contains(string(raw), "/private/path") {
		t.Fatal("raw diagnostic content escaped")
	}
}

func TestCDNRealSmallInventoryExhaustsWithoutFalseGreen(t *testing.T) {
	var calls atomic.Int32
	dir := t.TempDir()
	// A finite eight-address inventory makes exhaustion observable.
	small := func(context.Context, string, int) (edges.Preset, edges.CandidateIterator, error) {
		ips := []string{"23.12.147.13", "23.12.147.29", "23.73.207.8", "23.212.250.78", "23.212.250.91", "23.215.0.203", "23.215.0.206", "92.123.102.43"}
		return edges.Preset{Provider: "akamai", URL: "https://a248.e.akamai.net/", Source: "test inventory"}, func(ctx context.Context) (string, bool, error) {
			if len(ips) == 0 {
				return "", false, ctx.Err()
			}
			ip := ips[0]
			ips = ips[1:]
			return ip, true, nil
		}, nil
	}
	if err := startCDNScan("akamai", 0, 0, dir, small,
		func(_ context.Context, _ probe.Config) (probe.Result, error) {
			switch calls.Add(1) {
			case 1:
				return probe.Result{Phase: "tls", Reachable: true}, nil
			case 2:
				return probe.Result{TLSVersion: "TLS 1.3", Status: 421}, nil
			case 3:
				return probe.Result{Success: true, Status: 200}, nil
			case 4:
				return probe.Result{Success: true, TLSVersion: "TLS 1.3", Status: 200, Error: "body failed secret-content"}, nil
			case 5:
				return probe.Result{}, errors.New("sensitive /private/folder secret-content")
			default:
				return probe.Result{TLSVersion: "TLS 1.3", Status: 503}, nil
			}
		}); err != nil {
		t.Fatal(err)
	}
	s := waitCDNScan(t)
	if !s.Exhausted || !s.Unlimited || s.Attempted != 8 || s.TotalVerified != 0 || len(s.VerifiedHTTP) != 0 || s.Budget != 0 || len(s.Results) != 8 {
		t.Fatalf("false green/invented inventory: %+v", s)
	}
	for _, r := range s.Results {
		if r.HTTPVerified || r.Assessment == "provider_https_verified" {
			t.Fatalf("false green: %+v", r)
		}
	}
	if len(readScanCSV(t)) != 9 || len(loadVerifiedCDNEdges(dir, "akamai")) != 0 {
		t.Fatal("failed attempts missing or cached as verified")
	}
	if strings.Contains(CDNScanStatus(), "secret-content") {
		t.Fatal("raw error leaked into status")
	}
}

func TestCDNRecentFailuresAreBoundedButAllExported(t *testing.T) {
	if err := startCDNScan("cloudflare", 401, 0, t.TempDir(), nil,
		func(_ context.Context, _ probe.Config) (probe.Result, error) {
			return probe.Result{Error: "connection refused"}, nil
		}); err != nil {
		t.Fatal(err)
	}
	s := waitCDNScan(t)
	if s.Attempted != 401 || len(s.Results) != 20 || s.TotalVerified != 0 || len(readScanCSV(t)) != 402 {
		t.Fatalf("failed-attempt retention/export mismatch: %+v", s)
	}
}

func TestCDNFileAPIRejectsUnsafeDirectoryBeforeNetwork(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	for _, dir := range []string{"", ".", "relative/path", root, filepath.Join(t.TempDir(), "missing")} {
		if err := StartCDNScanToFile("cloudflare", 30, dir); err == nil {
			CancelCDNScan()
			t.Fatalf("unsafe directory accepted: %q", dir)
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := StartCDNScanToFile("cloudflare", 30, file); err == nil {
		t.Fatal("regular file accepted as directory")
	}
	for _, tc := range []struct {
		p string
		b int
	}{{"unknown", 30}, {"cloudflare", -1}} {
		if err := StartCDNScanToFile(tc.p, tc.b, dir); err == nil {
			t.Fatal("invalid scan input accepted")
		}
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, link); err == nil {
		if err := StartCDNScanToFile("cloudflare", 30, link); err == nil {
			t.Fatal("symlink directory accepted")
		}
		child := filepath.Join(dir, "child")
		os.Mkdir(child, 0700)
		if err := StartCDNScanToFile("cloudflare", 30, filepath.Join(link, "child")); err == nil {
			t.Fatal("symlink ancestor accepted")
		}
	} else {
		t.Logf("symlink checks unavailable: %v", err)
	}
}

func TestCDNFileScanMeasuresRealTLSHTTPWithoutTrustBypass(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	root := x509.NewCertPool()
	root.AddCert(server.Certificate())
	local, _ := url.Parse(server.URL)
	for _, trusted := range []bool{true, false} {
		dir := t.TempDir()
		if err := startCDNScan("cloudflare", 1, 0, dir, nil,
			func(ctx context.Context, cfg probe.Config) (probe.Result, error) {
				// Only the network destination/trust fixture changes. Probe.Run
				// and the actual scan, recorder, status, and CSV remain real.
				if cfg.URL != "https://www.cloudflare.com/cdn-cgi/trace" || cfg.ConnectAddr == "" {
					t.Errorf("provider probe was not bound: %+v", cfg)
				}
				cfg.URL, cfg.ConnectAddr = server.URL, local.Host
				if trusted {
					cfg.RootCAs = root
				}
				return probe.Run(ctx, cfg)
			}); err != nil {
			t.Fatal(err)
		}
		s := waitCDNScan(t)
		if s.Attempted != 1 || len(s.Results) != 1 || len(readScanCSV(t)) != 2 {
			t.Fatalf("real observation lost: %+v", s)
		}
		r := s.Results[0]
		if trusted {
			if !r.TLSVerified || !r.HTTPVerified || r.HTTPStatus != 204 || r.ElapsedMS < 15 || r.TCPMS < 0 || r.TLSMS < 0 || r.Assessment != "provider_https_verified" {
				t.Fatalf("real TLS/HTTP timings not recorded: %+v", r)
			}
		} else if r.TLSVerified || r.HTTPVerified || s.TotalVerified != 0 || r.Error != "certificate verification failed" {
			t.Fatalf("untrusted TLS was falsely green: %+v", r)
		}
	}
}

func TestCDNExportIsUnavailableAfterSnapshotDisappears(t *testing.T) {
	if err := startCDNScan("akamai", 1, 0, t.TempDir(), nil, func(context.Context, probe.Config) (probe.Result, error) { return probe.Result{}, nil }); err != nil {
		t.Fatal(err)
	}
	waitCDNScan(t)
	path, err := CDNScanExportPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if path, err := CDNScanExportPath(); err == nil || path != "" {
		t.Fatalf("missing snapshot returned: %q %v", path, err)
	}
}

func TestCDNScanSnapshotDoesNotPublishOnStorageFailure(t *testing.T) {
	dir := t.TempDir()
	ready, release := make(chan struct{}), make(chan struct{})
	if err := startCDNScan("cloudflare", 1, 0, dir, nil, func(context.Context, probe.Config) (probe.Result, error) {
		close(ready)
		<-release
		return probe.Result{Error: "connection refused"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	<-ready
	files, err := filepath.Glob(filepath.Join(dir, "cdn-scans", "scan-*.partial"))
	if err != nil || len(files) != 1 {
		t.Fatalf("partial export missing: %v %v", files, err)
	}
	// A directory at the unique snapshot filename makes finalization fail on
	// every platform, without disk-full devices or replacing the CSV writer.
	blocked := strings.TrimSuffix(files[0], ".partial") + ".csv"
	if err := os.Mkdir(blocked, 0700); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	s := waitCDNScan(t)
	if s.Error == "" || s.ExportPath != "" {
		t.Fatalf("failed snapshot published: %+v", s)
	}
	if path, err := CDNScanExportPath(); err == nil || path != "" {
		t.Fatalf("failed export returned: %q %v", path, err)
	}
	if _, err := os.Stat(files[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed partial file left behind: %v", err)
	}
}

func TestCDNCancellationDoesNotHideCacheWriteFailure(t *testing.T) {
	dir := t.TempDir()
	storage, err := cdnPrivateDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(storage, "verified-cloudflare.json"), 0700); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	if err := startCDNScan("cloudflare", 0, 0, dir, nil, func(ctx context.Context, _ probe.Config) (probe.Result, error) {
		if calls.Add(1) == 1 {
			return probe.Result{Success: true, TLSVersion: "TLS 1.3", Status: 200}, nil
		}
		<-ctx.Done()
		return probe.Result{Error: "context canceled"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CancelCDNScan(); waitCDNScan(t) })
	deadline := time.Now().Add(time.Second)
	for {
		var s cdnScan
		json.Unmarshal([]byte(CDNScanStatus()), &s)
		if s.TotalVerified == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("verified request not observed")
		}
		time.Sleep(time.Millisecond)
	}
	CancelCDNScan()
	s := waitCDNScan(t)
	if !s.Canceled || s.Error == "" || s.ExportPath == "" {
		t.Fatalf("cancellation hid cache persistence failure: %+v", s)
	}
}
