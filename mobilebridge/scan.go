package mobilebridge

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/probe"
)

type cdnScanResult = edges.ScanResult

type cdnScan struct {
	Running       bool            `json:"running"`
	Canceled      bool            `json:"canceled"`
	Attempted     int             `json:"attempted"`
	Budget        int             `json:"budget"`
	Goal          int             `json:"goal"`
	VerifiedHTTP  []string        `json:"verified_http"`
	ReachedGoal   bool            `json:"reached_goal"`
	ElapsedMS     int64           `json:"elapsed_ms"`
	Error         string          `json:"error,omitempty"`
	Note          string          `json:"note"`
	Provider      string          `json:"provider"`
	Family        string          `json:"family"`
	Source        string          `json:"source,omitempty"`
	Results       []cdnScanResult `json:"results"`
	TotalVerified int             `json:"total_verified"`
	Unlimited     bool            `json:"unlimited"`
	Exhausted     bool            `json:"exhausted"`
	ExportPath    string          `json:"export_path"`
}

var scanMu sync.Mutex
var scanState cdnScan
var scanCancel context.CancelFunc
var scanStarted time.Time

// StartCDNScan preserves the original explicit success-goal API. Goal zero
// scans the entire budget; budget zero scans until cancellation or exhaustion.
func StartCDNScan(budget, goal int) error {
	return StartCDNScanForProvider("cloudflare", budget, goal)
}

func StartCDNScanForProvider(provider string, budget, goal int) error {
	return StartCDNScanForProviderFamily(provider, "ipv4", budget, goal)
}

func StartCDNScanForProviderFamily(provider, family string, budget, goal int) error {
	if !proxyStartMu.TryLock() {
		return errors.New("disconnect or finish startup before scanning CDN routes")
	}
	defer proxyStartMu.Unlock()
	if routeWorkActive() {
		return errors.New("disconnect before scanning CDN routes")
	}
	return startCDNScan(provider, budget, goal, "", nil, nil, family)
}

// StartCDNScanToFile streams all started attempts to an app-private CSV. Budget
// zero removes the count limit, with no session deadline or success cap. Android
// must copy the completed snapshot through its document save picker. It does not
// change routing: provider HTTPS is not proof of fronting to another target.
func StartCDNScanToFile(provider string, budget int, privateFilesDir string) error {
	return StartCDNScanToFileFamily(provider, "ipv4", budget, privateFilesDir)
}

// StartCDNScanToFileFamily scans only the selected IP family. IPv6 mode does
// not silently fall back to IPv4, so the result remains useful for dual-stack
// firewall diagnosis.
func StartCDNScanToFileFamily(provider, family string, budget int, privateFilesDir string) error {
	if !proxyStartMu.TryLock() {
		return errors.New("disconnect or finish startup before scanning CDN routes")
	}
	defer proxyStartMu.Unlock()
	if routeWorkActive() {
		return errors.New("disconnect before scanning CDN routes")
	}
	if privateFilesDir == "" {
		return errors.New("scan export needs an absolute private files directory")
	}
	return startCDNScan(provider, budget, 0, privateFilesDir, nil, nil, family)
}

type cdnScanSource func(context.Context, string, int) (edges.Preset, edges.CandidateIterator, error)

func startCDNScan(provider string, budget, goal int, privateDir string, discover cdnScanSource, runner edges.Runner, familyOption ...string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	family := "ipv4"
	if len(familyOption) > 0 {
		family = strings.ToLower(strings.TrimSpace(familyOption[0]))
	}
	if family != "ipv4" && family != "ipv6" {
		return errors.New("IP family must be ipv4 or ipv6")
	}
	if !cdnProvider(provider) {
		return errors.New("choose " + strings.Join(cdnranges.Providers, ", "))
	}
	if budget < 0 || goal < 0 || (budget > 0 && goal > budget) {
		return errors.New("budget and goal must be nonnegative; goal must not exceed a finite budget")
	}
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanState.Running {
		return errors.New("a CDN scan is already running")
	}
	var file *os.File
	var writer *csv.Writer
	var dir string
	if privateDir != "" {
		var err error
		dir, err = cdnPrivateDirectory(privateDir)
		if err != nil {
			return err
		}
		file, err = os.CreateTemp(dir, "scan-*.partial")
		if err != nil {
			return errors.New("cannot create private scan export")
		}
		writer = csv.NewWriter(file)
		_ = writer.Write([]string{"ip", "tcp_ms", "tls_ms", "elapsed_ms", "http_status", "tls_verified", "http_verified", "assessment", "error"})
		writer.Flush()
		if writer.Error() != nil {
			file.Close()
			os.Remove(file.Name())
			return errors.New("cannot write private scan export")
		}
	}
	if discover == nil {
		discover = func(ctx context.Context, provider string, budget int) (edges.Preset, edges.CandidateIterator, error) {
			return edges.ScanCandidateSourceFamily(ctx, provider, budget, family)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	scanCancel, scanStarted = cancel, time.Now()
	note := "Verified HTTPS to the provider's test host only; target fronting, VPN access, and DNS resolver functionality remain unverified. Discovery/DNS and HTTPS can be blocked independently."
	if family == "ipv6" {
		note += " IPv6-only scan: the device needs a working IPv6 route; no IPv4 fallback is attempted."
	}
	scanState = cdnScan{Running: true, Budget: budget, Goal: goal, Provider: provider, Family: family, Unlimited: budget == 0,
		VerifiedHTTP: []string{}, Results: []cdnScanResult{}, Note: note}
	go runCDNScan(ctx, cancel, provider, family, budget, goal, dir, file, writer, discover, runner)
	return nil
}

func runCDNScan(ctx context.Context, cancel context.CancelFunc, provider, family string, budget, goal int, dir string, file *os.File, writer *csv.Writer, discover cdnScanSource, runner edges.Runner) {
	defer cancel()
	if file != nil {
		defer func() { file.Close(); os.Remove(file.Name()) }()
	}
	preset, next, err := discover(ctx, provider, budget)
	var out edges.ScanOutcome
	var best, recent []cdnScanResult
	writeFailed := false
	cacheFailed := false
	failure := ""
	if err != nil {
		if family == "ipv6" {
			failure = "provider IPv6 inventory unavailable"
		} else {
			failure = "provider candidate discovery failed"
		}
	} else {
		scanMu.Lock()
		scanState.Source = preset.Source
		scanMu.Unlock()
		out, err = edges.ScanCDNStream(ctx, next, preset.URL, goal, runner,
			func(ip string, r probe.Result, attempted, verified int) {
				record := cdnResult(ip, r)
				if writer != nil && !writeFailed {
					_ = writer.Write([]string{record.IP, strconv.FormatInt(record.TCPMS, 10), strconv.FormatInt(record.TLSMS, 10),
						strconv.FormatInt(record.ElapsedMS, 10), strconv.Itoa(record.HTTPStatus), strconv.FormatBool(record.TLSVerified),
						strconv.FormatBool(record.HTTPVerified), record.Assessment, record.Error})
					writer.Flush()
					if writer.Error() != nil {
						writeFailed = true
						cancel()
					}
				}
				if record.HTTPVerified {
					best = append(best, record)
					sort.Slice(best, func(i, j int) bool {
						if best[i].ElapsedMS != best[j].ElapsedMS {
							return best[i].ElapsedMS < best[j].ElapsedMS
						}
						return best[i].IP < best[j].IP
					})
					if len(best) > 100 {
						best = best[:100]
					}
				} else {
					recent = append(recent, record)
					if len(recent) > 20 {
						recent = recent[len(recent)-20:]
					}
				}
				scanMu.Lock()
				defer scanMu.Unlock()
				scanState.Attempted, scanState.TotalVerified = attempted, verified
				scanState.Results = append(append([]cdnScanResult{}, best...), recent...)
				scanState.VerifiedHTTP = make([]string, len(best))
				for i, r := range best {
					scanState.VerifiedHTTP[i] = r.IP
				}
			})
		if err != nil {
			failure = "scan interrupted"
		}
	}
	path := ""
	if file != nil {
		writer.Flush()
		if writer.Error() != nil || file.Sync() != nil {
			writeFailed = true
		}
		if file.Close() != nil {
			writeFailed = true
		}
		if !writeFailed {
			path = strings.TrimSuffix(file.Name(), ".partial") + ".csv"
			if os.Rename(file.Name(), path) != nil {
				writeFailed = true
				path = ""
			}
		}
	}
	if writeFailed {
		failure = "could not complete private scan export"
	}
	if dir != "" && len(best) > 0 && !writeFailed {
		if saveVerifiedCDNEdges(dir, edges.VerifiedCache{Provider: provider, Source: preset.Source, VerifiedAt: time.Now().UTC(), Results: best}) != nil {
			cacheFailed = true
			failure = "scan finished but verified provider edges could not be saved"
		}
	}
	if file != nil {
		os.Remove(file.Name())
	}
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanState.Canceled && errors.Is(err, context.Canceled) && !writeFailed && !cacheFailed {
		failure = ""
	}
	scanState.Running, scanState.Error, scanState.ExportPath = false, failure, path
	scanState.ElapsedMS = time.Since(scanStarted).Milliseconds()
	scanState.ReachedGoal = out.ReachedGoal
	scanState.Exhausted = out.Exhausted && !scanState.Canceled && (budget == 0 || out.Attempted < budget || preset.InventorySize <= budget)
	scanCancel = nil
}

// cdnResult copies only measurements and fixed error categories, never response
// content, headers, resolver diagnostics, URLs, or raw filesystem error text.
func cdnResult(ip string, r probe.Result) cdnScanResult { return edges.ResultOf(ip, r) }

func cdnProvider(p string) bool {
	return cdnranges.Known(p)
}

func realPrivateDirectory(dir string) bool {
	if !filepath.IsAbs(dir) {
		return false
	}
	dir = filepath.Clean(dir)
	if filepath.Dir(dir) == dir {
		return false
	}
	// An arbitrary symlink in any caller-controlled ancestor would permit
	// scans to write outside private storage. Android may expose the platform
	// /data/user/0 alias; that known OS-owned mapping is the only exception.
	for p := dir; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if runtime.GOOS != "android" || p != "/data/user/0" && p != "/data/user" {
				return false
			}
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return true
}
func cdnPrivateDirectory(privateDir string) (string, error) {
	if !realPrivateDirectory(privateDir) {
		return "", errors.New("scan storage requires a real absolute private directory leaf, not a symlink or filesystem root")
	}
	dir := filepath.Join(privateDir, "cdn-scans")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", errors.New("cannot create private scan directory")
	}
	if !realPrivateDirectory(dir) {
		return "", errors.New("scan storage directory is not a real private directory")
	}
	return dir, nil
}

func CDNScanStatus() string {
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanState.Running {
		scanState.ElapsedMS = time.Since(scanStarted).Milliseconds()
	}
	raw, _ := json.Marshal(scanState)
	return string(raw)
}

// CDNScanExportPath returns only a completed app-private CSV snapshot, including
// a manually canceled scan. Android owns the document-picker copy operation.
func CDNScanExportPath() (string, error) {
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanState.Running {
		return "", errors.New("scan export is unavailable while scanning")
	}
	path := scanState.ExportPath
	info, err := os.Lstat(path)
	if path == "" || err != nil || !info.Mode().IsRegular() || !realPrivateDirectory(filepath.Dir(path)) {
		return "", errors.New("no completed scan export is available")
	}
	return path, nil
}

func CancelCDNScan() {
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanCancel != nil {
		scanState.Canceled = true
		scanCancel()
	}
}

// saveVerifiedCDNEdges keeps Android's network-independent cache; the shared
// edges package applies the same rules as the desktop's per-network one.
func saveVerifiedCDNEdges(dir string, cache edges.VerifiedCache) error {
	return edges.SaveVerified(dir, cache)
}

// loadVerifiedCDNEdges loads at most 100 previous provider-HTTPS measurements for
// preconnection candidates. The caller must validate the actual target before
// treating any address as a fronting route. Loading never changes active routes.
func loadVerifiedCDNEdges(privateFilesDir, provider string) []string {
	if !cdnProvider(provider) || !realPrivateDirectory(privateFilesDir) {
		return nil
	}
	dir := filepath.Join(privateFilesDir, "cdn-scans")
	if !realPrivateDirectory(dir) {
		return nil
	}
	return edges.LoadVerified(dir, provider, "")
}
