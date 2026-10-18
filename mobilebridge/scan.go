package mobilebridge

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/probe"
)

type cdnScanResult struct {
	IP           string `json:"ip"`
	TCPMS        int64  `json:"tcp_ms"`
	TLSMS        int64  `json:"tls_ms"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	HTTPStatus   int    `json:"http_status"`
	TLSVerified  bool   `json:"tls_verified"`
	HTTPVerified bool   `json:"http_verified"`
	Assessment   string `json:"assessment"`
	Error        string `json:"error"`
}

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
	if !proxyStartMu.TryLock() {
		return errors.New("disconnect or finish startup before scanning CDN routes")
	}
	defer proxyStartMu.Unlock()
	if routeWorkActive() {
		return errors.New("disconnect before scanning CDN routes")
	}
	return startCDNScan(provider, budget, goal, "", nil, nil)
}

// StartCDNScanToFile streams all started attempts to an app-private CSV. Budget
// zero removes the count limit, with no session deadline or success cap. Android
// must copy the completed snapshot through its document save picker. It does not
// change routing: provider HTTPS is not proof of fronting to another target.
func StartCDNScanToFile(provider string, budget int, privateFilesDir string) error {
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
	return startCDNScan(provider, budget, 0, privateFilesDir, nil, nil)
}

type cdnScanSource func(context.Context, string, int) (edges.Preset, edges.CandidateIterator, error)

func startCDNScan(provider string, budget, goal int, privateDir string, discover cdnScanSource, runner edges.Runner) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if !cdnProvider(provider) {
		return errors.New("choose cloudflare, akamai, fastly or google")
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
		discover = edges.ScanCandidateSource
	}
	ctx, cancel := context.WithCancel(context.Background())
	scanCancel, scanStarted = cancel, time.Now()
	scanState = cdnScan{Running: true, Budget: budget, Goal: goal, Provider: provider, Unlimited: budget == 0,
		VerifiedHTTP: []string{}, Results: []cdnScanResult{},
		Note: "Verified HTTPS to the provider's test host only; target fronting, VPN access, and DNS resolver functionality remain unverified. Discovery/DNS and HTTPS can be blocked independently."}
	go runCDNScan(ctx, cancel, provider, budget, goal, dir, file, writer, discover, runner)
	return nil
}

func runCDNScan(ctx context.Context, cancel context.CancelFunc, provider string, budget, goal int, dir string, file *os.File, writer *csv.Writer, discover cdnScanSource, runner edges.Runner) {
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
		failure = "provider candidate discovery failed"
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
		if saveVerifiedCDNEdges(dir, cdnEdgeCache{Provider: provider, Source: preset.Source, VerifiedAt: time.Now().UTC(), Results: best}) != nil {
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
func cdnResult(ip string, r probe.Result) cdnScanResult {
	result := cdnScanResult{IP: ip, TCPMS: r.ConnectMS, TLSMS: r.TLSMS, ElapsedMS: r.ElapsedMS,
		HTTPStatus: r.Status, TLSVerified: r.TLSVersion != ""}
	if r.Error != "" {
		err := strings.ToLower(r.Error)
		switch {
		case strings.Contains(err, "canceled"):
			result.Error = "canceled"
		case strings.Contains(err, "timeout"), strings.Contains(err, "deadline exceeded"):
			result.Error = "timeout"
		case strings.Contains(err, "x509"), strings.Contains(err, "certificate"):
			result.Error = "certificate verification failed"
		case strings.Contains(err, "tls"):
			result.Error = "TLS failed"
		case strings.Contains(err, "connection refused"):
			result.Error = "connection refused"
		case strings.Contains(err, "connection reset"):
			result.Error = "connection reset"
		default:
			result.Error = "probe failed"
		}
	}
	result.HTTPVerified = r.Success && result.TLSVerified && r.Status >= 200 && r.Status < 300 && result.Error == ""
	switch {
	case result.HTTPVerified:
		result.Assessment = "provider_https_verified"
	case result.Error == "canceled":
		result.Assessment = "canceled"
	case result.TLSVerified:
		result.Assessment = "tls_only"
	case r.Reachable || r.Phase == "tls" || r.Phase == "http" || r.Phase == "tls_or_http":
		result.Assessment = "tcp_only"
	default:
		result.Assessment = "unreachable"
	}
	return result
}

func cdnProvider(p string) bool {
	return p == "cloudflare" || p == "akamai" || p == "fastly" || p == "google"
}

func realPrivateDirectory(dir string) bool {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || filepath.Dir(dir) == dir {
		return false
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	if filepath.Separator == '\\' {
		return strings.EqualFold(real, dir)
	}
	return real == dir
}

func cdnPrivateDirectory(privateDir string) (string, error) {
	if !realPrivateDirectory(privateDir) {
		return "", errors.New("scan storage requires a real absolute private directory, without symlinks or a filesystem root")
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

type cdnEdgeCache struct {
	Provider   string          `json:"provider"`
	Source     string          `json:"source"`
	VerifiedAt time.Time       `json:"verified_at"`
	Results    []cdnScanResult `json:"results"`
}

func saveVerifiedCDNEdges(dir string, cache cdnEdgeCache) error {
	file, err := os.CreateTemp(dir, "verified-*.partial")
	if err != nil {
		return err
	}
	defer func() { file.Close(); os.Remove(file.Name()) }()
	if err := json.NewEncoder(file).Encode(cache); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, "verified-"+cache.Provider+".json"))
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
	path := filepath.Join(dir, "verified-"+provider+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128*1024 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var cache cdnEdgeCache
	if json.NewDecoder(io.LimitReader(f, 128*1024)).Decode(&cache) != nil || cache.Provider != provider || cache.Source == "" || len(cache.Results) > 100 || cache.VerifiedAt.After(time.Now()) || time.Since(cache.VerifiedAt) > 24*time.Hour {
		return nil
	}
	ips := make([]string, 0, len(cache.Results))
	seen := map[string]bool{}
	for _, r := range cache.Results {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || !r.HTTPVerified || !r.TLSVerified || r.HTTPStatus < 200 || r.HTTPStatus >= 300 || r.Error != "" || seen[ip.String()] {
			return nil
		}
		ips = append(ips, ip.String())
		seen[ip.String()] = true
	}
	return ips
}
