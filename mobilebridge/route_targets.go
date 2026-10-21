package mobilebridge

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/quickcheck"
)

const routeTargetsFile = "route-targets.json"

var routeTargetsMu sync.Mutex

// Fronting false excludes the exact host from family-wide fronting; the URL path is only for tests.
// It neither extends the local CA nor changes protected-domain routing policy.
type routeTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Fronting bool   `json:"fronting"`
}

type routeTargetInfo struct {
	routeTarget
	Family    string `json:"family"`
	CACovered bool   `json:"ca_covered"`
	Supported bool   `json:"supported"`
	Note      string `json:"note"`
}

func defaultRouteTargets() []routeTarget {
	var out []routeTarget
	for _, target := range quickcheck.Targets() {
		id := "default-" + strings.ReplaceAll(strings.ToLower(target.Name), " ", "-")
		u, _ := url.Parse(target.URL)
		out = append(out, routeTarget{id, target.Name, target.URL, front.Lookup(front.DefaultFamilies(), u.Hostname()) != nil})
	}
	for _, control := range []struct{ id, name, host string }{
		{"x-api", "X API (transport control)", "api.x.com"},
		{"twitter-api", "Twitter API (transport control)", "api.twitter.com"},
		{"x-photos", "X photos (transport control)", "pbs.twimg.com"},
		{"x-video", "X video (transport control)", "video.twimg.com"},
	} {
		out = append(out, routeTarget{"default-" + control.id, control.name, "https://" + control.host + "/", true})
	}
	return out
}

// realRouteDirectory validates the caller-owned Context.filesDir leaf and
// canonicalizes platform mappings in its ancestors (e.g. /data/user/0). The
// Android caller supplies this trusted private path; desktop ACLs are unknown.
func realRouteDirectory(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", errors.New("targets require an absolute app-private directory")
	}
	dir = filepath.Clean(dir)
	if filepath.Dir(dir) == dir {
		return "", errors.New("targets cannot be stored in a filesystem root")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("targets require an existing real app-private directory leaf")
	}
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", errors.New("cannot resolve app-private directory")
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil || filepath.Dir(canonical) == canonical {
		return "", errors.New("invalid canonical private directory")
	}
	return canonical, nil
}

func targetURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 2048 || strings.IndexFunc(raw, unicode.IsControl) >= 0 || strings.Contains(raw, "#") {
		return nil, errors.New("use an HTTPS URL without credentials, fragments or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
		return nil, errors.New("use an HTTPS URL without credentials or fragments")
	}
	if decoded, err := url.PathUnescape(u.EscapedPath() + "?" + u.RawQuery); err != nil || strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
		return nil, errors.New("URL contains encoded control characters")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !validTargetHost(host) {
		return nil, errors.New("invalid HTTPS hostname")
	}
	port := u.Port()
	if port != "" {
		// Other HTTPS ports are useful for ordinary diagnostics, but can never
		// authorize a fronting takeover, which only supports port 443.
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid HTTPS port")
		}
	}
	u.Host = host
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func validTargetHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) < 3 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validRouteID(id string) bool {
	if len(id) == 0 || len(id) > 80 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validateRouteTarget(target routeTarget) (routeTarget, error) {
	if !validRouteID(target.ID) || strings.TrimSpace(target.Name) == "" || len(target.Name) > 160 || strings.IndexFunc(target.Name, unicode.IsControl) >= 0 {
		return target, errors.New("target needs a valid ID and a name of 1..160 bytes")
	}
	u, err := targetURL(target.URL)
	if err != nil {
		return target, err
	}
	target.Name = strings.TrimSpace(target.Name)
	target.URL = u.String()
	return target, nil
}

// loadRouteTargets returns the persisted complete override, including an empty
// list. Missing storage alone selects defaults; corrupt storage fails closed.
func loadRouteTargets(privateDir string) ([]routeTarget, error) {
	routeTargetsMu.Lock()
	defer routeTargetsMu.Unlock()
	return loadRouteTargetsLocked(privateDir)
}

func loadRouteTargetsLocked(privateDir string) ([]routeTarget, error) {
	dir, err := realRouteDirectory(privateDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, routeTargetsFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return defaultRouteTargets(), nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("invalid route target storage")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var targets []routeTarget
	dec := json.NewDecoder(io.LimitReader(file, 1<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&targets); err != nil || targets == nil {
		return nil, errors.New("invalid route target JSON; defaults were not restored")
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing route target data")
	}
	seen := map[string]bool{}
	for i, target := range targets {
		validated, err := validateRouteTarget(target)
		if err != nil || seen[target.ID] {
			return nil, errors.New("invalid or duplicate stored route target")
		}
		seen[target.ID] = true
		targets[i] = validated
	}
	return targets, nil
}

// Revision is a hash of the effective target set, never raw URL log material.
func routeTargetsRevision(targets []routeTarget) string {
	ordered := append([]routeTarget{}, targets...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	raw, _ := json.Marshal(ordered)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// With fronting enabled, every host of a fronting family (Google, YouTube,
// X, Meta, Fastly sites) may be fronted, as on Windows: YouTube alone needs
// googlevideo, ytimg and ggpht hosts no one lists by hand. A saved target
// with fronting switched off is the exception for its exact host. An app that
// refuses the CA only loses fronting for that host; other routes take over.
func routeFrontingAllowed(targets []routeTarget, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if front.Lookup(front.DefaultFamilies(), host) == nil {
		return false
	}
	for _, target := range targets {
		u, err := targetURL(target.URL)
		if err == nil && u.Hostname() == host && (u.Port() == "" || u.Port() == "443") && !target.Fronting {
			return false
		}
	}
	return true
}

func writeRouteTargets(dir string, targets []routeTarget) error {
	if targets == nil {
		targets = []routeTarget{}
	}
	raw, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".route-targets-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err = tmp.Write(raw); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, routeTargetsFile))
}

// RouteTargets lists diagnostics and current public CA coverage. It never reads
// a CA key, creates a certificate, contacts a target, or modifies OS trust.
func RouteTargets(privateDir string) (string, error) {
	dir, err := realRouteDirectory(privateDir)
	if err != nil {
		return "", err
	}
	targets, err := loadRouteTargets(dir)
	if err != nil {
		return "", err
	}
	return routeTargetsJSON(dir, targets)
}

func routeTargetsJSON(dir string, targets []routeTarget) (string, error) {
	cert := routeTargetsPublicCA(dir)
	infos := make([]routeTargetInfo, 0, len(targets))
	for _, target := range targets {
		u, _ := targetURL(target.URL)
		info := routeTargetInfo{routeTarget: target, Note: "Fronting off excludes this exact hostname; the path is used only for diagnostics. CA trust and target reachability are not verified."}
		if fam := front.Lookup(front.DefaultFamilies(), u.Hostname()); fam != nil {
			info.Family = fam.Name
			info.Supported = u.Port() == "" || u.Port() == "443"
		}
		info.CACovered = publicCAPermits(cert, u.Hostname())
		if !info.Supported {
			info.Note = "Unsupported fronting family or port. Ordinary HTTPS route diagnostics remain available; an arbitrary URL does not establish shared-edge support."
		} else if !info.CACovered {
			info.Note += " The current public CA certificate does not cover this host; it was not replaced."
		}
		infos = append(infos, info)
	}
	raw, err := json.Marshal(struct {
		Targets  []routeTargetInfo `json:"targets"`
		Revision string            `json:"revision"`
		Note     string            `json:"note"`
	}{infos, routeTargetsRevision(targets), "Removing a target changes tests and its fronting exclusion only. Protected-domain policy and CA constraints remain in force."})
	return string(raw), err
}

func routeTargetsPublicCA(dir string) *x509.Certificate {
	frontCAMu.Lock()
	defer frontCAMu.Unlock()
	rootDir, err := realRouteDirectory(dir)
	if err != nil {
		return nil
	}
	caDir, err := realRouteDirectory(filepath.Join(rootDir, androidFrontCADirectory))
	if err != nil {
		return nil
	}
	relative, err := filepath.Rel(rootDir, caDir)
	if err != nil {
		return nil
	}
	// Windows canonicalizes path-component casing independently of the
	// spelling supplied by the caller. Only this single direct-child name is
	// allowed; use case-insensitive comparison only on Windows.
	if filepath.Separator == '\\' {
		if !strings.EqualFold(relative, androidFrontCADirectory) {
			return nil
		}
	} else if relative != androidFrontCADirectory {
		return nil
	}
	path := filepath.Join(caDir, front.CertFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || !cert.PermittedDNSDomainsCritical || len(cert.PermittedDNSDomains) == 0 || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return nil
	}
	return cert
}

func publicCAPermits(cert *x509.Certificate, host string) bool {
	if cert == nil || net.ParseIP(host) != nil {
		return false
	}
	match := func(domain string) bool {
		domain = strings.ToLower(domain)
		if strings.HasPrefix(domain, ".") {
			return strings.HasSuffix(host, domain)
		}
		return host == domain || strings.HasSuffix(host, "."+domain)
	}
	for _, d := range cert.ExcludedDNSDomains {
		if match(d) {
			return false
		}
	}
	for _, d := range cert.PermittedDNSDomains {
		if match(d) {
			return true
		}
	}
	return false
}

// SaveRouteTarget adds or edits a target. Empty id allocates a random local ID.
// routeWorkActive is owned by the connection/calibration coordinator.
func SaveRouteTarget(privateDir, id, name, rawURL string, fronting bool) (string, error) {
	if !proxyStartMu.TryLock() {
		return "", errors.New("proxy startup or a target operation is active")
	}
	defer proxyStartMu.Unlock()
	routeTargetsMu.Lock()
	defer routeTargetsMu.Unlock()
	if routeWorkActive() {
		return "", errors.New("disconnect and finish startup/calibration before editing targets")
	}
	dir, err := realRouteDirectory(privateDir)
	if err != nil {
		return "", err
	}
	if id == "" {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", err
		}
		id = "custom-" + hex.EncodeToString(nonce[:])
	}
	target, err := validateRouteTarget(routeTarget{id, name, rawURL, fronting})
	if err != nil {
		return "", err
	}
	targets, err := loadRouteTargetsLocked(dir)
	if err != nil {
		return "", err
	}
	found := false
	for i := range targets {
		if targets[i].ID == id {
			targets[i] = target
			found = true
			break
		}
	}
	if !found {
		targets = append(targets, target)
	}
	if err = writeRouteTargets(dir, targets); err != nil {
		return "", err
	}
	return routeTargetsJSON(dir, targets)
}

func DeleteRouteTarget(privateDir, id string) (string, error) {
	if !proxyStartMu.TryLock() {
		return "", errors.New("proxy startup or a target operation is active")
	}
	defer proxyStartMu.Unlock()
	routeTargetsMu.Lock()
	defer routeTargetsMu.Unlock()
	if routeWorkActive() {
		return "", errors.New("disconnect and finish startup/calibration before editing targets")
	}
	dir, err := realRouteDirectory(privateDir)
	if err != nil {
		return "", err
	}
	targets, err := loadRouteTargetsLocked(dir)
	if err != nil {
		return "", err
	}
	index := -1
	for i := range targets {
		if targets[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return "", errors.New("target ID was not found")
	}
	targets = append(targets[:index], targets[index+1:]...)
	if err = writeRouteTargets(dir, targets); err != nil {
		return "", err
	}
	return routeTargetsJSON(dir, targets)
}
