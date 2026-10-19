package smartproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
)

// FailureKind is what an attempt's failure says about the filter in front of
// the destination. It is inferred from the stage at which the attempt died and
// how: it is evidence, not proof (a dead server and an IP block look alike).
type FailureKind uint8

const (
	KindNone      FailureKind = iota
	KindOther                 // local core trouble, TLS alerts, anything unclassified
	KindIPBlock               // TCP connect timed out or was refused/unreachable
	KindReset                 // connection reset right after the ClientHello (SNI reset)
	KindSilent                // ClientHello sent, then silence until the deadline
	KindBlackhole             // handshake allowed (ServerHello seen), then stalled or cut
	KindBlockPage             // non-TLS bytes (block page) or a certificate the client refused
	KindDNSPoison             // only private/reserved answers from the system resolver
	kindCount
)

var kindKeys = [kindCount]string{"", "other", "ip-block", "sni-reset", "silent-drop", "blackhole", "block-page", "dns-poison"}
var kindLabels = [kindCount]string{"", "other failure", "IP block", "SNI reset", "ClientHello dropped", "post-handshake blackhole", "block page/wrong certificate", "DNS poisoning"}

func (k FailureKind) String() string {
	if k < kindCount {
		return kindLabels[k]
	}
	return "unknown"
}

func kindFromKey(key string) FailureKind {
	for i, k := range kindKeys {
		if k == key && k != "" {
			return FailureKind(i)
		}
	}
	return KindNone
}

// informative kinds describe the filter; KindOther describes our own side.
func (k FailureKind) informative() bool { return k > KindOther && k < kindCount }

type failureError struct {
	kind FailureKind
	err  error
}

func (e *failureError) Error() string { return e.err.Error() }
func (e *failureError) Unwrap() error { return e.err }

func withKind(kind FailureKind, err error) error {
	if err == nil {
		return nil
	}
	return &failureError{kind, err}
}

type socksReplyError struct{ code byte }

func (e socksReplyError) Error() string {
	return fmt.Sprintf("upstream CONNECT failed (reply %d)", e.code)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// Windows reports WSA error numbers that do not match the POSIX constants, so
// the message is checked as well.
func isReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed") || strings.Contains(s, "aborted") || strings.Contains(s, "broken pipe")
}

func isUnreachable(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "refused") || strings.Contains(s, "unreachable")
}

// classifyConnect explains a failed destination connection (direct dial or the
// upstream core's SOCKS CONNECT).
func classifyConnect(err error) FailureKind {
	var fe *failureError
	var se socksReplyError
	switch {
	case err == nil || errors.Is(err, context.Canceled):
		return KindNone
	case errors.As(err, &fe):
		return fe.kind
	case errors.Is(err, ErrPoisoned):
		return KindDNSPoison
	case errors.As(err, &se):
		if se.code >= 3 && se.code <= 6 { // network/host unreachable, refused, TTL expired
			return KindIPBlock
		}
		return KindOther
	case isTimeout(err), isUnreachable(err), isReset(err):
		return KindIPBlock
	}
	return KindOther
}

// classifyAfterHello explains a failure while waiting for the server's answer
// to the first flight. read is how many bytes arrived, first the first of them.
func classifyAfterHello(err error, read int, first byte) FailureKind {
	switch {
	case err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed):
		return KindNone
	case read == 0 && isTimeout(err):
		return KindSilent
	case read == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isReset(err)):
		return KindReset
	case read == 0:
		return KindOther
	case first == 21: // a TLS alert: the server (or a forger) refused the hello
		return KindOther
	case first != 22:
		return KindBlockPage
	case isTimeout(err):
		return KindBlackhole // the answer began, then the flow went dark
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isReset(err):
		return KindReset
	}
	return KindOther
}

func failureKind(err error) FailureKind {
	var fe *failureError
	if errors.As(err, &fe) {
		return fe.kind
	}
	return classifyConnect(err)
}

type countingReader struct {
	r     io.Reader
	n     int
	first byte
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 && c.n == 0 {
		c.first = b[0]
	}
	c.n += n
	return n, err
}

// Method families group routes by the mechanism that defeats the filter, so a
// lesson learned with one ByeDPI fake strategy carries to the others.
const (
	FamilyPlain  = "plain"
	FamilyFake   = "fake"
	FamilyOOB    = "oob"
	FamilyTLSRec = "tlsrec"
	FamilySplit  = "split"
	FamilyExit   = "exit"
	FamilyFront  = "front"
	FamilyOther  = "other"
)

var familyLabels = map[string]string{
	FamilyPlain: "plain", FamilyFake: "fake/low-TTL", FamilyOOB: "OOB", FamilyTLSRec: "TLS record split",
	FamilySplit: "TCP split", FamilyExit: "exit", FamilyFront: "fronting", FamilyOther: "other",
}

func familyLabel(f string) string {
	if l, ok := familyLabels[f]; ok {
		return l
	}
	return f
}

// ByeDPIFamily names the strongest technique in a ByeDPI argument list.
func ByeDPIFamily(args []string) string {
	has := map[string]bool{}
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		switch name {
		case "-f", "--fake", "-t", "--ttl", "--md5sig", "--fake-sni", "--fake-data", "--fake-offset", "--fake-tls-mod":
			has[FamilyFake] = true
		case "-o", "--oob", "-q", "--disoob", "--oob-data":
			has[FamilyOOB] = true
		case "-r", "--tlsrec":
			has[FamilyTLSRec] = true
		case "-s", "--split", "-d", "--disorder":
			has[FamilySplit] = true
		}
	}
	for _, f := range []string{FamilyFake, FamilyOOB, FamilyTLSRec, FamilySplit} {
		if has[f] {
			return f
		}
	}
	return FamilyOther
}

func methodFamily(u Upstream) string {
	if u.Family != "" {
		return u.Family
	}
	if u.Exit {
		return FamilyExit
	}
	if u.Takeover != nil {
		return FamilyFront
	}
	name := strings.ToLower(u.Name)
	for _, c := range []struct{ family, words string }{
		{FamilyFake, "fake|ttl|md5sig|combo"},
		{FamilyOOB, "oob"},
		{FamilyTLSRec, "tlsrec|tls record"},
		{FamilySplit, "split|disorder|fragment|segment"},
		{FamilyPlain, "plain"},
	} {
		for _, w := range strings.Split(c.words, "|") {
			if strings.Contains(name, w) {
				return c.family
			}
		}
	}
	if u.Addr == "" && u.Send == nil && u.Dial == nil {
		return FamilyPlain
	}
	return FamilyOther
}

// familyPrior is the network-level tally for one failure kind: on how many
// destinations each family won or lost. Counts are per destination, not per
// connection, so one busy site cannot dominate.
type familyPrior struct {
	sites        int
	wins, losses map[string]int
	updated      time.Time
}

const (
	priorMinWins = 3
	priorTTL     = 7 * 24 * time.Hour
	priorCap     = 32
)

func (pr *familyPrior) add(m map[string]int, family string) {
	m[family]++
	pr.updated = time.Now()
	if m[family] > priorCap { // keep adapting when the filter changes
		for _, t := range []map[string]int{pr.wins, pr.losses} {
			for f := range t {
				t[f] /= 2
			}
		}
		pr.sites /= 2
	}
}

// best is the family that keeps winning against this kind: enough distinct
// destinations, more wins than losses, and strictly ahead of every other.
func (pr *familyPrior) best() string {
	if pr == nil {
		return ""
	}
	best, top, second := "", 0, 0
	for f, w := range pr.wins {
		switch {
		case w > top:
			best, top, second = f, w, top
		case w == top:
			second = w
		case w > second:
			second = w
		}
	}
	if top < priorMinWins || top <= second || top <= pr.losses[best] {
		return ""
	}
	return best
}

func (p *Proxy) priorLocked(kind FailureKind) *familyPrior {
	pr := p.priors[kind]
	if pr == nil {
		pr = &familyPrior{wins: map[string]int{}, losses: map[string]int{}}
		p.priors[kind] = pr
	}
	return pr
}

// priorsApply: frozen selections (and protected destinations) keep their
// exact behaviour; priors only reorder an open race.
func (p *Proxy) priorsApplyLocked(host string) bool {
	return p.cfg.Frozen == nil && !(p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host))
}

// noteFailureLocked attaches a classified failure to the destination. The
// plain route's failure is the most truthful description of the filter.
func (p *Proxy) noteFailureLocked(m *destinationMemory, u *upstreamState, host string, kind FailureKind) {
	if !kind.informative() || !p.priorsApplyLocked(host) {
		return
	}
	if u.family != FamilyExit && (m.kind == KindNone || (u.family == FamilyPlain && m.kind != kind)) {
		if m.kind == KindNone {
			p.priorLocked(kind).sites++
		}
		m.kind = kind
	}
	if m.failed == nil {
		m.failed = map[string]bool{}
	}
	m.failed[u.family] = true
}

// creditLocked credits the winning family once per destination (and again
// only when a different family takes over), plus a loss for each family that
// failed there.
func (p *Proxy) creditLocked(m *destinationMemory, u *upstreamState, host string) {
	if m.kind == KindNone || m.winner != u.Name || m.credited == u.family || !p.priorsApplyLocked(host) {
		return
	}
	pr := p.priorLocked(m.kind)
	pr.add(pr.wins, u.family)
	for f := range m.failed {
		if f != u.family && !m.lossCredited[f] {
			pr.add(pr.losses, f)
			if m.lossCredited == nil {
				m.lossCredited = map[string]bool{}
			}
			m.lossCredited[f] = true
		}
	}
	m.credited = u.family
}

// priorFamily is the family to try first for a destination that just showed
// kind, or "" when the network has no clear lesson or the destination already
// has its own winner.
func (p *Proxy) priorFamily(host, port string, kind FailureKind) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !kind.informative() || !p.priorsApplyLocked(host) {
		return ""
	}
	if m := p.memoryLocked(host, port); m != nil && m.winner != "" {
		return ""
	}
	return p.priors[kind].best()
}

// FilteringSummary describes, per failure kind seen on this network, which
// method family wins, e.g. "SNI reset: fake/low-TTL wins (5/6 sites); IP block:
// exit only (3 sites)". Empty until something was learned.
func (p *Proxy) FilteringSummary() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return summarizePriors(p.priors)
}

func summarizePriors(priors map[FailureKind]*familyPrior) string {
	kinds := make([]FailureKind, 0, len(priors))
	for k, pr := range priors {
		if pr.sites > 0 || len(pr.wins) > 0 {
			kinds = append(kinds, k)
		}
	}
	sort.Slice(kinds, func(i, j int) bool {
		a, b := priors[kinds[i]], priors[kinds[j]]
		if a.sites != b.sites {
			return a.sites > b.sites
		}
		return kinds[i] < kinds[j]
	})
	var parts []string
	for _, k := range kinds {
		pr := priors[k]
		sites := max(pr.sites, 1)
		var fams []string
		for f, w := range pr.wins {
			if w > 0 {
				fams = append(fams, f)
			}
		}
		sort.Slice(fams, func(i, j int) bool {
			if pr.wins[fams[i]] != pr.wins[fams[j]] {
				return pr.wins[fams[i]] > pr.wins[fams[j]]
			}
			return fams[i] < fams[j]
		})
		lost := false
		for f, l := range pr.losses {
			if l > 0 && pr.wins[f] == 0 {
				lost = true
			}
		}
		var line string
		switch {
		case len(fams) == 0:
			line = fmt.Sprintf("no working method yet (%d sites)", sites)
		case len(fams) == 1 && lost && fams[0] == FamilyExit: // no local method works here
			line = fmt.Sprintf("%s only (%d sites)", familyLabel(fams[0]), pr.wins[fams[0]])
		case pr.best() != "":
			line = fmt.Sprintf("%s wins (%d/%d sites)", familyLabel(fams[0]), pr.wins[fams[0]], max(sites, pr.wins[fams[0]]))
		default:
			var mixed []string
			for _, f := range fams {
				mixed = append(mixed, fmt.Sprintf("%s %d", familyLabel(f), pr.wins[f]))
			}
			line = "mixed: " + strings.Join(mixed, ", ")
		}
		parts = append(parts, k.String()+": "+line)
	}
	return strings.Join(parts, "; ")
}
