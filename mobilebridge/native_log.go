package mobilebridge

import (
	"bytes"
	"regexp"
	"strings"
	"sync"

	"github.com/Nishef1/ktest/internal/aether"
)

// stageLog keeps the last few warnings of the native core, with addresses and
// identifiers removed, so a failed start can say which stage broke (WARP API,
// gateway scan, Psiphon) without exposing raw core output.
type stageLog struct {
	mu         sync.Mutex
	partial    []byte
	lines      []string
	scanFailed bool
}

var (
	logPrefix = regexp.MustCompile(`^\[[^\]]*?\s(TRACE|DEBUG|INFO|WARN|ERROR)\s+[^\]]*\]\s*`)
	logUUID   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	logIPv6   = regexp.MustCompile(`(?i)\[?\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b\]?(?::\d+)?`)
	logIPv4   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	logSecret = regexp.MustCompile(`(?i)(token|key|secret|password|device)[=:]\s*\S+`)
)

const stageLogLines = 8

var (
	nativeLogMu sync.Mutex
	nativeLog   *stageLog
)

func newStageLog() *stageLog {
	l := &stageLog{}
	nativeLogMu.Lock()
	nativeLog = l
	nativeLogMu.Unlock()
	return l
}

func (l *stageLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.partial = append(l.partial, p...)
	for {
		i := bytes.IndexByte(l.partial, '\n')
		if i < 0 {
			break
		}
		l.add(string(l.partial[:i]))
		l.partial = l.partial[i+1:]
	}
	if len(l.partial) > 8192 {
		l.partial = nil
	}
	return len(p), nil
}

func (l *stageLog) add(raw string) {
	if aether.MASQUEScanFailed(raw) {
		l.scanFailed = true
	}
	m := logPrefix.FindStringSubmatch(raw)
	if m == nil || (m[1] != "WARN" && m[1] != "ERROR") {
		return
	}
	line := strings.TrimSpace(raw[len(m[0]):])
	line = strings.TrimSpace(strings.TrimLeft(line, "[]!+-* "))
	line = logSecret.ReplaceAllString(line, "$1=<hidden>")
	line = logUUID.ReplaceAllString(line, "<id>")
	line = logIPv4.ReplaceAllString(line, "<ip>")
	line = logIPv6.ReplaceAllString(line, "<ip>")
	if len(line) > 220 {
		line = line[:220] + "…"
	}
	if line == "" || (len(l.lines) > 0 && l.lines[len(l.lines)-1] == line) {
		return
	}
	l.lines = append(l.lines, line)
	if len(l.lines) > stageLogLines {
		l.lines = l.lines[len(l.lines)-stageLogLines:]
	}
}

func (l *stageLog) failedScan() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.scanFailed
}

func (l *stageLog) last() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) == 0 {
		return ""
	}
	return l.lines[len(l.lines)-1]
}

// NativeLog returns the redacted recent warnings of the last native core
// (Aether, Psiphon or Tor), newest last, one per line.
func NativeLog() string {
	nativeLogMu.Lock()
	l := nativeLog
	nativeLogMu.Unlock()
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
