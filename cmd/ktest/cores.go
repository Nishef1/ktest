package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"time"
)

// tailBuffer keeps only the last bytes a core wrote, so a failed core can
// explain itself without flooding the terminal with every log line.
type tailBuffer struct {
	mu   sync.Mutex
	data []byte
	max  int
	tee  io.Writer
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.data = append(b.data, p...)
	if len(b.data) > b.max {
		b.data = b.data[len(b.data)-b.max:]
	}
	tee := b.tee
	b.mu.Unlock()
	if tee != nil {
		_, _ = tee.Write(p)
	}
	return len(p), nil
}

// lastLine is the most recent non-empty line a core wrote.
func (b *tailBuffer) lastLine() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := strings.TrimSpace(string(b.data))
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = text[i+1:]
	}
	return strings.TrimSpace(text)
}

// runningCore is one proxy core started by ktest.
type runningCore struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

// stop asks the core to end and waits until it has.
func (c *runningCore) stop() bool {
	c.cancel()
	select {
	case <-c.done:
		return true
	case <-time.After(6 * time.Second):
		return false
	}
}

// lastLines returns up to n of the most recent non-empty lines.
func (b *tailBuffer) lastLines(n int) []string {
	b.mu.Lock()
	text := string(b.data)
	b.mu.Unlock()
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// termLines forwards complete lines of core output through term.Printf, which
// clears and repaints progress lines and pinned boxes around each write.
type termLines struct {
	t       *term
	mu      sync.Mutex
	partial []byte
}

func (w *termLines) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.partial = append(w.partial, p...)
	var lines []string
	for {
		i := bytes.IndexByte(w.partial, '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimRight(string(w.partial[:i]), "\r"); strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
		w.partial = w.partial[i+1:]
	}
	if len(w.partial) > 4096 {
		lines = append(lines, string(w.partial))
		w.partial = nil
	}
	w.mu.Unlock()
	for _, line := range lines {
		w.t.Printf("    %s\n", w.t.Dim(line))
	}
	return len(p), nil
}
