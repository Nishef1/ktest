package main

import (
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
