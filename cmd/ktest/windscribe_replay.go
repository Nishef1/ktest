package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// carrierReplay retains the client stream until a carrier answers. Each
// candidate has its own offset, so slow dials replay exactly the same bytes.
// After selection only the winner consumes data and releases sent bytes.
type carrierReplay struct {
	mu      sync.Mutex
	data    []byte
	base    int64
	winner  net.Conn
	changed chan struct{}
}

const maxCarrierReplay = 1 << 20

func newCarrierReplay(first []byte) *carrierReplay {
	return &carrierReplay{data: append([]byte(nil), first...), changed: make(chan struct{})}
}

func (r *carrierReplay) notify() {
	close(r.changed)
	r.changed = make(chan struct{})
}

func (r *carrierReplay) selectWinner(c net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.winner = c
	r.notify()
}

func (r *carrierReplay) append(ctx context.Context, p []byte) error {
	for {
		r.mu.Lock()
		if len(r.data)+len(p) <= maxCarrierReplay {
			r.data = append(r.data, p...)
			r.notify()
			r.mu.Unlock()
			return nil
		}
		if r.winner == nil {
			r.mu.Unlock()
			return errors.New("Windscribe client sent more than 1 MiB before any carrier answered")
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (r *carrierReplay) send(ctx context.Context, c net.Conn) error {
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.mu.Lock()
		if r.winner != nil && r.winner != c {
			r.mu.Unlock()
			return context.Canceled
		}
		if r.winner == c && offset > r.base {
			r.data = r.data[offset-r.base:]
			r.base = offset
			r.notify()
		}
		start := offset - r.base
		if start < int64(len(r.data)) {
			// Copy while locked: append/compaction cannot alter an in-flight write.
			p := append([]byte(nil), r.data[start:min(start+32<<10, int64(len(r.data)))]...)
			r.mu.Unlock()
			n, err := c.Write(p)
			offset += int64(n)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrNoProgress
			}
			continue
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
