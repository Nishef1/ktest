package smartproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type relayResult struct {
	up, down    int64
	downErr     error
	remoteFirst bool
	elapsed     time.Duration
	// stalled: the stall watch fired (and already scored the route);
	// recovered: response data arrived after all, so it was only slow.
	stalled, recovered bool
}

// stallWatch fires once when a young TLS flow goes dark: nothing arrived
// after the ServerHello, or the client's first flight after it got no answer,
// for after. A healthy server answers both at once (the rest of its handshake
// flight, then a session ticket or the response), so silence there is the
// "handshake allowed, then blackholed" filter, even while the socket is open.
type stallWatch struct {
	after   time.Duration
	onStall func()
}

type countedReader struct {
	r     io.Reader
	n     *atomic.Int64
	first *atomic.Int64 // UnixNano of the first byte, when tracked
	last  *atomic.Int64 // UnixNano of the latest byte, when tracked
}

func (c countedReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.n.Add(int64(n))
		now := time.Now().UnixNano()
		if c.first != nil {
			c.first.CompareAndSwap(0, now)
		}
		if c.last != nil {
			c.last.Store(now)
		}
	}
	return n, err
}

func pipe(a, b net.Conn) relayResult { return pipeWatch(a, b, nil) }

// pipeWatch relays client a and upstream b until both directions end.
func pipeWatch(a, b net.Conn, w *stallWatch) relayResult {
	type copied struct {
		down    bool
		n       int64
		err     error
		elapsed time.Duration
	}
	done := make(chan copied, 2)
	began := time.Now()
	var up, down, firstUp, lastDown atomic.Int64
	cp := func(dst net.Conn, src io.Reader, down bool) {
		n, err := io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- copied{down, n, err, time.Since(began)}
	}
	var stalled atomic.Bool
	var downAtStall atomic.Int64
	stop := make(chan struct{})
	if w != nil && w.after > 0 && w.onStall != nil {
		go func() {
			tick := time.NewTicker(max(w.after/8, 10*time.Millisecond))
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case now := <-tick.C:
					fu := firstUp.Load()
					var since time.Time
					switch {
					case fu == 0 && down.Load() == 0:
						since = began
					case fu != 0 && lastDown.Load() < fu:
						since = time.Unix(0, fu)
					case fu != 0:
						return // the client's first flight was answered
					default:
						continue // server flight arrived; the client has not spoken yet
					}
					if now.Sub(since) >= w.after {
						downAtStall.Store(down.Load())
						stalled.Store(true)
						w.onStall()
						return
					}
				}
			}
		}()
	}
	go cp(a, countedReader{r: b, n: &down, last: &lastDown}, true)
	go cp(b, countedReader{r: a, n: &up, first: &firstUp}, false)
	first := <-done
	close(stop)
	second := <-done
	r := relayResult{remoteFirst: first.down, elapsed: first.elapsed}
	for _, c := range []copied{first, second} {
		if c.down {
			r.down, r.downErr = c.n, c.err
		} else {
			r.up = c.n
		}
	}
	r.stalled = stalled.Load()
	r.recovered = r.stalled && r.down > downAtStall.Load()
	return r
}

func (p *Proxy) observeRelay(ctx context.Context, host, port, path string, r relayResult) {
	if r.stalled && !r.recovered {
		return // observeStall already scored this connection
	}
	// A client-initiated close or small TLS alert is inconclusive. Only two
	// repeated, prompt upstream closes without response data put a route into
	// a temporary cooldown. Requests already handed to the client are not replayed.
	var op *net.OpError
	remoteError := r.downErr == nil || (errors.As(r.downErr, &op) && op.Op == "read")
	early := r.remoteFirst && remoteError && r.up > 32 && r.down == 0 && r.elapsed < 2*time.Second
	if r.down == 0 && !early {
		return
	}
	if !early {
		p.mu.Lock()
		s := p.historyLocked(host, port).score(path)
		s.earlyFailures = 0
		s.coolUntil = time.Time{}
		p.mu.Unlock()
		return
	}
	p.earlyFailure(ctx, host, port, path, false)
}

// observeStall scores a relayed flow that went silent after the handshake.
// The connection stays open: a slow server can still answer, and nothing is
// replayed after the client has received bytes.
func (p *Proxy) observeStall(ctx context.Context, host, port, path string) {
	if ctx.Err() != nil {
		return
	}
	p.earlyFailure(ctx, host, port, path, true)
}

// earlyFailure records that a route passed the handshake but was then cut or
// blackholed. Two in a row put it into a temporary cooldown.
func (p *Proxy) earlyFailure(ctx context.Context, host, port, path string, stall bool) {
	p.mu.Lock()
	m := p.historyLocked(host, port)
	s := m.score(path)
	s.earlyFailures++
	s.fails++
	s.kind = KindBlackhole
	if s.earlyFailures >= 2 {
		s.coolUntil = time.Now().Add(30 * time.Second)
		if m.winner == path {
			m.winner = ""
		}
	}
	for _, u := range p.ups {
		if u.Name == path {
			u.fails++
			p.noteFailureLocked(m, u, host, KindBlackhole)
			break
		}
	}
	p.mu.Unlock()
	msg := "Early upstream close without response data; route score updated."
	if stall {
		msg = "No response data after the TLS handshake; route score updated."
	}
	p.emit(ctx, Event{Host: host, Port: port, Site: siteKey(host), Path: path, EarlyClose: true, Stall: stall,
		Failure: KindBlackhole.String(), Err: msg})
}
