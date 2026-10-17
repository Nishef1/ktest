package smartproxy

import (
	"errors"
	"io"
	"net"
	"time"
)

type relayResult struct {
	up, down    int64
	downErr     error
	remoteFirst bool
	elapsed     time.Duration
}

func pipe(a, b net.Conn) relayResult {
	type copied struct {
		down    bool
		n       int64
		err     error
		elapsed time.Duration
	}
	done := make(chan copied, 2)
	began := time.Now()
	cp := func(dst, src net.Conn, down bool) {
		n, err := io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- copied{down, n, err, time.Since(began)}
	}
	go cp(a, b, true)
	go cp(b, a, false)
	first, second := <-done, <-done
	r := relayResult{remoteFirst: first.down, elapsed: first.elapsed}
	for _, c := range []copied{first, second} {
		if c.down {
			r.down, r.downErr = c.n, c.err
		} else {
			r.up = c.n
		}
	}
	return r
}

func (p *Proxy) observeRelay(host, port, path string, r relayResult) {
	// A client-initiated close or small TLS alert is inconclusive. Only two
	// repeated, prompt upstream closes without response data put a route into
	// a temporary cooldown. Requests already handed to the client are not replayed.
	var op *net.OpError
	remoteError := r.downErr == nil || (errors.As(r.downErr, &op) && op.Op == "read")
	early := r.remoteFirst && remoteError && r.up > 32 && r.down == 0 && r.elapsed < 2*time.Second
	if r.down == 0 && !early {
		return
	}
	p.mu.Lock()
	m := p.historyLocked(host, port)
	s := m.score(path)
	if !early {
		s.earlyFailures = 0
		s.coolUntil = time.Time{}
		p.mu.Unlock()
		return
	}
	s.earlyFailures++
	s.fails++
	if s.earlyFailures >= 2 {
		s.coolUntil = time.Now().Add(30 * time.Second)
		if m.winner == path {
			m.winner = ""
		}
	}
	for _, u := range p.ups {
		if u.Name == path {
			u.fails++
			break
		}
	}
	p.mu.Unlock()
	p.emit(Event{Host: host, Port: port, Site: siteKey(host), Path: path, EarlyClose: true,
		Err: "Early upstream close without response data; route score updated."})
}
