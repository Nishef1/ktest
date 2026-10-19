package packetdesync

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Dialer serializes packet strategies while ordinary ByeDPI/Go connections
// continue independently. A failed cleanup disables further filters.
type Dialer struct {
	base    string
	gate    chan struct{}
	blocked error // accessed only while holding gate
}

func NewDialer(base string) *Dialer { return &Dialer{base: base, gate: make(chan struct{}, 1)} }

func (d *Dialer) Dial(ctx context.Context, network, address string, strategy Strategy) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errors.New("Zapret2 local routing requires a public IPv4 TCP 443 destination")
	}
	if _, _, err := Target(host, strategy); err != nil {
		return nil, err
	}
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	unlock := func() { <-d.gate }
	if d.blocked != nil {
		unlock()
		return nil, d.blocked
	}
	dialer := net.Dialer{}
	c, err := dialer.DialContext(ctx, "tcp4", address)
	if err != nil {
		unlock()
		return nil, err
	}
	// The first TLS flight needs shaping; the TCP SYN does not. Connecting
	// first provides an OS-owned tuple without releasing an ephemeral port.
	runCtx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()); cancel() })
	trial, err := start(runCtx, d.base, host, c.LocalAddr().(*net.TCPAddr).Port, strategy, io.Discard)
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		cancel()
		if trial != nil {
			err = errors.Join(err, trial.Stop())
		}
		_ = c.Close()
		if errors.Is(err, ErrCleanupUnconfirmed) {
			d.blocked = err
		}
		unlock()
		return nil, err
	}
	return &shapedConn{Conn: c, finish: func() error {
		// Stop before closing the owning TCP socket: keep its tuple reserved.
		err := trial.Stop()
		cancel()
		if errors.Is(err, ErrCleanupUnconfirmed) {
			d.blocked = err
		}
		unlock()
		return err
	}}, nil
}

type shapedConn struct {
	net.Conn
	once   sync.Once
	finish func() error
	err    error
}

func (c *shapedConn) finishFilter() error { c.once.Do(func() { c.err = c.finish() }); return c.err }
func (c *shapedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 || err != nil {
		if cleanup := c.finishFilter(); cleanup != nil {
			return 0, cleanup
		}
	}
	return n, err
}
func (c *shapedConn) Close() error {
	_ = c.Conn.SetDeadline(time.Now())
	cleanup := c.finishFilter()
	return errors.Join(cleanup, c.Conn.Close())
}
