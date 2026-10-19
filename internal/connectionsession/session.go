// Package connectionsession owns the portable connection lifetime shared by
// the terminal and Android. Platform clients supply routing and native cores;
// this package owns local listeners and cancels every stream on failure/stop.
package connectionsession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/Nishef1/ktest/internal/httpproxy"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

type Session struct {
	Proxy     *smartproxy.Proxy
	SOCKS     net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	listeners []net.Listener
	err       error
	wg        sync.WaitGroup
}

func Start(parent context.Context, proxy *smartproxy.Proxy, address string) (*Session, error) {
	if proxy == nil {
		return nil, errors.New("connection requires a Go proxy")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Session{Proxy: proxy, SOCKS: listener, ctx: ctx, cancel: cancel, listeners: []net.Listener{listener}}
	s.wg.Go(func() { proxy.MaintainHistory(ctx) })
	s.serve("SOCKS", listener, func() error { return proxy.Serve(ctx, listener) })
	return s, nil
}

func (s *Session) serve(name string, listener net.Listener, run func() error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer listener.Close()
		err := run()
		if s.ctx.Err() == nil {
			if err == nil {
				err = errors.New("listener stopped unexpectedly")
			}
			s.mu.Lock()
			if s.err == nil {
				s.err = fmt.Errorf("%s: %w", name, err)
			}
			s.mu.Unlock()
			s.cancel()
		}
	}()
}

func (s *Session) listen(address string) (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	s.listeners = append(s.listeners, listener)
	return listener, nil
}

// StartHTTP uses the same learned Go routes, or the caller's Windscribe-only
// dial contract. It never constructs an independent transport engine.
func (s *Session) StartHTTP(address string, dial func(context.Context, string, string) (net.Conn, error)) (string, error) {
	listener, err := s.listen(address)
	if err != nil {
		return "", err
	}
	bridge := &httpproxy.Server{Upstream: s.SOCKS.Addr().String(), Dial: dial}
	s.serve("HTTP", listener, func() error { return bridge.Serve(s.ctx, listener) })
	return listener.Addr().String(), nil
}

func (s *Session) StartProbes() (int, error) {
	listener, err := s.listen("127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	s.serve("probes", listener, func() error { return s.Proxy.ServeProbes(s.ctx, listener) })
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func (s *Session) Done() <-chan struct{} { return s.ctx.Done() }

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Stop is idempotent and waits for listeners to end. Cancellation closes
// existing SOCKS, UDP associations and hijacked HTTP CONNECT streams too.
// Callers serialize StartHTTP/StartProbes with Stop.
func (s *Session) Stop() {
	s.cancel()
	s.mu.Lock()
	for _, listener := range s.listeners {
		_ = listener.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
