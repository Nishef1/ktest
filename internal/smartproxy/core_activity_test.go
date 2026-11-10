package smartproxy

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoreActivityTracksLoopbackDownstream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if got := LastCoreDownstream(ln.Addr().String()); !got.IsZero() {
		t.Fatalf("activity before any data = %v, want zero", got)
	}
	var n atomic.Int64
	r := countedReader{r: conn, n: &n, also: coreActivityFor(conn)}
	buf := make([]byte, 16)
	if _, err := r.Read(buf); err != nil {
		t.Fatal(err)
	}
	got := LastCoreDownstream(ln.Addr().String())
	if got.IsZero() || time.Since(got) > 5*time.Second {
		t.Fatalf("activity after data = %v, want recent", got)
	}
}

func TestCoreActivityIgnoresNonLoopback(t *testing.T) {
	if coreActivityFor(fakeRemote{net.ParseIP("203.0.113.9")}) != nil {
		t.Fatal("non-loopback upstream must not be tracked")
	}
}

type fakeRemote struct{ ip net.IP }

func (f fakeRemote) Read([]byte) (int, error)         { return 0, nil }
func (f fakeRemote) Write(b []byte) (int, error)      { return len(b), nil }
func (f fakeRemote) Close() error                     { return nil }
func (f fakeRemote) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (f fakeRemote) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: f.ip, Port: 1} }
func (f fakeRemote) SetDeadline(time.Time) error      { return nil }
func (f fakeRemote) SetReadDeadline(time.Time) error  { return nil }
func (f fakeRemote) SetWriteDeadline(time.Time) error { return nil }
