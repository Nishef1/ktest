package smartproxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A recovered SNI may steer routing, but the connection must still go to the
// numeric address the client chose (e.g. an Aether gateway with a decoy SNI).
func TestRecoveredSNIRoutesButDialsTheOriginalAddress(t *testing.T) {
	requested := make(chan string, 4)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				host, port, err := socksRequest(c)
				if err != nil {
					return
				}
				requested <- net.JoinHostPort(host, port)
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	p, err := New(Config{Upstreams: []Upstream{{Name: "upstream", Addr: l.Addr().String()}},
		RecoverIPHostSNI: true, FirstByteTimeout: 200 * time.Millisecond, ConnectTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); front.Close() })
	go func() { _ = p.Serve(ctx, front) }()
	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(c, make([]byte, 2))
	_, _ = c.Write([]byte{5, 1, 0, 1, 9, 9, 9, 9, 1, 187})
	_, _ = io.ReadFull(c, make([]byte, 10))
	_, _ = c.Write(helloWithExtensions(sniExtension("decoy.example.com")))
	select {
	case got := <-requested:
		if got != "9.9.9.9:443" {
			t.Fatalf("dialed %s instead of the client's address", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream was never asked to connect")
	}
}
