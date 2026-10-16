package smartproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWindscribeRequiresVerifiedExit(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "direct"},
		{Name: "unverified", Addr: "127.0.0.1:19998", Exit: true},
	}})
	if err != nil { t.Fatal(err) }
	if p.HasVerifiedExit() { t.Fatal("unverified proxy wrongly accepted") }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := p.DialVerifiedExit(ctx, "198.51.100.15", "443")
	if c != nil { _ = c.Close(); t.Fatal("unsafe direct connection") }
	if err == nil || !strings.Contains(err.Error(), "no verified foreign") { t.Fatalf("unexpected error: %v", err) }
}

func TestWindscribeVerifiedSocksAndSessionPin(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer l.Close()
	got := make(chan string, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil { return }
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 3)
				if _, err := io.ReadFull(c, buf); err != nil { return }
				if _, err := c.Write([]byte{5, 0}); err != nil { return }
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(c, hdr); err != nil { return }
				if hdr[0] != 5 || hdr[1] != 1 || hdr[3] != 1 { return }
				dest := make([]byte, 6)
				if _, err := io.ReadFull(c, dest); err != nil { return }
				if binary.BigEndian.Uint16(dest[4:]) != 443 { return }
				got <- net.IP(dest[:4]).String()
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	defer func(){ _ = l.Close(); <-done }()
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "direct", Rank: 0},
		{Name: "verified", Addr: l.Addr().String(), Exit: true, AIEligible: true, Rank: 5},
	}})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.DialVerifiedExit(ctx, "198.51.100.15", "443")
	if err != nil { t.Fatal(err) }
	_ = c.Close()
	if target := <-got; target != "198.51.100.15" { t.Fatal(target) }
	p.mu.Lock()
	pinned := p.bootstrapPinned
	p.mu.Unlock()
	if pinned != "verified" { t.Fatalf("bootstrap was not pinned: %s", pinned) }
}
