package httpproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestStoppingBridgeClosesActiveCONNECT(t *testing.T) {
	for _, shutdown := range []string{"context", "listener"} {
		t.Run(shutdown, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, z := net.Pipe()
			defer a.Close()
			defer z.Close()
			s := &Server{Upstream: "127.0.0.1:10800", Dial: func(context.Context, string, string) (net.Conn, error) { return a, nil }}
			finished := make(chan error, 1)
			go func() { finished <- s.Serve(ctx, l) }()
			c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = fmt.Fprint(c, "CONNECT api.windscribe.com:443 HTTP/1.1\r\nHost: api.windscribe.com:443\r\n\r\n")
			r := bufio.NewReader(c)
			response, err := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT status %d", response.StatusCode)
			}
			if shutdown == "context" {
				cancel()
			} else {
				_ = l.Close()
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("HTTP server did not stop")
			}
			for name, conn := range map[string]net.Conn{"client": c, "upstream": z} {
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				_, err := conn.Read(make([]byte, 1))
				if err == nil {
					t.Fatalf("%s remained readable after shutdown", name)
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatalf("%s was left open after shutdown", name)
				}
			}
		})
	}
}
