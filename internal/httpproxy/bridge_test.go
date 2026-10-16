package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeSocks verifies that names are passed to the SOCKS5 server (remote DNS).
func fakeSocks(t *testing.T) (string, <-chan string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	names := make(chan string, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(c, greeting); err != nil {
					return
				}
				if string(greeting) != string([]byte{5, 1, 0}) {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				if hdr[0] != 5 || hdr[1] != 1 || hdr[3] != 3 {
					return
				}
				sz := []byte{0}
				if _, err := io.ReadFull(c, sz); err != nil {
					return
				}
				b := make([]byte, int(sz[0])+2)
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				names <- string(b[:len(b)-2])
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				_ = c.SetDeadline(time.Time{})
				data := make([]byte, 1024)
				n, err := c.Read(data)
				if err != nil {
					return
				}
				if strings.HasPrefix(string(data[:n]), "GET") {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello!"))
				} else {
					_, _ = c.Write(data[:n])
				}
			}()
		}
	}()
	return l.Addr().String(), names, func() { _ = l.Close(); <-done }
}

func bridge(t *testing.T, socks string) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{Upstream: socks}).Serve(ctx, l) }()
	return l.Addr().String(), func() { cancel(); _ = l.Close(); <-done }
}

func TestCONNECTPreservesSNIBytesAndRemoteDNS(t *testing.T) {
	socks, names, finish := fakeSocks(t)
	defer finish()
	endpoint, stop := bridge(t, socks)
	defer stop()
	c, err := net.DialTimeout("tcp", endpoint, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT api.windscribe.com:443 HTTP/1.1\r\nHost: api.windscribe.com:443\r\n\r\n")
	reader := bufio.NewReader(c)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q %v", line, err)
	}
	_, _ = reader.ReadString('\n')
	_, _ = c.Write([]byte("opaque TLS bytes"))
	answer := make([]byte, len("opaque TLS bytes"))
	if _, err := io.ReadFull(reader, answer); err != nil {
		t.Fatal(err)
	}
	if string(answer) != "opaque TLS bytes" {
		t.Fatalf("got %q", answer)
	}
	select {
	case name := <-names:
		if name != "api.windscribe.com" {
			t.Fatalf("remote DNS host %q", name)
		}
	case <-time.After(time.Second):
		t.Fatal("missing host")
	}
}

func TestHTTPAbsoluteFormProxy(t *testing.T) {
	socks, names, finish := fakeSocks(t)
	defer finish()
	endpoint, stop := bridge(t, socks)
	defer stop()
	transport := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return ProxyURL(endpoint) }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get("http://api.windscribe.com/check")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || string(b) != "hello!" {
		t.Fatalf("body %q: %v", b, err)
	}
	if name := <-names; name != "api.windscribe.com" {
		t.Fatalf("host %q", name)
	}
}

func TestRejectLocalTargets(t *testing.T) {
	for _, target := range []string{"127.0.0.1:80", "[::1]:443", "localhost:1234", "example.org:0", "example.org:99999"} {
		if _, _, err := validTarget(target); err == nil {
			t.Fatalf("accepted %s", target)
		}
	}
	if _, _, err := validTarget("api.windscribe.com:443"); err != nil {
		t.Fatal(err)
	}
}
func TestRefuseNonLoopbackBind(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	if err := (&Server{Upstream: "127.0.0.1:10800"}).Serve(context.Background(), l); err == nil {
		t.Fatal("accepted wildcard listener")
	}
}

func TestWindscribeStrictCONNECTRejectsBeforeAcknowledgement(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	dialed := make(chan string, 1)
	go func() {
		finished <- (&Server{
			Upstream: "127.0.0.1:19001",
			Dial: func(_ context.Context, host, port string) (net.Conn, error) {
				dialed <- net.JoinHostPort(host, port)
				return nil, errors.New("no verified foreign exit")
			},
		}).Serve(ctx, l)
	}()
	defer func() { cancel(); _ = l.Close(); <-finished }()
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "CONNECT 198.51.100.15:443 HTTP/1.1\r\nHost: 198.51.100.15:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, "502") {
		t.Fatalf("expected 502 instead of false 200, got %q %v", line, err)
	}
	select {
	case dest := <-dialed:
		if dest != "198.51.100.15:443" {
			t.Fatal(dest)
		}
	case <-time.After(time.Second):
		t.Fatal("strict dial was not called")
	}
}
