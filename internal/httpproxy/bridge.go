// Package httpproxy exposes a loopback-only HTTP proxy for software (such as
// Windscribe) that supports an upstream HTTP proxy but not a SOCKS5 proxy.
// TLS remains end-to-end between the application and its destination.
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
	"strconv"
	"strings"
	"time"
)

// Server bridges HTTP CONNECT or absolute-form HTTP requests into a local
// SOCKS5 CONNECT server. It does not change system DNS, routes or certificates.
// Dial, when supplied, replaces the generic SOCKS5 bridge. Windscribe uses it
// to restrict HTTP CONNECT to local anti-DPI paths. HTTP 200 only confirms TCP.
type Server struct {
	Upstream string
	Dial     func(context.Context, string, string) (net.Conn, error)
}

func isLoopback(addr net.Addr) bool {
	t, ok := addr.(*net.TCPAddr)
	return ok && t.IP != nil && t.IP.IsLoopback()
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if !isLoopback(listener.Addr()) {
		return errors.New("refusing non-loopback HTTP proxy listener")
	}
	up, err := net.ResolveTCPAddr("tcp", s.Upstream)
	if err != nil || up.IP == nil || !up.IP.IsLoopback() || up.Port == 0 {
		return errors.New("SOCKS5 upstream must be a loopback address")
	}
	if listener.Addr().String() == up.String() {
		return errors.New("HTTP bridge cannot proxy through itself")
	}
	server := &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 8 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { <-ctx.Done(); _ = server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || (ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func validTarget(addr string) (string, int, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "", 0, errors.New("CONNECT requires host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid target port")
	}
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return "", 0, errors.New("loopback destinations are not permitted")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return "", 0, errors.New("local destinations are not permitted")
		}
	} else if len(host) > 255 || strings.ContainsAny(host, "\x00/\\ \t\r\n@") {
		return "", 0, errors.New("invalid target hostname")
	}
	return host, port, nil
}

func (s *Server) socksDial(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := validTarget(target)
	if err != nil {
		return nil, err
	}
	if s.Dial != nil {
		return s.Dial(ctx, host, strconv.Itoa(port))
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", s.Upstream)
	if err != nil {
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(conn, greeting); err != nil {
		return nil, err
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		return nil, errors.New("SOCKS5 authentication unavailable")
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err = conn.Write(req); err != nil {
		return nil, err
	}
	reply := make([]byte, 4)
	if _, err = io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 CONNECT rejected (code %d)", reply[1])
	}
	length := 0
	switch reply[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		b := []byte{0}
		if _, err = io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		length = int(b[0])
	default:
		return nil, errors.New("bad SOCKS5 address type")
	}
	if _, err = io.CopyN(io.Discard, conn, int64(length+2)); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	good = true
	return conn, nil
}

func closeWrite(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.CloseWrite()
	}
}

func relay(client net.Conn, buffered *bufio.ReadWriter, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, buffered); closeWrite(upstream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); closeWrite(client); done <- struct{}{} }()
	<-done
	// A half-close must leave time for the remote side's final response.
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	_ = upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
	<-done
}

func removeHopHeaders(h http.Header) {
	for _, field := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(field))
	}
	for _, field := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(field)
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		upstream, err := s.socksDial(r.Context(), r.Host)
		if err != nil {
			http.Error(w, "upstream connect failed", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			upstream.Close()
			http.Error(w, "hijack unsupported", 500)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
			err = buffered.Flush()
		}
		if err != nil {
			client.Close()
			upstream.Close()
			return
		}
		relay(client, buffered, upstream)
		return
	}
	// Support absolute-form HTTP requests for clients with non-CONNECT API calls.
	if r.URL == nil || !r.URL.IsAbs() || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		http.Error(w, "absolute URL or CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	target := r.URL.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		port := "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
		target = net.JoinHostPort(r.URL.Hostname(), port)
	}
	if _, _, err := validTarget(target); err != nil {
		http.Error(w, "target blocked", http.StatusForbidden)
		return
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 20 * time.Second,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) { return s.socksDial(ctx, address) },
	}
	defer transport.CloseIdleConnections()
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.Header = r.Header.Clone()
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	removeHopHeaders(req.Header)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ProxyURL helps integration tests and optional HTTP-aware clients.
func ProxyURL(addr string) (*url.URL, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("HTTP proxy URL must be loopback")
	}
	return &url.URL{Scheme: "http", Host: addr}, nil
}
