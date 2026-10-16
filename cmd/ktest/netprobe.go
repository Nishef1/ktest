package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// cutConn routes the first Write (the ClientHello) through a cutting family,
// so a normal crypto/tls handshake exercises that family.
type cutConn struct {
	net.Conn
	send func(net.Conn, []byte) error
	done bool
}

func (c *cutConn) Write(p []byte) (int, error) {
	if !c.done && c.send != nil {
		c.done = true
		if err := c.send(c.Conn, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// handshake opens ip:443, sends the ClientHello cut by send (nil = untouched)
// and requires a certificate-verified TLS handshake for sni.
func handshake(ctx context.Context, ip, sni string, send func(net.Conn, []byte) error) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(6 * time.Second))
	c := tls.Client(&cutConn{Conn: raw, send: send}, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
	return c.HandshakeContext(ctx)
}

func shortErr(err error) string {
	if err == nil {
		return "ok"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "reset") || strings.Contains(s, "forcibly"):
		return "reset"
	case err == io.EOF || strings.Contains(s, "EOF"):
		return "closed"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "certificate"):
		return "bad cert"
	}
	if len(s) > 18 {
		s = s[:18]
	}
	return s
}

// networkProbe characterizes the current network without any proxy: what the
// resolver returns, whether the usual DoH endpoints are reachable, and which
// ClientHello shapes get through to Google for an unblocked and a blocked SNI.
// It uses one connection per cell and sends no HTTP.
func networkProbe(ctx context.Context, out io.Writer, line func(level, name, detail string)) {
	// 1. What the system resolver says.
	var googleIP string
	for _, host := range []string{"www.google.com", "www.youtube.com", "example.org"} {
		rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ips, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
		cancel()
		switch {
		case err != nil:
			line("WARN", "dns "+host, "no answer: "+shortErr(err))
		case smartproxy.Bogus(ips[0]):
			line("WARN", "dns "+host, fmt.Sprintf("POISONED: system DNS answers %s (a private block-page address)", ips[0]))
		default:
			line("OK", "dns "+host, ips[0].String())
			if host == "www.google.com" {
				googleIP = ips[0].String()
			}
		}
	}

	// 2. Encrypted DNS by IP literal: reachable at all, no DNS needed.
	var wg sync.WaitGroup
	var mu sync.Mutex
	dohOK := 0
	rows := make([]string, 0, len(smartproxy.DefaultDoH))
	for _, ep := range smartproxy.DefaultDoH {
		if ep.Addr == "" {
			continue
		}
		wg.Add(1)
		go func(ep smartproxy.DoHEndpoint) {
			defer wg.Done()
			host, _, _ := net.SplitHostPort(ep.Addr)
			err := handshake(ctx, host, ep.ServerName, nil)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				dohOK++
			}
			rows = append(rows, fmt.Sprintf("%s via %s: %s", ep.ServerName, ep.Addr, shortErr(err)))
		}(ep)
	}
	wg.Wait()
	sort.Strings(rows)
	level := "OK"
	if dohOK == 0 {
		level = "WARN"
	}
	line(level, "encrypted DNS", fmt.Sprintf("%d of %d resolver addresses complete a TLS handshake", dohOK, len(rows)))
	for _, r := range rows {
		fmt.Fprintf(out, "      %s\n", r)
	}

	// 3. ClientHello shapes to Google, unblocked vs blocked SNI.
	if googleIP == "" {
		line("WARN", "tls matrix", "skipped: no usable address for www.google.com")
		return
	}
	type family struct {
		name string
		send func(net.Conn, []byte) error
	}
	families := []family{{"plain (uncut)", nil}}
	for _, u := range smartproxy.DesyncUpstreams() {
		if u.Network == "" {
			families = append(families, family{strings.TrimPrefix(u.Name, "self: "), u.Send})
		}
	}
	snis := []string{"www.google.com", "www.youtube.com"}
	cells := make([][]error, len(snis))
	for i := range cells {
		cells[i] = make([]error, len(families))
		for j := range cells[i] {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				cells[i][j] = handshake(ctx, googleIP, snis[i], families[j].send)
			}(i, j)
		}
	}
	wg.Wait()
	fmt.Fprintf(out, "      TLS handshakes to Google front end %s (certificate verified for the SNI shown):\n", googleIP)
	fmt.Fprintf(out, "      %-34s %-18s %-18s\n", "ClientHello shape", snis[0], snis[1])
	for j, f := range families {
		fmt.Fprintf(out, "      %-34s %-18s %-18s\n", f.name, shortErr(cells[0][j]), shortErr(cells[1][j]))
	}

	// 4. Interpretation.
	okAt := func(i, j int) bool { return cells[i][j] == nil }
	anyCut := func(i int) bool {
		for j := 1; j < len(families); j++ {
			if okAt(i, j) {
				return true
			}
		}
		return false
	}
	switch {
	case !okAt(0, 0) && !anyCut(0):
		line("FAIL", "verdict", "cannot complete any TLS handshake to a Google address here; check connectivity before blaming a method")
	case okAt(0, 0) && okAt(1, 0):
		line("INFO", "verdict", "YouTube's SNI passes uncut: nothing to bypass on this path right now (another VPN carrying the traffic looks the same)")
	case okAt(0, 0) && !okAt(1, 0) && anyCut(1):
		line("OK", "verdict", "YouTube's SNI is filtered but a cut ClientHello gets through: the cutting paths in `ktest smart` can work here")
	case okAt(0, 0) && !okAt(1, 0) && !anyCut(1) && !anyCut(0):
		line("WARN", "verdict", "YouTube's SNI is filtered AND every cut ClientHello fails even for the unblocked name: this network punishes cutting, so Xray fragment, ByeDPI split/tlsrec and the self: paths cannot work; only methods that do not cut (fake packets with a low TTL, IPv6, QUIC) remain")
	default:
		line("WARN", "verdict", "YouTube's SNI is filtered and cutting helps only partly; see the table")
	}
}
