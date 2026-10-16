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
	case strings.Contains(s, "poisoned"):
		return "no trusted address (DNS poisoned)"
	}
	if len(s) > 18 {
		s = s[:18]
	}
	return s
}

// systemDNS asks the operating system's resolver and says whether the answer is
// a private block-page address, which is what a poisoning resolver returns.
func systemDNS(ctx context.Context, host string) (ip string, poisoned bool, err error) {
	rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("no address")
		}
		return "", false, err
	}
	return ips[0].String(), smartproxy.Bogus(ips[0]), nil
}

// netReport is what the network characterization measured.
type netReport struct {
	dns         []dnsRow
	doh         []string
	dohOK       int
	googleIP    string
	families    []string
	snis        []string
	cells       [][]error // [sni][family]
	verdict     tone
	verdictText string
}

type dnsRow struct {
	host, ip string
	state    string // ok, poisoned, none
	err      string
}

// probeNetwork characterizes the current network without any proxy: what the
// resolver returns, whether the usual DoH endpoints are reachable, and which
// ClientHello shapes get through to Google for an unblocked and a blocked SNI.
// It uses one connection per cell and sends no HTTP. step is told when each of
// the three stages is done.
func probeNetwork(ctx context.Context, step func(done int)) netReport {
	var r netReport
	// 1. What the system resolver says.
	for _, host := range []string{"www.google.com", "www.youtube.com", "example.org"} {
		ip, poisoned, err := systemDNS(ctx, host)
		switch {
		case err != nil:
			r.dns = append(r.dns, dnsRow{host: host, state: "none", err: shortErr(err)})
		case poisoned:
			r.dns = append(r.dns, dnsRow{host: host, ip: ip, state: "poisoned"})
		default:
			r.dns = append(r.dns, dnsRow{host: host, ip: ip, state: "ok"})
			if host == "www.google.com" {
				r.googleIP = ip
			}
		}
	}
	step(1)

	// 2. Encrypted DNS by IP literal: reachable at all, no DNS needed.
	var wg sync.WaitGroup
	var mu sync.Mutex
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
				r.dohOK++
			}
			r.doh = append(r.doh, fmt.Sprintf("%s via %s: %s", ep.ServerName, ep.Addr, shortErr(err)))
		}(ep)
	}
	wg.Wait()
	sort.Strings(r.doh)
	step(2)

	// 3. ClientHello shapes to Google, unblocked vs blocked SNI.
	if r.googleIP == "" {
		r.verdict, r.verdictText = toneWarn, "No usable address for www.google.com, so ClientHello shapes could not be compared."
		step(3)
		return r
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
	r.snis = []string{"www.google.com", "www.youtube.com"}
	r.cells = make([][]error, len(r.snis))
	for i := range r.cells {
		r.cells[i] = make([]error, len(families))
		for j := range r.cells[i] {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				r.cells[i][j] = handshake(ctx, r.googleIP, r.snis[i], families[j].send)
			}(i, j)
		}
	}
	wg.Wait()
	for _, f := range families {
		r.families = append(r.families, f.name)
	}
	step(3)

	okAt := func(i, j int) bool { return r.cells[i][j] == nil }
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
		r.verdict, r.verdictText = toneFail, "No TLS handshake to a Google address completes here. Check connectivity before blaming a method."
	case okAt(0, 0) && okAt(1, 0):
		r.verdict, r.verdictText = toneInfo, "YouTube's SNI passes uncut: nothing is being filtered on this path right now. Another VPN carrying the traffic looks the same."
	case okAt(0, 0) && !okAt(1, 0) && anyCut(1):
		r.verdict, r.verdictText = toneOK, "YouTube's SNI is filtered but a cut ClientHello gets through: the cutting paths in Connect can work here."
	case okAt(0, 0) && !okAt(1, 0) && !anyCut(1) && !anyCut(0):
		r.verdict, r.verdictText = toneWarn, "YouTube's SNI is filtered AND every cut ClientHello fails even for the unblocked name: this network punishes cutting. Xray fragment, ByeDPI split/slice and the built-in cutting paths cannot work; only methods that do not cut (fake packets with a low TTL, IPv6, QUIC) remain."
	case okAt(0, 0) && !okAt(1, 0) && !anyCut(1):
		r.verdict, r.verdictText = toneWarn, "YouTube's SNI is filtered and no cutting shape gets through: cuts across TCP segments are reassembled by the filter, and cuts across TLS records are dropped (even for Google). Xray fragment, ByeDPI split/slice and the built-in cuts will not help here; domain fronting and fake-packet strategies are what remain."
	default:
		r.verdict, r.verdictText = toneWarn, "YouTube's SNI is filtered and cutting helps only partly; see the table."
	}
	return r
}

// print renders the report.
func (r netReport) print(u *term) {
	for _, d := range r.dns {
		switch d.state {
		case "ok":
			u.Line(toneOK, "%-26s %s", "DNS "+d.host, d.ip)
		case "poisoned":
			u.Line(toneWarn, "%-26s %s", "DNS "+d.host, u.Yellow("POISONED")+u.Dim(" → "+d.ip+" (private block-page address)"))
		default:
			u.Line(toneWarn, "%-26s no answer (%s)", "DNS "+d.host, d.err)
		}
	}
	k := toneOK
	if r.dohOK == 0 {
		k = toneWarn
	}
	u.Line(k, "%-26s %d of %d resolver addresses complete a TLS handshake", "Encrypted DNS", r.dohOK, len(r.doh))
	for _, row := range r.doh {
		u.Note("%s", row)
	}
	if len(r.cells) == 0 {
		return
	}
	u.Println("")
	u.Println("  " + u.Bold("ClientHello shapes") + u.Dim(" → Google front end "+r.googleIP+", certificate verified for the SNI"))
	pad := func(s string, n int) string { return s + strings.Repeat(" ", max(n-visibleLen(s), 0)) }
	u.Printf("    %s %s %s\n", pad("", 34), pad(u.Dim(r.snis[0]), 18), u.Dim(r.snis[1]))
	cell := func(err error) string {
		if err == nil {
			return u.Green(u.glyph(toneOK) + " ok")
		}
		return u.Red(u.glyph(toneFail) + " " + shortErr(err))
	}
	for j, name := range r.families {
		u.Printf("    %s %s %s\n", pad(name, 34), pad(cell(r.cells[0][j]), 18), cell(r.cells[1][j]))
	}
}
