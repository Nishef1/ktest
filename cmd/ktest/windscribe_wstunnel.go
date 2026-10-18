package main

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/wstunnel"
)

// wsOptions configures the WStunnel bridge in Windscribe mode. Windscribe is
// set to OpenVPN TCP with ktest as its HTTP proxy; ktest re-wraps that OpenVPN
// stream the way Windscribe's own WStunnel protocol does, but with a chosen
// SNI, a browser TLS fingerprint and optionally through the user's own CDN
// hostname. The exit is always the Windscribe server: no other proxy or VPN
// sees the decrypted traffic.
type wsOptions struct {
	direct   bool
	sni      string // comma-separated SNIs for direct mode
	serverIP string // explicit WStunnel server IP; otherwise provider node list
	path     string
	cdnHost  string // user's CDN hostname whose origin is a Windscribe WStunnel IP
	cdnSNI   string
	cdnEdges string // comma-separated edge IPs or names
}

// defaultWindscribeSNIs are raced on the direct carriers: names a filtering
// SNI allowlist is likely to pass. The Windscribe node ignores the SNI.
const defaultWindscribeSNIs = "www.speedtest.net,www.digikala.com,www.aparat.com"

func (o wsOptions) enabled() bool { return o.direct || o.cdnHost != "" }

// describe names the WStunnel carriers for the connect summary.
func (o wsOptions) describe() string {
	var parts []string
	if o.cdnHost != "" {
		parts = append(parts, "CDN "+o.cdnHost)
	}
	if o.direct {
		parts = append(parts, "SNI "+strings.Join(splitList(o.sni), ","))
	}
	return "WStunnel/Stealth race (" + strings.Join(parts, "; ") + ")"
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil || strings.ContainsAny(h, "/:@ \t\r\n\\") || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (o wsOptions) validate() error {
	for _, s := range splitList(o.sni) {
		if !validHostname(s) {
			return fmt.Errorf("-windscribe-wstunnel-sni %q is not a hostname", s)
		}
	}
	if o.serverIP != "" {
		if ip := net.ParseIP(o.serverIP); ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return fmt.Errorf("-windscribe-wstunnel-ip %q must be a public IPv4 address", o.serverIP)
		}
	}
	if o.path != "" && (!strings.HasPrefix(o.path, "/tcp/127.0.0.1/") || strings.ContainsAny(o.path, " \r\n?#")) {
		return fmt.Errorf("-windscribe-wstunnel-path %q must look like /tcp/127.0.0.1/1194", o.path)
	}
	if o.cdnHost == "" {
		if o.cdnSNI != "" || o.cdnEdges != "" {
			return errors.New("-windscribe-cdn-sni and -windscribe-cdn-edge need -windscribe-cdn")
		}
		return nil
	}
	if strings.Contains(o.cdnHost, "://") || !validHostname(o.cdnHost) {
		return fmt.Errorf("-windscribe-cdn %q must be a bare hostname such as ws.example.com", o.cdnHost)
	}
	if o.cdnSNI != "" && !validHostname(o.cdnSNI) {
		return fmt.Errorf("-windscribe-cdn-sni %q is not a hostname", o.cdnSNI)
	}
	for _, e := range splitList(o.cdnEdges) {
		host := e
		if h, p, err := net.SplitHostPort(e); err == nil {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("-windscribe-cdn-edge %q has a bad port", e)
			}
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsGlobalUnicast() || ip.IsPrivate() {
				return fmt.Errorf("-windscribe-cdn-edge %q must be a public address", e)
			}
		} else if !validHostname(host) {
			return fmt.Errorf("-windscribe-cdn-edge %q is neither an IP nor a hostname", e)
		}
	}
	return nil
}

// wsCarrier is one way to carry a Windscribe OpenVPN TCP stream.
type wsCarrier struct {
	name   string
	method string // actual local technique, shared by its transport/SNI variants
	open   func(ctx context.Context, host, port string) (net.Conn, error)
	addr   string
	source string
}

// wsBridge decides, per HTTP CONNECT from Windscribe, how to carry it. Names
// (Windscribe API/DNS calls) keep the existing local anti-DPI dialer. An IP
// target is held until Windscribe's first bytes arrive: TLS/HTTP keeps the
// local dialer; OpenVPN is raced over every carrier and the first one whose
// server returns data carries the stream, including later client writes.
type wsActiveCarrier struct {
	id          uint64
	key         string
	name        string
	started     time.Time
	confirmed   bool // correlated with unique CLI TCP Connected transition, not cryptographic identity
	upstreamEnd bool // upstream read terminated before ktest locally closed the stream
}

type wsBridge struct {
	opts         wsOptions
	path         string
	local        func(ctx context.Context, host, port string) (net.Conn, error)
	carrierLocal func(ctx context.Context, host, port string) (net.Conn, error)
	report       func(smartproxy.Event)
	logf         func(string, ...any)
	note         func(string, ...any) // always shown (edge scan progress)
	stagger      time.Duration
	replyTimeout time.Duration // TCP, TLS/upgrade and initial OpenVPN reply per carrier
	catalog      *wsNodeCatalog
	methods      func() []smartproxy.WindscribeMethod
	view         *wsProgressView
	onProgress   func(string, bool) // nonblocking notification; rendering belongs to the live feed
	// candidates overrides the carrier list (tests).
	candidates func(host string) []wsCarrier

	mu          sync.Mutex
	edges       []string                        // CDN edges found by the scan, best first
	good        map[string]string               // destination -> carrier that carried a working VPN
	bad         map[string]map[string]time.Time // destination -> carrier -> demoted until
	retries     map[string]uint64               // attempt index for choosing independent alternatives
	active      map[*wsActiveCarrier]bool       // streams awaiting CLI state correlation
	shortEnds   map[string]int                  // consecutive short unexpected ends of correlated sessions
	nextAttempt uint64
	targets     map[string]*wsTargetProgress
}

// CLI authentication is attributed only if a single OpenVPN stream is
// active at the moment Windscribe transitions to Connected over TCP.
// Concurrent candidate streams are ambiguous, so none is credited.
func (b *wsBridge) observeCLIConnected() {
	b.mu.Lock()
	key := ""
	defer func() {
		b.mu.Unlock()
		if key != "" {
			b.publishProgress(key, true)
		}
	}()
	if len(b.active) != 1 {
		if b.logf != nil {
			b.logf("Windscribe CLI Connected correlation ambiguous: active-carriers=%d; no carrier promoted", len(b.active))
		}
		return
	}
	for active := range b.active {
		// A long-lived leftover socket from an earlier connection attempt
		// must not be credited when an unrelated CLI session changes state.
		// CLI state has no authoritative link to the carrier socket.
		if active.upstreamEnd || active.started.IsZero() || time.Since(active.started) > 90*time.Second {
			return
		}
		active.confirmed = true
		key = active.key
		if target := b.targets[key]; target != nil {
			if p := target.paths[active.name]; p != nil {
				p.last, p.updated = "connected (Windscribe CLI)", time.Now()
			}
		}
		if b.logf != nil {
			b.logf("Windscribe attempt=%d target=%s carrier=%s correlated with CLI TCP Connected (not cryptographically attributable)", active.id, active.key, active.name)
		}
		// A real Windscribe TCP Connected transition is stronger evidence
		// than an arbitrary 60-second/64-KiB threshold. This session is
		// uniquely attributable, and already passed OpenVPN authentication.
		b.good[active.key] = active.name
		delete(b.bad[active.key], active.name)
	}
}

// windscribeServerCert rejects certificates without a Windscribe hostname.
// The inner OpenVPN client performs the authenticated server verification.
func windscribeServerCert(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.New("no certificate")
	}
	names := append([]string{certs[0].Subject.CommonName}, certs[0].DNSNames...)
	for _, n := range names {
		name := strings.ToLower(n)
		// Current Windscribe mob-v2 node hostnames use whiskergalaxy.com
		// in addition to the legacy windscribe.com domain. Checking only
		// the older suffix excludes legitimate advertised WStunnel nodes.
		if strings.HasSuffix(name, ".windscribe.com") || strings.HasSuffix(name, ".whiskergalaxy.com") {
			return nil
		}
	}
	return errors.New("server is not a Windscribe node")
}

func newWSBridge(o wsOptions, local func(context.Context, string, string) (net.Conn, error), report func(smartproxy.Event), logf func(string, ...any)) *wsBridge {
	path := o.path
	if path == "" {
		path = wstunnel.DefaultPath
	}
	b := &wsBridge{opts: o, path: path, local: local, carrierLocal: local, report: report, logf: logf, note: logf, stagger: 250 * time.Millisecond,
		replyTimeout: 12 * time.Second,
		good:         map[string]string{}, bad: map[string]map[string]time.Time{}, retries: map[string]uint64{}, active: map[*wsActiveCarrier]bool{}, shortEnds: map[string]int{}}
	for _, e := range splitList(o.cdnEdges) {
		if _, _, err := net.SplitHostPort(e); err != nil {
			e = net.JoinHostPort(e, "443")
		}
		b.edges = append(b.edges, e)
	}
	return b
}

func directDial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", addr)
}

// carriersFor lists every way to reach the Windscribe node behind host, in
// launch order: CDN, WStunnel and Stealth per SNI (each straight and through
// local anti-DPI), then the raw OpenVPN stream through local anti-DPI.
func (b *wsBridge) carriersFor(host string) []wsCarrier {
	if b.candidates != nil {
		return b.candidates(host)
	}
	viaLocal := func(ctx context.Context, addr string) (net.Conn, error) {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return b.carrierLocal(ctx, h, p)
	}
	type wsLeg struct {
		suffix  string
		method  string
		tlsOnly bool
		dial    func(context.Context, string) (net.Conn, error)
	}
	legs := []wsLeg{{method: "direct", dial: directDial}}
	if b.methods == nil {
		legs = append(legs, wsLeg{suffix: " +anti-DPI", method: "local anti-DPI rotation", dial: viaLocal})
	} else {
		for _, method := range b.methods() {
			if method.IPv6Only {
				continue
			} // provider carrier entries are IPv4
			legs = append(legs, wsLeg{suffix: " +" + method.Name, method: method.Name, tlsOnly: method.TLSOnly, dial: func(ctx context.Context, addr string) (net.Conn, error) {
				h, p, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return method.Dial(ctx, h, p)
			}})
		}
	}
	var out []wsCarrier
	o := b.opts
	if o.cdnHost != "" {
		sni := o.cdnSNI
		if sni == "" {
			sni = o.cdnHost
		}
		b.mu.Lock()
		edges := append([]string(nil), b.edges...)
		b.mu.Unlock()
		if len(edges) == 0 {
			edges = []string{net.JoinHostPort(o.cdnHost, "443")}
		}
		if len(edges) > 3 {
			edges = edges[:3]
		}
		for _, leg := range legs {
			for _, edge := range edges {
				out = append(out, wsCarrier{name: "CDN " + o.cdnHost + " entry=" + edge + leg.suffix, method: leg.method, addr: edge, source: "configured CDN", open: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return wstunnel.Dial(ctx, wstunnel.Config{Addr: edge, SNI: sni, Host: o.cdnHost, Path: b.path, Verify: true, Dial: leg.dial})
				}})
			}
		}
	}
	if o.direct {
		snis := splitList(o.sni)
		if len(snis) == 0 {
			snis = []string{""}
		}
		endpoints := b.catalog.endpoints(host)
		stealthEndpoints := b.catalog.endpointsByField(host, "ip3")
		if len(endpoints) == 0 && o.serverIP == "" {
			b.logf("Windscribe %s: no fresh provider node mapping; no IP neighbours guessed; raw destination retained", host)
		}
		for _, leg := range legs {
			for _, sni := range snis {
				label := sni
				if label == "" {
					label = "none"
				}
				wsEndpoints := endpoints
				if o.serverIP != "" {
					wsEndpoints = []wsEndpoint{{o.serverIP, "explicit override"}}
				}
				for _, endpoint := range wsEndpoints {
					addr := net.JoinHostPort(endpoint.ip, "443")
					// Preserve the known Chrome path and offer Windscribe's
					// upstream TLS fingerprint as a separately scored retry.
					// A ClientHello alone is not evidence of working OpenVPN.
					for _, fp := range []struct {
						name     string
						official bool
					}{{"chrome", false}, {"windscribe", true}} {
						out = append(out, wsCarrier{name: "WStunnel sni=" + label + leg.suffix + " entry=" + endpoint.ip + " hello=" + fp.name, method: leg.method, addr: addr, source: endpoint.source, open: func(ctx context.Context, _, _ string) (net.Conn, error) {
							return wstunnel.Dial(ctx, wstunnel.Config{Addr: addr, SNI: sni, Host: endpoint.ip, Path: b.path, VerifyPeer: windscribeServerCert, Dial: leg.dial, OfficialHello: fp.official})
						}})
					}
				}
				// Windscribe's published Android port map selects ip3 for
				// Stealth and ip2 for raw OpenVPN TCP. An ip3 TLS listener
				// cannot be inferred from the node's ip field. Explicit
				// server-IP overrides apply to WStunnel only.
				if o.serverIP == "" {
					for _, endpoint := range stealthEndpoints {
						addr := net.JoinHostPort(endpoint.ip, "443")
						for _, fp := range []struct {
							name     string
							official bool
						}{{"chrome", false}, {"windscribe", true}} {
							out = append(out, wsCarrier{name: "Stealth sni=" + label + leg.suffix + " entry=" + endpoint.ip + " hello=" + fp.name, method: leg.method, addr: addr, source: endpoint.source, open: func(ctx context.Context, _, _ string) (net.Conn, error) {
								// Windscribe's official wrapper leaves outer TLS chain
								// verification to the authenticated inner OpenVPN client.
								return wstunnel.DialStealth(ctx, wstunnel.Config{Addr: addr, SNI: sni, Dial: leg.dial, OfficialHello: fp.official})
							}})
						}
					}
				}
			}
		}
	}
	for _, leg := range legs[1:] {
		if !leg.tlsOnly {
			out = append(out, wsCarrier{name: "raw OpenVPN" + leg.suffix, method: leg.method, source: "client CONNECT", open: func(ctx context.Context, host, port string) (net.Conn, error) {
				return leg.dial(ctx, net.JoinHostPort(host, port))
			}})
		}
	}
	return out
}

// isWindscribeCarrier tells the live feed that a path name is a carrier.
func isWindscribeCarrier(path string) bool {
	for _, p := range []string{"CDN ", "WStunnel ", "Stealth ", "raw OpenVPN"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Dial is the HTTP bridge's dial function in Windscribe mode.
func (b *wsBridge) Dial(ctx context.Context, host, port string) (net.Conn, error) {
	if net.ParseIP(host) == nil {
		return b.local(ctx, host, port)
	}
	return newSniffConn(ctx, func(ctx context.Context, first []byte, input io.Reader) (net.Conn, func(time.Duration, int64), error) {
		// TCP reads can split even the two-byte TLS signature. Read only an
		// ambiguous prefix before deciding; ordinary OpenVPN/junk starts racing
		// immediately, and all bytes remain part of the forwarded stream.
		for !looksTLSorHTTP(first) {
			pending := false
			for _, prefix := range bridgeAPIPrefixes {
				if strings.HasPrefix(prefix, string(first)) {
					pending = true
					break
				}
			}
			if !pending {
				break
			}
			var next [1]byte
			if _, err := io.ReadFull(input, next[:]); err != nil {
				return nil, nil, err
			}
			first = append(first, next[0])
		}
		if looksTLSorHTTP(first) {
			c, err := b.local(ctx, host, port)
			if err == nil {
				stop := context.AfterFunc(ctx, func() { _ = c.Close() })
				if _, err = c.Write(first); err != nil {
					stop()
					_ = c.Close()
				} else {
					go func() { defer stop(); _, _ = io.Copy(c, input); _ = c.Close() }()
				}
			}
			return c, nil, err
		}
		return b.race(ctx, host, port, first, input)
	}), nil
}

var bridgeAPIPrefixes = [...]string{"\x16\x03", "GET ", "POST", "HEAD", "PUT ", "CONN", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "}

// looksTLSorHTTP tells Windscribe's API/HTTPS traffic from OpenVPN TCP,
// whose first bytes are a 2-byte length and a control opcode.
func looksTLSorHTTP(b []byte) bool {
	for _, m := range bridgeAPIPrefixes {
		if strings.HasPrefix(string(b), m) {
			return true
		}
	}
	return false
}

// Families rotate on repeated attempts so that one blocked IP/SNI or
// wrapper does not consume every early time slot. Only provider-advertised
// endpoints remain eligible; raw anti-DPI traffic is a final alternative.
func wsCarrierFamily(name string) int {
	switch {
	case strings.HasPrefix(name, "CDN "):
		return 0
	case strings.HasPrefix(name, "WStunnel "):
		return 1
	case strings.HasPrefix(name, "Stealth "):
		return 2
	default:
		return 3
	}
}

// wsSpreadSNIs avoids spending the per-CONNECT candidate budget on only
// the first SNI, whose many IP/transport variants appear consecutively.
func wsSpreadSNIs(cs []wsCarrier, attempt uint64) []wsCarrier {
	if len(cs) <= 1 {
		return cs
	}
	buckets := make(map[string][]wsCarrier)
	var keys []string
	for _, candidate := range cs {
		label := "default"
		for _, field := range strings.Fields(candidate.name) {
			if strings.HasPrefix(field, "sni=") {
				label = field
				break
			}
		}
		if _, ok := buckets[label]; !ok {
			keys = append(keys, label)
		}
		buckets[label] = append(buckets[label], candidate)
	}
	// Rotate inside each SNI too, including inventories with only one SNI.
	for _, key := range keys {
		bucket := buckets[key]
		if len(bucket) > 1 {
			shift := int(attempt % uint64(len(bucket)))
			buckets[key] = append(append([]wsCarrier{}, bucket[shift:]...), bucket[:shift]...)
		}
	}
	rotation := int(attempt % uint64(len(keys)))
	keys = append(append([]string{}, keys[rotation:]...), keys[:rotation]...)
	var result []wsCarrier
	for len(result) < len(cs) {
		for _, key := range keys {
			bucket := buckets[key]
			if len(bucket) == 0 {
				continue
			}
			result = append(result, bucket[0])
			buckets[key] = bucket[1:]
		}
	}
	return result
}

func wsDiversify(candidates []wsCarrier, attempt uint64) []wsCarrier {
	var groups [4][]wsCarrier
	for _, candidate := range candidates {
		group := wsCarrierFamily(candidate.name)
		groups[group] = append(groups[group], candidate)
	}
	for i := range groups {
		groups[i] = wsSpreadSNIs(groups[i], attempt)
	}
	result := make([]wsCarrier, 0, len(candidates))
	for len(result) < len(candidates) {
		for i := range 4 {
			group := 3
			if i < 3 {
				group = (i + int(attempt%3)) % 3
			}
			if len(groups[group]) == 0 {
				continue
			}
			result = append(result, groups[group][0])
			groups[group] = groups[group][1:]
		}
	}
	return result
}

func (b *wsBridge) ordered(key string, cs []wsCarrier) []wsCarrier {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.retries == nil {
		b.retries = make(map[string]uint64)
	}
	attempt := b.retries[key]
	b.retries[key] = attempt + 1
	good := b.good[key]
	var preferred, untried, fresh, cooling []wsCarrier
	now := time.Now()
	for _, c := range cs {
		switch {
		case now.Before(b.bad[key][c.name]):
			cooling = append(cooling, c)
		case c.name == good:
			preferred = append(preferred, c)
		case b.targets[key] != nil && b.targets[key].paths[c.name] != nil && b.targets[key].paths[c.name].needsTrial():
			untried = append(untried, c)
		default:
			fresh = append(fresh, c)
		}
	}
	ordered := append(preferred, wsDiversify(untried, attempt)...)
	ordered = append(ordered, wsDiversify(fresh, attempt)...)
	if len(ordered) > 0 || len(cooling) == 0 {
		// Merely launching failed handshakes later still lets their quick
		// reset packets beat a slower healthy handshake on every retry.
		return ordered
	}
	// Keep recovery possible when every route is cooling, but re-probe
	// only the least recently penalized route instead of flooding them all.
	oldest := cooling[0]
	for _, c := range cooling[1:] {
		if b.bad[key][c.name].Before(b.bad[key][oldest.name]) {
			oldest = c
		}
	}
	return []wsCarrier{oldest}
}

// Only observed transport failures lower a carrier's priority; neither a
// TCP timeout nor an OpenVPN-shaped response proves a DPI block or VPN login.
func (b *wsBridge) demoteFailure(key, name, stage string) {
	cooldown := 20 * time.Second
	switch stage {
	case "tls", "websocket", "openvpn":
		cooldown = 45 * time.Second
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bad[key] == nil {
		b.bad[key] = make(map[string]time.Time)
	}
	if remaining := time.Until(b.bad[key][name]); remaining > 0 {
		cooldown = max(cooldown, min(remaining*2, 3*time.Minute))
	}
	b.bad[key][name] = time.Now().Add(cooldown)
	if b.good[key] == name {
		delete(b.good, key)
	}
}

type raceResult struct {
	conn  net.Conn
	reply []byte
	c     wsCarrier
	took  time.Duration
}

// readOpenVPNReply requires a complete TCP-framed server control packet before
// selecting a carrier. TLS/HTTP error pages must not beat the real VPN server.
// This checks framing and opcode only; Windscribe still checks authentication.
func readOpenVPNReply(r io.Reader) ([]byte, error) {
	var header [3]byte // two-byte TCP length, then opcode/key ID
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if string(header[:]) == "HTT" {
		return nil, errors.New("HTTP response instead of OpenVPN")
	}
	size := int(binary.BigEndian.Uint16(header[:2]))
	opcode := header[2] >> 3
	minimum := 14 // opcode, session ID, ACK count and control packet ID
	switch opcode {
	case 5: // P_ACK_V1 has no control packet ID
		minimum = 10
	case 2, 3, 4, 8: // server reset/control packets (ssl_pkt.h)
	default:
		return nil, fmt.Errorf("unexpected initial OpenVPN server opcode %d", opcode)
	}
	if size < minimum {
		return nil, fmt.Errorf("short OpenVPN control packet: %d", size)
	}
	packet := make([]byte, 2+size) // bounded by the 16-bit wire length
	copy(packet, header[:])
	if _, err := io.ReadFull(r, packet[3:]); err != nil {
		return nil, err
	}
	return packet, nil
}

// race replays the client stream (including junk and later handshake writes)
// over every carrier and keeps the first complete OpenVPN-shaped reply.
// Windscribe, rather than this bridge, authenticates the server's response.
func (b *wsBridge) race(ctx context.Context, host, port string, first []byte, input io.Reader) (net.Conn, func(time.Duration, int64), error) {
	key := net.JoinHostPort(host, port)
	b.mu.Lock()
	b.nextAttempt++
	attemptID := b.nextAttempt
	b.mu.Unlock()
	if b.logf != nil {
		b.logf("Windscribe attempt=%d started target=%s (OpenVPN authentication pending)", attemptID, key)
	}
	if b.catalog != nil && b.opts.serverIP == "" && len(b.catalog.endpoints(host)) == 0 {
		// A valid provider source containing another node does not make
		// this destination ready. Wait for its exact mapping, or until
		// every in-flight source completed (with an 8-second cap).
		b.catalog.waitForTarget(ctx, host, 8*time.Second)
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
	}
	allCarriers := b.carriersFor(host)
	b.registerCarriers(key, host, allCarriers)
	cs := b.ordered(key, allCarriers)
	b.publishProgress(key, true)
	// Each connection attempt is a bounded experiment, not a broadcast to
	// every advertised entry/IP/SNI. Later retries rotate the candidates.
	const maxRaceCandidates = 24
	if len(cs) > maxRaceCandidates {
		b.logf("Windscribe attempt=%d target=%s: testing %d of %d candidates; alternatives rotate on retry", attemptID, key, maxRaceCandidates, len(cs))
		cs = cs[:maxRaceCandidates]
	}
	live, stopLive := context.WithCancel(ctx)
	rctx, cancel := context.WithTimeout(live, 25*time.Second)
	defer cancel()
	replay := newCarrierReplay(first)
	if input != nil {
		go func() {
			buf := make([]byte, 32<<10)
			for {
				n, err := input.Read(buf)
				if n > 0 {
					if err := replay.append(live, buf[:n]); err != nil {
						b.logf("Windscribe %s: %v", key, err)
						stopLive()
						return
					}
				}
				if err != nil {
					stopLive()
					return
				}
			}
		}()
	}
	began := time.Now()
	var won sync.Once
	winner := make(chan raceResult, 1)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var lastErr error
	failures := make(map[string]int)
	fail := func(c wsCarrier, err error) {
		stage := "tcp"
		var staged *wstunnel.StageError
		if errors.As(err, &staged) {
			stage = staged.Stage
		}
		errMu.Lock()
		failures[stage]++
		lastErr = fmt.Errorf("%s: %w", c.name, err)
		errMu.Unlock()
		b.demoteFailure(key, c.name, stage)
		b.carrierProgress(key, c.name, stage+": "+trimDetail(err.Error()))
		b.logf("Windscribe attempt=%d target=%s carrier=%s destination=%s source=%s failed stage=%s: %v", attemptID, key, c.name, c.addr, c.source, stage, err)
	}
	b.mu.Lock()
	hasPreferred := len(cs) > 0 && cs[0].name == b.good[key]
	b.mu.Unlock()
	preferredFailed := make(chan struct{})
	if !hasPreferred {
		close(preferredFailed)
	}
	for i, c := range cs {
		if c.addr == "" {
			c.addr = key
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			keep := false
			started, completed := false, false
			defer func() {
				if started {
					if !completed {
						b.carrierProgress(key, c.name, "interrupted")
					}
					b.carrierProgress(key, c.name, "finish")
				}
			}()
			if hasPreferred && i == 0 {
				// A previously CLI-confirmed path gets a bounded exclusive
				// attempt. A faster unauthenticated reset cannot steal it.
				defer func() {
					if !keep {
						close(preferredFailed)
					}
				}()
			} else {
				select {
				case <-rctx.Done():
					return
				case <-preferredFailed:
				}
			}
			slot := i
			if hasPreferred && i > 0 {
				slot--
			}
			select {
			case <-rctx.Done():
				return
			case <-time.After(time.Duration(slot) * b.stagger):
			}
			b.carrierProgress(key, c.name, "start")
			started = true
			probeCtx, stopProbe := context.WithTimeout(rctx, b.replyTimeout)
			defer stopProbe()
			conn, err := c.open(probeCtx, host, port)
			if err != nil {
				if ctx.Err() == nil && rctx.Err() == nil {
					fail(c, err)
					completed = true
				}
				return
			}
			stop := context.AfterFunc(probeCtx, func() { _ = conn.Close() })
			wctx, stopWrite := context.WithCancel(live)
			defer func() {
				if !keep {
					stopWrite()
					_ = conn.Close()
				}
			}()
			// A silent reader must not prevent a writer from forwarding the
			// client's later junk/handshake bytes. The race deadline bounds both.
			go func() {
				if err := replay.send(wctx, conn); err != nil && wctx.Err() == nil && replay.isWinner(conn) {
					b.logf("Windscribe %s carrier=%s downstream write failed: %v", key, c.name, err)
				}
				_ = conn.Close()
			}()
			reply, err := readOpenVPNReply(conn)
			if err != nil || !stop() {
				_ = conn.Close()
				if probeCtx.Err() != nil {
					err = probeCtx.Err()
				} else if err == nil {
					err = errors.New("no answer")
				}
				if ctx.Err() == nil && rctx.Err() == nil {
					fail(c, &wstunnel.StageError{Stage: "openvpn", Err: err})
					completed = true
				}
				return
			}
			completed = true
			b.carrierProgress(key, c.name, "reply")
			taken := false
			won.Do(func() {
				taken = true
				keep = true
				replay.selectWinner(conn)
				winner <- raceResult{conn: conn, reply: reply, c: c, took: time.Since(began)}
			})
			if !taken {
				_ = conn.Close()
			}
		}()
	}
	go func() { wg.Wait(); close(winner) }()
	r, ok := <-winner
	raceErr := rctx.Err()
	cancel() // stops the losers
	if !ok {
		stopLive()
		b.publishProgress(key, true)
		errMu.Lock()
		err := lastErr
		var parts []string
		for _, stage := range []string{"tcp", "tls", "websocket", "openvpn"} {
			if failures[stage] > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", stage, failures[stage]))
			}
		}
		summary := strings.Join(parts, ", ")
		errMu.Unlock()
		if err == nil {
			err = raceErr
			if err == nil {
				err = errors.New("no carrier")
			}
		}
		if b.catalog != nil && len(b.catalog.endpoints(host)) == 0 && b.opts.serverIP == "" {
			summary = b.catalog.missingReason(host) + "; " + summary
		}
		if b.report != nil && ctx.Err() == nil {
			b.report(smartproxy.Event{Host: host, Site: host, Err: "Windscribe race failed [" + summary + "]"})
		}
		return nil, nil, fmt.Errorf("no Windscribe carrier answered (%s): %w", summary, err)
	}
	b.logf("Windscribe attempt=%d target=%s carrier=%s source=%s; initial control reply in %s (authentication pending)", attemptID, key, r.c.name, r.c.source, shortDur(r.took))
	session := &wsActiveCarrier{id: attemptID, key: key, name: r.c.name, started: time.Now()}
	b.mu.Lock()
	if b.active == nil {
		b.active = make(map[*wsActiveCarrier]bool)
	}
	b.active[session] = true
	if p := b.targets[key].paths[r.c.name]; p != nil {
		p.selected++
		p.last, p.updated = "selected; awaiting Windscribe", time.Now()
	}
	b.mu.Unlock()
	b.publishProgress(key, true)
	if b.report != nil {
		b.report(smartproxy.Event{Host: host, Site: host, Path: r.c.name, Took: r.took, TCPOnly: true})
	}
	done := func(lived time.Duration, received int64) {
		b.mu.Lock()
		defer func() { b.mu.Unlock(); b.publishProgress(key, true) }()
		confirmed := session.confirmed
		delete(b.active, session)
		streakKey := key + "|" + r.c.name
		if confirmed {
			// One short EOF can be a deliberate location switch. Only two
			// consecutive *unexpected upstream read ends* on short
			// CLI-correlated sessions justify a temporary cooldown.
			if session.upstreamEnd && lived < 15*time.Second && received < 64<<10 {
				b.shortEnds[streakKey]++
				if b.shortEnds[streakKey] >= 2 {
					if b.good[key] == r.c.name {
						delete(b.good, key)
					}
					if b.bad[key] == nil {
						b.bad[key] = make(map[string]time.Time)
					}
					b.bad[key][r.c.name] = time.Now().Add(90 * time.Second)
					b.shortEnds[streakKey] = 0
				}
			} else {
				b.shortEnds[streakKey] = 0
			}
		}
		// Unverified streams that die during the handshake failure window
		// receive a temporary penalty; a short intentional VPN session
		// is not automatically classified as a failure.
		if !confirmed && lived < 50*time.Second && received < 64<<10 {
			if b.good[key] == r.c.name {
				delete(b.good, key)
			}
			if b.bad[key] == nil {
				b.bad[key] = make(map[string]time.Time)
			}
			ttl := 90 * time.Second
			if lived < 15*time.Second {
				ttl = 2 * time.Minute
			}
			b.bad[key][r.c.name] = time.Now().Add(ttl)
		}
		if p := b.targets[key].paths[r.c.name]; p != nil {
			p.updated = time.Now()
			p.last = "session ended; VPN unconfirmed"
			if confirmed {
				p.last = "CLI-confirmed session ended"
			}
		}
		b.logf("Windscribe attempt=%d target=%s carrier=%s session ended after %s, returned=%d bytes, CLI-correlated=%v, upstream-ended=%v (not proof of DPI or per-carrier authentication)", attemptID, key, r.c.name, shortDur(lived), received, confirmed, session.upstreamEnd)
	}
	stopClose := context.AfterFunc(live, func() { _ = r.conn.Close() })
	return &carrierConn{Conn: &prefixConn{Conn: r.conn, pending: r.reply}, cancel: stopLive, stopClose: stopClose, logf: b.logf, name: r.c.name, destination: key, started: time.Now(), onUpstreamEnd: func() {
		b.mu.Lock()
		session.upstreamEnd = true
		b.mu.Unlock()
	}}, done, nil
}

// carrierConn exposes only observed stream failures. EOF may be the
// remote peer ending the stream normally; neither EOF nor reset is by itself
// proof that a DPI device terminated the connection.
type carrierConn struct {
	net.Conn
	cancel        context.CancelFunc
	stopClose     func() bool
	logf          func(string, ...any)
	name          string
	destination   string
	started       time.Time
	ended         sync.Once
	closed        atomic.Bool
	onUpstreamEnd func()
}

func (c *carrierConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && !c.closed.Load() {
		c.ended.Do(func() {
			if c.onUpstreamEnd != nil {
				c.onUpstreamEnd()
			}
			if c.logf != nil {
				c.logf("Windscribe %s carrier=%s upstream read ended after %s: %v (source of closure unverified)", c.destination, c.name, shortDur(time.Since(c.started)), err)
			}
		})
	}
	return n, err
}

func (c *carrierConn) Close() error {
	c.closed.Store(true)
	c.cancel()
	c.stopClose()
	return c.Conn.Close()
}

// prefixConn returns already-read bytes before reading the connection.
type prefixConn struct {
	net.Conn
	pending []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pending) > 0 {
		n := copy(b, p.pending)
		p.pending = p.pending[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// scanCDNEdges looks for Cloudflare edges this network reaches that also
// carry the user's hostname to a WebSocket upgrade (HTTP 101), the way
// Shir-o-Khorshid scans CDN IPs for Psiphon's fronted hosts. It keeps the
// fastest few; until it finds one the hostname's own DNS answer is used.
func (b *wsBridge) scanCDNEdges(ctx context.Context, candidates []string) {
	o := b.opts
	sni := o.cdnSNI
	if sni == "" {
		sni = o.cdnHost
	}
	type found struct {
		addr string
		took time.Duration
	}
	jobs := make(chan string)
	results := make(chan found)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				addr := net.JoinHostPort(ip, "443")
				began := time.Now()
				c, err := wstunnel.Dial(sctx, wstunnel.Config{Addr: addr, SNI: sni, Host: o.cdnHost, Path: b.path, Verify: true, Dial: directDial, Timeout: 6 * time.Second})
				if err != nil {
					continue
				}
				_ = c.Close()
				select {
				case results <- found{addr, time.Since(began)}:
				case <-sctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range candidates {
			select {
			case jobs <- ip:
			case <-sctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var best []found
	for f := range results {
		best = append(best, f)
		slices.SortFunc(best, func(a, b found) int { return int(a.took - b.took) })
		addrs := make([]string, 0, len(best))
		for _, x := range best {
			addrs = append(addrs, x.addr)
		}
		b.mu.Lock()
		b.edges = addrs
		b.mu.Unlock()
		b.note("CDN edge %s completed TLS/WebSocket for %s (%s); %d found; OpenVPN unverified", f.addr, o.cdnHost, shortDur(f.took), len(best))
		if len(best) >= 6 {
			cancel()
		}
	}
	if len(best) == 0 && ctx.Err() == nil {
		b.note("No Cloudflare edge carried %s to a WebSocket upgrade; check the proxied DNS record and SSL mode Full", o.cdnHost)
	}
}

// sniffConn uses a full-duplex pipe so client writes keep flowing while open
// waits for a carrier response. The pipe owns deadlines and unblocks on Close.
// open must send first and continue consuming input for the connection lifetime.
type sniffConn struct {
	net.Conn
	cancel context.CancelFunc
	mu     sync.Mutex
	err    error
}

func newSniffConn(ctx context.Context, open func(context.Context, []byte, io.Reader) (net.Conn, func(time.Duration, int64), error)) *sniffConn {
	ctx, cancel := context.WithCancel(ctx)
	client, peer := net.Pipe()
	s := &sniffConn{Conn: client, cancel: cancel}
	stop := context.AfterFunc(ctx, func() { _ = peer.Close(); _ = client.Close() })
	go func() {
		defer cancel()
		defer stop()
		defer peer.Close()
		first := make([]byte, 32<<10)
		n, err := peer.Read(first)
		if err != nil {
			return
		}
		conn, done, err := open(ctx, first[:n], peer)
		if err != nil {
			s.mu.Lock()
			s.err = err
			s.mu.Unlock()
			return
		}
		defer conn.Close()
		began := time.Now()
		received, _ := io.Copy(peer, conn)
		if done != nil {
			done(time.Since(began), received)
		}
	}()
	return s
}

func (s *sniffConn) result(n int, err error) (int, error) {
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.err != nil {
			err = s.err
		}
	}
	return n, err
}

func (s *sniffConn) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	return s.result(n, err)
}

func (s *sniffConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := s.Conn.Write(p)
	return s.result(n, err)
}

func (s *sniffConn) Close() error {
	s.cancel()
	return s.Conn.Close()
}
