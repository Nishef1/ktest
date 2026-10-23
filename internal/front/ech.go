package front

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"
)

// Encrypted Client Hello without DNS.
//
// Normally a client learns a site's ECH configuration from a DNS HTTPS record,
// which is exactly what a poisoned or filtered network denies. But a server
// that cannot decrypt an ECH extension answers with retry_configs, which the
// client verifies against the configuration's public name. So ktest sends a
// well-formed configuration that nobody holds the key to, takes the fresh
// configuration from the rejection, and handshakes again with it. Cloudflare's
// public name is cloudflare-ech.com, shared by every site behind it, so one
// bootstrap serves all of them and the wire only ever shows that name.

// dummyECHConfig builds an ECHConfigList with one X25519/HKDF-SHA256/AES-128-GCM
// entry for public, whose private key does not exist.
func dummyECHConfig(public string) []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return echConfigList(public, key)
}

// echConfigList encodes a one-entry ECHConfigList for an X25519 public key.
func echConfigList(public string, key []byte) []byte {
	id := make([]byte, 1)
	_, _ = rand.Read(id)
	var c []byte
	c = append(c, id[0])
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(key)))
	c = append(c, key...)
	c = binary.BigEndian.AppendUint16(c, 4) // one cipher suite: 4 bytes
	c = binary.BigEndian.AppendUint16(c, 1) // HKDF-SHA256
	c = binary.BigEndian.AppendUint16(c, 1) // AES-128-GCM
	c = append(c, 64)                       // maximum_name_length
	c = append(c, byte(len(public)))
	c = append(c, public...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	var cfg []byte
	cfg = binary.BigEndian.AppendUint16(cfg, 0xfe0d)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(c)))
	cfg = append(cfg, c...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(cfg)))
	return append(list, cfg...)
}

// echTTL bounds how long an accepted configuration is reused before the
// next connection relearns it; providers rotate ECH keys (hours, typically).
const echTTL = time.Hour

// echEntry is a configuration that completed an accepted ECH handshake.
type echEntry struct {
	list     []byte
	accepted time.Time
}

func (f *Fronter) echConfig(public string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.ech[public]
	if !ok || time.Since(e.accepted) > echTTL {
		delete(f.ech, public)
		return nil
	}
	return e.list
}

// storeECH keeps only a configuration that an edge just accepted, never a
// retry list on its own: a list that does not complete must not stay cached.
func (f *Fronter) storeECH(public string, list []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ech == nil {
		f.ech = map[string]echEntry{}
	}
	f.ech[public] = echEntry{list: list, accepted: time.Now()}
}

func (f *Fronter) forgetECH(public string, list []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.ech[public]; ok && string(e.list) == string(list) {
		delete(f.ech, public)
	}
}

// tryECH reaches name through an ECH service. connect opens a fresh TCP
// connection to an edge address each time it is called.
func (f *Fronter) tryECH(ctx context.Context, fr Front, name string, protos []string, connect func() (net.Conn, error)) (net.Conn, error) {
	list := f.echConfig(fr.ECH)
	if list == nil {
		list = dummyECHConfig(fr.ECH)
	}
	for round := 0; ; round++ {
		raw, err := connect()
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		c := tls.Client(fragmentHello(raw), &tls.Config{
			ServerName:                     name,
			EncryptedClientHelloConfigList: list,
			MinVersion:                     tls.VersionTLS13,
			NextProtos:                     protos,
			RootCAs:                        f.cfg.Roots,
		})
		err = c.HandshakeContext(ctx)
		if !stop() {
			_ = raw.Close()
			return nil, context.Canceled
		}
		if err == nil {
			st := c.ConnectionState()
			switch {
			case !st.ECHAccepted:
				_ = raw.Close()
				f.forgetECH(fr.ECH, list)
				return nil, errors.New("the edge did not accept Encrypted Client Hello")
			case len(protos) == 1 && st.NegotiatedProtocol != protos[0] && !noALPNIsHTTP1(protos, st.NegotiatedProtocol):
				_ = raw.Close()
				return nil, fmt.Errorf("edge chose %q instead of %q", st.NegotiatedProtocol, protos[0])
			}
			f.storeECH(fr.ECH, list)
			return c, nil
		}
		_ = raw.Close()
		var rej *tls.ECHRejectionError
		// RFC 9849: never accept a second retry_config after the retry.
		if errors.As(err, &rej) && len(rej.RetryConfigList) > 0 && round == 0 {
			// A cached list the edge no longer holds is replaced only once
			// the retry is accepted (stored above).
			f.forgetECH(fr.ECH, list)
			list = rej.RetryConfigList
			continue
		}
		return nil, fmt.Errorf("handshake: %w", err)
	}
}

// fragmentHello sends the first TLS record (the ClientHello) in small pieces.
// An ECH hello shows the outer name cloudflare-ech.com, which some networks
// filter by looking for it in a single packet; reassembly is what they skip.
// Only the first write is cut, the rest of the connection is untouched.
func fragmentHello(c net.Conn) net.Conn { return &helloCutter{Conn: c} }

type helloCutter struct {
	net.Conn
	done bool
}

func (c *helloCutter) Write(p []byte) (int, error) {
	if c.done || len(p) < 64 || p[0] != 0x16 {
		return c.Conn.Write(p)
	}
	c.done = true
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	// The names sit in the first ~150 bytes; the bulk follows in one write.
	head := min(len(p), 160)
	sent := 0
	for sent < head {
		n := 8 + mrand.IntN(9)
		if sent+n > head {
			n = head - sent
		}
		w, err := c.Conn.Write(p[sent : sent+n])
		sent += w
		if err != nil {
			return sent, err
		}
		time.Sleep(time.Duration(1+mrand.IntN(3)) * time.Millisecond)
	}
	if sent < len(p) {
		w, err := c.Conn.Write(p[sent:])
		sent += w
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// shuffled returns a copy of s in random order, so that one dead hint does not
// stay first for every connection.
func shuffled(s []string) []string {
	out := append([]string(nil), s...)
	mrand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// The bootstrap result is shared by every automatic caller for a while.
// Reports from 2026-10-21 describe both filtering of UDP DNS HTTPS-record
// queries and blocking the visible cloudflare-ech.com SNI on at least one
// network. This bootstrap is DNS-independent, not SNI-independent: the public
// name remains visible in the outer ClientHello. Cache definite outcomes so a
// failed bootstrap does not cost every connection another handshake; a caller's
// own deadline expiring says nothing about the network.
const (
	echBootstrapOK   = 10 * time.Minute
	echBootstrapFail = 5 * time.Minute
)

var echBootstrap struct {
	sync.Mutex
	config   []byte
	edge     string
	err      error
	at       time.Time
	inflight chan struct{} // closed when the running fetch has stored its result
	fetch    func(context.Context) ([]byte, string, error)
}

// echBootstrapBudget bounds the shared fetch itself: three edges, 5s each.
const echBootstrapBudget = 16 * time.Second

// SharedCloudflareECH is FetchCloudflareECH with the shared result above. The
// fetch runs on its own deadline and stores its answer even when this caller
// stops waiting: a direct Cloudflare ECH retry-config bootstrap that times out
// otherwise outlasts every short caller and is never remembered.
// Explicit diagnostics call FetchCloudflareECH to measure afresh.
func SharedCloudflareECH(ctx context.Context) ([]byte, string, error) {
	echBootstrap.Lock()
	age := time.Since(echBootstrap.at)
	if echBootstrap.config != nil && age < echBootstrapOK {
		defer echBootstrap.Unlock()
		return echBootstrap.config, echBootstrap.edge, nil
	}
	if echBootstrap.err != nil && age < echBootstrapFail {
		defer echBootstrap.Unlock()
		return nil, "", fmt.Errorf("ECH bootstrap failed %s ago (not retried yet): %w", age.Round(time.Second), echBootstrap.err)
	}
	if echBootstrap.inflight == nil {
		done := make(chan struct{})
		echBootstrap.inflight = done
		fetch := echBootstrap.fetch
		if fetch == nil {
			fetch = FetchCloudflareECH
		}
		go func() {
			fctx, cancel := context.WithTimeout(context.Background(), echBootstrapBudget)
			config, edge, err := fetch(fctx)
			cancel()
			echBootstrap.Lock()
			echBootstrap.config, echBootstrap.edge, echBootstrap.err, echBootstrap.at = config, edge, err, time.Now()
			echBootstrap.inflight = nil
			echBootstrap.Unlock()
			close(done)
		}()
	}
	done := echBootstrap.inflight
	echBootstrap.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
	echBootstrap.Lock()
	defer echBootstrap.Unlock()
	if echBootstrap.config != nil {
		return echBootstrap.config, echBootstrap.edge, nil
	}
	return nil, "", echBootstrap.err
}

// FetchCloudflareECH asks a Cloudflare edge address for the current ECH
// configuration without any DNS: a dummy configuration is rejected and the
// edge answers with the real one. It returns the configuration (the wire
// ECHConfigList, which is what DNS HTTPS records and Aether's --ech carry) and
// the address that answered, which can be reused as an address that is known to
// be reachable.
func FetchCloudflareECH(ctx context.Context) ([]byte, string, error) {
	var hints []string
	for _, f := range DefaultFamilies() {
		if f.Name == "cloudflare" {
			hints = f.Hints
		}
	}
	var last error
	for i, ip := range shuffled(hints) {
		if i == 3 {
			break
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		raw, err := (&net.Dialer{}).DialContext(cctx, "tcp", net.JoinHostPort(ip, "443"))
		if err != nil {
			cancel()
			last = err
			continue
		}
		c := tls.Client(fragmentHello(raw), &tls.Config{
			ServerName:                     "api.cloudflareclient.com",
			EncryptedClientHelloConfigList: dummyECHConfig(CloudflareECH),
			MinVersion:                     tls.VersionTLS13,
		})
		err = c.HandshakeContext(cctx)
		cancel()
		_ = raw.Close()
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) && len(rej.RetryConfigList) > 0 {
			return rej.RetryConfigList, ip, nil
		}
		last = fmt.Errorf("%s: %v", ip, err)
	}
	if last == nil {
		last = errors.New("no Cloudflare address to ask")
	}
	return nil, "", last
}

// DialECH opens a verified TLS connection to name through Cloudflare's ECH, from
// ktest itself (no certificate on anyone's side, no proxy): the way to reach a
// Cloudflare-hosted service such as cloudflare-dns.com without DNS.
func (f *Fronter) DialECH(ctx context.Context, name string, protos []string) (net.Conn, error) {
	var hints []string
	for _, fam := range f.cfg.Families {
		if fam.Name == "cloudflare" {
			hints = shuffled(fam.Hints)
		}
	}
	if len(hints) == 0 {
		return nil, errors.New("no Cloudflare addresses configured")
	}
	connect := func() (net.Conn, error) { return f.dialAny(ctx, hints) }
	return f.tryECH(ctx, Front{ECH: CloudflareECH}, name, protos, connect)
}
