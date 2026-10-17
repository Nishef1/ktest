// Package wstunnel speaks the client side of Windscribe's WStunnel transport:
// an HTTP/1.1 WebSocket upgrade to /tcp/127.0.0.1/<port> on a Windscribe
// server, after which binary WebSocket messages carry the OpenVPN TCP stream.
// The wire format matches https://github.com/Windscribe/wstunnel (cli package).
//
// The TLS layer uses a browser ClientHello and lets the caller choose the SNI,
// so the same stream can go straight to a Windscribe server or through a CDN
// hostname the user controls whose origin is a Windscribe WStunnel server.
package wstunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DefaultPath is the path Windscribe's desktop client requests: its WStunnel
// server forwards the stream to the node's local OpenVPN TCP server.
const DefaultPath = "/tcp/127.0.0.1/1194"

// Config describes one WStunnel attempt.
type Config struct {
	// Addr is the TCP destination host:port: a Windscribe server or a CDN edge.
	Addr string
	// SNI is the TLS server name; empty sends none (as the official client
	// does for an IP address).
	SNI string
	// Host is the HTTP Host header: the server IP in direct mode, the user's
	// CDN hostname in CDN mode.
	Host string
	// Path is the WebSocket request path; empty means DefaultPath.
	Path string
	// Verify checks the certificate chain against SNI (CDN mode). Without it,
	// VerifyPeer, when set, still decides whether to accept the peer.
	Verify     bool
	VerifyPeer func(certs []*x509.Certificate) error
	// OfficialHello selects a Windscribe-style randomized uTLS ClientHello
	// instead of the existing Chrome preset. Unsupported post-quantum groups
	// are removed because pinned uTLS 1.8.2 cannot finish their TLS HRR flow.
	// It is an alternative, not a byte-for-byte official fingerprint.
	OfficialHello bool
	// Dial opens the TCP leg (directly or through a local anti-DPI core).
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Timeout bounds TCP, TLS and the upgrade together; 0 means 12 s.
	Timeout time.Duration
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// StageError identifies the boundary that failed, preserving the original
// error for errors.Is/errors.As and timeout diagnostics.
type StageError struct {
	Stage string
	Err   error
}

func (e *StageError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *StageError) Unwrap() error { return e.Err }

func stageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &StageError{Stage: stage, Err: err}
}

// Dial opens the TCP leg, completes TLS and the WebSocket upgrade, and
// returns a stream whose Read/Write carry the raw tunneled bytes. HTTP 101
// proves a WStunnel server answered; it does not prove the VPN handshake.
func Dial(ctx context.Context, c Config) (net.Conn, error) {
	if c.Dial == nil || c.Addr == "" || c.Host == "" {
		return nil, errors.New("wstunnel: Addr, Host and Dial are required")
	}
	if c.Verify && c.SNI == "" {
		return nil, errors.New("wstunnel: certificate verification needs an SNI")
	}
	path := c.Path
	if path == "" {
		path = DefaultPath
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \r\n") {
		return nil, fmt.Errorf("wstunnel: invalid path %q", path)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := c.Dial(dctx, c.Addr)
	if err != nil {
		return nil, stageError("tcp", err)
	}
	stop := context.AfterFunc(dctx, func() { _ = raw.Close() })
	conn, br, err := handshake(dctx, raw, c, path)
	if !stop() || err != nil {
		_ = raw.Close()
		if err == nil {
			err = stageError("websocket", dctx.Err())
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &Conn{c: conn, r: br}, nil
}

// DialStealth opens Windscribe's Stealth transport (stunnel): TLS, then the
// raw OpenVPN TCP stream. Path and Host are not used.
func DialStealth(ctx context.Context, c Config) (net.Conn, error) {
	if c.Dial == nil || c.Addr == "" {
		return nil, errors.New("stealth: Addr and Dial are required")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := c.Dial(dctx, c.Addr)
	if err != nil {
		return nil, stageError("tcp", err)
	}
	stop := context.AfterFunc(dctx, func() { _ = raw.Close() })
	conn, err := clientTLS(dctx, raw, c)
	err = stageError("tls", err)
	if !stop() || err != nil {
		_ = raw.Close()
		if err == nil {
			err = stageError("tls", dctx.Err())
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// clientTLS runs a Chrome-like TLS handshake offering only http/1.1.
func clientTLS(ctx context.Context, raw net.Conn, c Config) (*utls.UConn, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conf := &utls.Config{
		ServerName:         c.SNI,
		InsecureSkipVerify: !c.Verify,
		MinVersion:         tls.VersionTLS12,
	}
	if c.VerifyPeer != nil {
		check := c.VerifyPeer
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, b := range rawCerts {
				cert, err := x509.ParseCertificate(b)
				if err != nil {
					return err
				}
				certs = append(certs, cert)
			}
			return check(certs)
		}
	}
	u := utls.UClient(raw, conf, utls.HelloChrome_Auto)
	if c.OfficialHello {
		// Windscribe/wstunnel uses HelloRandomizedALPN + ApplyPreset.
		// Keep http/1.1 as the only offered ALPN for WebSocket upgrade.
		spec, err := utls.UTLSIdToSpec(utls.HelloRandomizedALPN)
		if err != nil {
			return nil, fmt.Errorf("Windscribe ClientHello preset: %w", err)
		}
		extensions := spec.Extensions[:0]
		for _, ext := range spec.Extensions {
			switch x := ext.(type) {
			case *utls.ALPNExtension:
				x.AlpnProtocols = []string{"http/1.1"}
			case *utls.ApplicationSettingsExtension:
				continue
			case *utls.SupportedCurvesExtension:
				// The randomized generator can advertise X25519MLKEM768
				// without an initial key share. uTLS 1.8.2 then fails
				// HelloRetryRequest with "unsupported curve" (upstream
				// refraction-networking/utls#366). Advertise only key
				// exchange groups that this pinned runtime can complete.
				x.Curves = []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}
			case *utls.KeyShareExtension:
				x.KeyShares = []utls.KeyShare{{Group: utls.X25519}}
			}
			extensions = append(extensions, ext)
		}
		spec.Extensions = extensions
		u = utls.UClient(raw, conf, utls.HelloCustom)
		if err := u.ApplyPreset(&spec); err != nil {
			return nil, fmt.Errorf("Windscribe ClientHello: %w", err)
		}
	}
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	onlyHTTP11(u)
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS: %w", err)
	}
	return u, nil
}

func handshake(ctx context.Context, raw net.Conn, c Config, path string) (net.Conn, *bufio.Reader, error) {
	u, err := clientTLS(ctx, raw, c)
	if err != nil {
		return nil, nil, stageError("tls", err)
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	req := "GET " + path + " HTTP/1.1\r\nHost: " + c.Host + "\r\nUser-Agent: Go-http-client/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(u, req); err != nil {
		return nil, nil, stageError("websocket", err)
	}
	br := bufio.NewReaderSize(u, 32<<10)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, stageError("websocket", fmt.Errorf("upgrade: %w", err))
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, nil, stageError("websocket", fmt.Errorf("upgrade refused: HTTP %d", resp.StatusCode))
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		return nil, nil, stageError("websocket", errors.New("upgrade: not a WebSocket server"))
	}
	return u, br, nil
}

// onlyHTTP11 offers exactly http/1.1: a WebSocket upgrade cannot use h2.
func onlyHTTP11(u *utls.UConn) {
	exts := u.Extensions[:0]
	for _, e := range u.Extensions {
		switch x := e.(type) {
		case *utls.ALPNExtension:
			x.AlpnProtocols = []string{"http/1.1"}
		case *utls.ApplicationSettingsExtension:
			continue
		}
		exts = append(exts, e)
	}
	u.Extensions = exts
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// Conn carries a byte stream in binary WebSocket messages (client side).
type Conn struct {
	c         net.Conn
	r         *bufio.Reader
	wmu       sync.Mutex
	remaining int64 // unread payload of the current data frame
	mask      [4]byte
	masked    bool
	maskPos   int
	fragmented bool
	closed    bool
}

const (
	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
	maxFrame = 16 << 10
)

func (w *Conn) writeFrame(op byte, payload []byte) error {
	header := make([]byte, 0, 14)
	header = append(header, 0x80|op)
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n <= 0xFFFF:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127)
		header = binary.BigEndian.AppendUint64(header, uint64(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)
	frame := append(header, payload...)
	body := frame[len(header):]
	for i := range body {
		body[i] ^= mask[i&3]
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	// net.Conn.Write is permitted to return a short successful write.
	// A partial WebSocket frame corrupts *all* later OpenVPN bytes.
	for len(frame) > 0 {
		n, err := w.c.Write(frame)
		if n > 0 {
			frame = frame[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// Write sends p as one or more binary messages, like the official client
// which sends each TCP read as its own message.
func (w *Conn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), maxFrame)
		if err := w.writeFrame(opBinary, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Read returns tunneled bytes, answering pings and ending at a close frame.
func (w *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for w.remaining == 0 {
		if err := w.nextFrame(); err != nil {
			return 0, err
		}
	}
	if int64(len(p)) > w.remaining {
		p = p[:w.remaining]
	}
	n, err := w.r.Read(p)
	if w.masked {
		for i := 0; i < n; i++ {
			p[i] ^= w.mask[w.maskPos&3]
			w.maskPos++
		}
	}
	w.remaining -= int64(n)
	if err == io.EOF && w.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (w *Conn) nextFrame() error {
	var h [2]byte
	if _, err := io.ReadFull(w.r, h[:]); err != nil {
		return err
	}
	op := h[0] & 0x0F
	if h[0]&0x70 != 0 {
		return errors.New("wstunnel: unexpected reserved bits in frame")
	}
	fin := h[0]&0x80 != 0
	masked := h[1]&0x80 != 0
	if masked {
		return errors.New("wstunnel: masked server frame violates RFC 6455")
	}
	if !fin && op >= 8 {
		return errors.New("wstunnel: fragmented control frame")
	}
	length := int64(h[1] & 0x7F)
	switch length {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(w.r, b[:]); err != nil {
			return err
		}
		length = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(w.r, b[:]); err != nil {
			return err
		}
		v := binary.BigEndian.Uint64(b[:])
		if v > 1<<40 {
			return errors.New("wstunnel: frame too large")
		}
		length = int64(v)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.r, mask[:]); err != nil {
			return err
		}
	}
	switch op {
	case opBinary:
		if w.fragmented {
			return errors.New("wstunnel: new binary message before previous fragments completed")
		}
		w.fragmented = !fin
		w.remaining, w.mask, w.masked, w.maskPos = length, mask, masked, 0
		return nil
	case opCont:
		if !w.fragmented {
			return errors.New("wstunnel: continuation without an initial binary fragment")
		}
		w.fragmented = !fin
		w.remaining, w.mask, w.masked, w.maskPos = length, mask, masked, 0
		return nil
	case opText:
		return errors.New("wstunnel: unexpected text message")
	}
	if length > 125 {
		return errors.New("wstunnel: oversized control frame")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(w.r, payload); err != nil {
		return err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	switch op {
	case opPing:
		return w.writeFrame(opPong, payload)
	case opPong:
		return nil
	case opClose:
		// Do not block the upstream reader writing a control reply: the
		// caller's Close performs a bounded best-effort close handshake.
		return io.EOF
	}
	return fmt.Errorf("wstunnel: unknown opcode %d", op)
}

// Close sends a close frame (best effort) and closes the TCP leg.
func (w *Conn) Close() error {
	// Bound the wait before acquiring wmu: a stalled frame writer holds it.
	// Setting the deadline afterwards would leave cancellation stuck forever.
	_ = w.c.SetWriteDeadline(time.Now().Add(time.Second))
	w.wmu.Lock()
	already := w.closed
	w.closed = true
	w.wmu.Unlock()
	if !already {
		_ = w.writeFrame(opClose, []byte{0x03, 0xE8})
	}
	return w.c.Close()
}

func (w *Conn) LocalAddr() net.Addr                { return w.c.LocalAddr() }
func (w *Conn) RemoteAddr() net.Addr               { return w.c.RemoteAddr() }
func (w *Conn) SetDeadline(t time.Time) error      { return w.c.SetDeadline(t) }
func (w *Conn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *Conn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }
