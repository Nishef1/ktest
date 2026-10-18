package smartproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
)

// WindscribeMethod pins one permitted local technique. TLSOnly methods shape
// the wrapper's ClientHello and cannot carry a raw OpenVPN first flight.
type WindscribeMethod struct {
	Name     string
	TLSOnly  bool
	IPv6Only bool
	Dial     func(context.Context, string, string) (net.Conn, error)
}

// WindscribeMethods exposes the actual inventory rather than a rotating
// anonymous +anti-DPI leg. Foreign exits, takeovers and plain TCP are excluded.
func (p *Proxy) WindscribeMethods() []WindscribeMethod {
	p.mu.Lock()
	defer p.mu.Unlock()
	var candidates []*upstreamState
	for _, u := range p.ups {
		if allowedLocalOnly(u.Upstream) {
			candidates = append(candidates, u)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Rank < candidates[j].Rank })
	methods := make([]WindscribeMethod, 0, len(candidates))
	for _, u := range candidates {
		methods = append(methods, WindscribeMethod{Name: u.Name, TLSOnly: u.Send != nil, IPv6Only: u.Network == "tcp6", Dial: func(ctx context.Context, host, port string) (net.Conn, error) {
			if u.Match != nil && !u.Match(host) {
				return nil, errors.New("local method does not apply to this destination")
			}
			// dial also enforces the protected-destination policy. Merely
			// listing a method must not bypass the normal routing boundary.
			conn, err := p.dial(ctx, u, host, port)
			if err != nil || u.Send == nil {
				return conn, err
			}
			return &windscribeHelloConn{Conn: conn, send: u.Send}, nil
		}})
	}
	return methods
}

// Buffer only the initial ClientHello, including fragmented writes/records.
// Later TLS and WebSocket/OpenVPN bytes pass unchanged. Embedded net.Conn
// preserves deadlines and Close so the wrapper owns the socket lifecycle.
type windscribeHelloConn struct {
	net.Conn
	mu      sync.Mutex
	send    func(net.Conn, []byte) error
	pending []byte
	sent    bool
}

func (c *windscribeHelloConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent {
		return c.Conn.Write(p)
	}
	if len(c.pending)+len(p) > maxClientFlight {
		return 0, errors.New("Windscribe wrapper ClientHello exceeds limit")
	}
	c.pending = append(c.pending, p...)
	for offset := 0; offset+5 <= len(c.pending); {
		n, err := handshakeRecordSize(c.pending[offset:])
		if err != nil {
			return 0, err
		}
		end := offset + 5 + n
		if end > len(c.pending) {
			break
		}
		if _, complete := clientHelloMessage(c.pending[:end]); complete {
			if _, _, valid := ParseClientHello(c.pending[:end]); !valid {
				return 0, errors.New("invalid Windscribe wrapper ClientHello")
			}
			if err := c.send(c.Conn, c.pending[:end]); err != nil {
				return 0, err
			}
			if extra := c.pending[end:]; len(extra) > 0 {
				n, err := c.Conn.Write(extra)
				if err != nil {
					return 0, err
				}
				if n != len(extra) {
					return 0, io.ErrShortWrite
				}
			}
			c.pending, c.sent = nil, true
			break
		}
		offset = end
	}
	return len(p), nil
}
