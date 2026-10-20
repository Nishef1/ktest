package exitnode

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Server is a loopback SOCKS5 exit-node: Xray's freedom outbound with a
// finalMask, as PattNG gives every Aether core. It serves CONNECT and
// UDP ASSOCIATE, without authentication, on a loopback address only.
type Server struct {
	mask     Mask
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	listenUP func() (net.PacketConn, error)
}

// Start listens on address, which must be loopback (port 0 picks one).
func Start(parent context.Context, address string, mask Mask) (*Server, error) {
	host, _, err := net.SplitHostPort(address)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("the exit-node listens on a loopback address only")
	}
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{mask: mask, listener: l, ctx: ctx, cancel: cancel,
		dial:     (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		listenUP: func() (net.PacketConn, error) { return net.ListenUDP("udp", nil) }}
	s.wg.Add(1)
	go s.serve()
	go func() { <-ctx.Done(); l.Close() }()
	return s, nil
}

// Addr is the loopback SOCKS5 address for --upstream socks5://<Addr>.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// Stop closes the listener and every relayed connection.
func (s *Server) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			stop := context.AfterFunc(s.ctx, func() { c.Close() })
			defer stop()
			_ = s.handle(c)
		}()
	}
}

const (
	cmdConnect   = 1
	cmdAssociate = 3
)

func (s *Server) handle(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != 5 {
		return errors.New("not socks5")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		_, _ = c.Write([]byte{5, 0xff})
		return errors.New("no acceptable method")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return err
	}
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return errors.New("bad request")
	}
	target, err := readAddr(c)
	if err != nil {
		return err
	}
	switch req[1] {
	case cmdConnect:
		remote, err := s.dial(s.ctx, "tcp", target)
		if err != nil {
			_, _ = c.Write(reply(5, nil))
			return err
		}
		defer remote.Close()
		if _, err := c.Write(reply(0, remote.LocalAddr())); err != nil {
			return err
		}
		_ = c.SetDeadline(time.Time{})
		relayTCP(c, wrapTCP(remote, s.mask.TCP))
		return nil
	case cmdAssociate:
		return s.associate(c)
	default:
		_, _ = c.Write(reply(7, nil))
		return fmt.Errorf("unsupported command %d", req[1])
	}
}

func relayTCP(client, remote net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, client)
		closeWrite(remote)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, remote)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	for {
		switch v := c.(type) {
		case interface{ CloseWrite() error }:
			_ = v.CloseWrite()
			return
		case *fragmentConn:
			c = v.Conn
		default:
			return
		}
	}
}

// associate opens a loopback relay; datagrams leave through one masked
// socket and replies return with their origin. It ends with the control conn.
func (s *Server) associate(control net.Conn) error {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_, _ = control.Write(reply(1, nil))
		return err
	}
	defer relay.Close()
	raw, err := s.listenUP()
	if err != nil {
		_, _ = control.Write(reply(1, nil))
		return err
	}
	defer raw.Close()
	out := wrapUDP(raw, s.mask.UDP)
	if _, err := control.Write(reply(0, relay.LocalAddr())); err != nil {
		return err
	}
	_ = control.SetDeadline(time.Time{})

	var mu sync.Mutex
	var client *net.UDPAddr
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.IsLoopback() {
				continue
			}
			target, payload, err := parseUDP(buf[:n])
			if err != nil {
				continue
			}
			addr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				continue
			}
			mu.Lock()
			client = from
			mu.Unlock()
			_, _ = out.WriteTo(payload, addr)
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := raw.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			to := client
			mu.Unlock()
			if to == nil {
				continue
			}
			framed := append(udpHeader(from), buf[:n]...)
			_, _ = relay.WriteToUDP(framed, to)
		}
	}()
	_, _ = io.Copy(io.Discard, control)
	return nil
}

func readAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 1, 4:
		ip := make([]byte, 4)
		if atyp[0] == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", fmt.Errorf("address type %d", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func parseUDP(b []byte) (string, []byte, error) {
	if len(b) < 4 || b[2] != 0 {
		return "", nil, errors.New("fragmented or short datagram")
	}
	r := &sliceReader{b: b[3:]}
	target, err := readAddr(r)
	if err != nil {
		return "", nil, err
	}
	return target, r.b, nil
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func encodeAddr(a net.Addr) []byte {
	ip, port := net.IPv4zero, 0
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, port = v.IP, v.Port
	case *net.UDPAddr:
		ip, port = v.IP, v.Port
	}
	var out []byte
	if ip4 := ip.To4(); ip4 != nil {
		out = append([]byte{1}, ip4...)
	} else {
		out = append([]byte{4}, ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(port))
}

func reply(code byte, bound net.Addr) []byte {
	if bound == nil {
		bound = &net.TCPAddr{IP: net.IPv4zero}
	}
	return append([]byte{5, code, 0}, encodeAddr(bound)...)
}

func udpHeader(from net.Addr) []byte { return append([]byte{0, 0, 0}, encodeAddr(from)...) }
