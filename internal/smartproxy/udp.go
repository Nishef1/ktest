package smartproxy

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

// RFC 1928 UDP associations live exactly as long as their TCP control socket.
// DNS uses ExchangeDNS; other datagrams require a verified foreign SOCKS exit.
// In particular, UDP never falls back to an ISP socket when an exit fails.
func (p *Proxy) serveUDP(parent context.Context, control net.Conn, host, port string) {
	peer, ok := control.RemoteAddr().(*net.TCPAddr)
	local, localOK := control.LocalAddr().(*net.TCPAddr)
	ip := net.ParseIP(host)
	if !ok || !localOK || ip == nil || (!ip.IsUnspecified() && !ip.Equal(peer.IP)) {
		_, _ = control.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		_, _ = control.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer socket.Close()
	bound := socket.LocalAddr().(*net.UDPAddr)
	reply, _ := udpPacket(bound.IP.String(), strconv.Itoa(bound.Port), nil)
	reply[0], reply[1] = 5, 0
	if _, err := control.Write(reply); err != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close(); _ = control.Close() })
	defer stop()
	go func() { _, _ = io.Copy(io.Discard, control); cancel() }()
	var exit *udpExit
	defer func() {
		if exit != nil {
			exit.close()
		}
	}()
	clientPort, _ := strconv.Atoi(port)
	var client *net.UDPAddr
	// DNS is concurrent, but its outstanding work and lifetime are bounded.
	slots := make(chan struct{}, 8)
	var jobs sync.WaitGroup
	defer func() { cancel(); jobs.Wait() }()
	buffer := make([]byte, 65535)
	for {
		_ = socket.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, source, err := socket.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if !source.IP.Equal(peer.IP) || (clientPort != 0 && source.Port != clientPort) {
			continue
		}
		destination, dstPort, payload, err := parseUDPPacket(buffer[:n])
		if err != nil {
			continue
		}
		if client == nil {
			clientPort, client = source.Port, source
		}
		if dstPort == "53" && p.cfg.ExchangeDNS != nil {
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			data := append([]byte(nil), payload...)
			jobs.Add(1)
			go func() {
				defer jobs.Done()
				defer func() { <-slots }()
				dctx, done := context.WithTimeout(ctx, 8*time.Second)
				defer done()
				response, err := p.cfg.ExchangeDNS(dctx, data)
				if err != nil {
					if ctx.Err() == nil {
						p.emit(ctx, Event{Host: destination, Port: "53", Site: "DNS", Err: err.Error()})
					}
					return
				}
				packet, err := udpPacket(destination, dstPort, response)
				if err == nil {
					_, _ = socket.WriteToUDP(packet, source)
				}
			}()
			continue
		}
		if exit == nil {
			exit, err = p.openUDPExit(ctx, destination, dstPort)
			if err != nil {
				if ctx.Err() == nil {
					p.emit(ctx, Event{Host: destination, Port: dstPort, Site: siteKey(destination), Err: err.Error()})
				}
				continue
			}
			current, target := exit, client
			go func() {
				buf := make([]byte, 65535)
				for {
					n, err := current.socket.Read(buf)
					if err != nil {
						return
					}
					if _, _, _, err := parseUDPPacket(buf[:n]); err == nil {
						_, _ = socket.WriteToUDP(buf[:n], target)
					}
				}
			}()
		}
		if !p.udpExitAllowed(exit.route, destination) || p.verifyExit(ctx, exit.route) != nil {
			continue
		}
		// Preserve the SOCKS header, including numeric IPv6 destinations.
		_, _ = exit.socket.Write(buffer[:n])
	}
}

type udpExit struct {
	control net.Conn
	socket  *net.UDPConn
	route   *upstreamState
	stop    func() bool
}

func (e *udpExit) close() {
	e.stop()
	_ = e.socket.Close()
	_ = e.control.Close()
}

func (p *Proxy) udpExitAllowed(u *upstreamState, host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfg.LocalOnly || p.cfg.RejectExits || !u.Exit || !u.AIEligible ||
		(u.Match != nil && !u.Match(host)) || (p.aiPinned != "" && p.aiPinned != u.Name) {
		return false
	}
	for _, active := range p.ups {
		if active == u {
			return true
		}
	}
	return false
}

// UDP routing is distinct from a frozen TCP/HTTPS method. Balanced may
// select a local method for TCP while sending QUIC only through an already
// verified foreign SOCKS5 UDP associate. Never create a direct UDP fallback.
func (p *Proxy) udpCandidates(host string) []*upstreamState {
	p.mu.Lock()
	defer p.mu.Unlock()
	protected := p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host)
	selected := p.aiPinned
	if pins := p.cfg.Frozen; pins != nil && protected {
		if pins.Protected == "" {
			return nil
		}
		selected = pins.Protected
	}
	var out []*upstreamState
	for _, u := range p.ups {
		if !u.Exit || !u.AIEligible || (u.Match != nil && !u.Match(host)) {
			continue
		}
		if selected != "" && u.Name != selected {
			continue
		}
		out = append(out, u)
	}
	return out
}

func (p *Proxy) openUDPExit(ctx context.Context, host, port string) (*udpExit, error) {
	for _, u := range p.udpCandidates(host) {
		if !p.udpExitAllowed(u, host) || p.verifyExit(ctx, u) != nil {
			continue
		}
		e, err := dialUDPExit(ctx, u, p.cfg.ConnectTimeout)
		if err != nil {
			continue
		}
		p.mu.Lock()
		allowed := p.aiPinned == "" || p.aiPinned == u.Name
		if allowed {
			p.aiPinned = u.Name
		}
		p.mu.Unlock()
		if allowed {
			return e, nil
		}
		e.close()
	}
	return nil, errors.New("UDP requires a verified SOCKS5 foreign exit with UDP ASSOCIATE; direct fallback is disabled")
}

func dialUDPExit(ctx context.Context, route *upstreamState, timeout time.Duration) (*udpExit, error) {
	control, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", route.Addr)
	if err != nil {
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			_ = control.Close()
		}
	}()
	stopHandshake := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stopHandshake()
	_ = control.SetDeadline(time.Now().Add(timeout))
	if _, err = control.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var greeting [2]byte
	if _, err = io.ReadFull(control, greeting[:]); err != nil {
		return nil, err
	}
	if greeting != [2]byte{5, 0} {
		return nil, errors.New("SOCKS UDP authentication refused")
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var header [4]byte
	if _, err = io.ReadFull(control, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, errors.New("SOCKS UDP association refused")
	}
	length := 4
	if header[3] == 4 {
		length = 16
	} else if header[3] != 1 {
		return nil, errors.New("SOCKS UDP relay must use a numeric address")
	}
	address := make([]byte, length+2)
	if _, err = io.ReadFull(control, address); err != nil {
		return nil, err
	}
	ip := net.IP(address[:length])
	peer := control.RemoteAddr().(*net.TCPAddr).IP
	if ip.IsUnspecified() {
		ip = peer
	}
	// KTest's transport cores are local. Refuse a relay redirect to a public
	// UDP socket, which would send unencrypted datagrams outside that core.
	if !ip.IsLoopback() || !peer.IsLoopback() {
		return nil, errors.New("SOCKS UDP relay must remain on loopback")
	}
	port := int(binary.BigEndian.Uint16(address[length:]))
	if port == 0 {
		return nil, errors.New("invalid UDP relay port")
	}
	socket, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})
	e := &udpExit{control: control, socket: socket, route: route}
	e.stop = context.AfterFunc(ctx, func() { _ = socket.Close(); _ = control.Close() })
	go func() { _, _ = io.Copy(io.Discard, control); _ = socket.Close() }()
	good = true
	return e, nil
}

func parseUDPPacket(packet []byte) (host, port string, payload []byte, err error) {
	bad := func() (string, string, []byte, error) {
		return "", "", nil, errors.New("invalid or fragmented SOCKS UDP datagram")
	}
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return bad()
	}
	offset, length := 4, 0
	switch packet[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		if len(packet) < 5 || packet[4] == 0 {
			return bad()
		}
		offset, length = 5, int(packet[4])
	default:
		return bad()
	}
	if len(packet) < offset+length+2 {
		return bad()
	}
	if packet[3] == 3 {
		host = string(packet[offset : offset+length])
	} else {
		host = net.IP(packet[offset : offset+length]).String()
	}
	number := binary.BigEndian.Uint16(packet[offset+length:])
	if number == 0 {
		return bad()
	}
	return host, strconv.Itoa(int(number)), packet[offset+length+2:], nil
}

func udpPacket(host, port string, payload []byte) ([]byte, error) {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, fmt.Errorf("invalid UDP port %q", port)
	}
	out := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(append(out, 1), v4...)
		} else {
			out = append(append(out, 4), ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid UDP hostname")
		}
		out = append(append(out, 3, byte(len(host))), host...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(number))
	return append(out, payload...), nil
}
