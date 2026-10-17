package mobilebridge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// UDPRelayReport reports a real DNS roundtrip through SOCKS5 UDP ASSOCIATE.
// It is intentionally *not* evidence of a foreign exit, tunnel privacy, or
// leak-free VPN. HEV/VpnService must not be enabled based on SOCKS ACK alone.
type UDPRelayReport struct {
	Ready       bool   `json:"ready"`
	Relay       string `json:"relay"`
	DNSAnswered bool   `json:"dns_answered"`
	Note        string `json:"note"`
}

// CheckUDPRelay is safe to expose through gomobile. It only accepts an
// explicitly supplied local SOCKS server, never arbitrary public proxies.
func CheckUDPRelay(address string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	report, err := probeUDPRelay(ctx, address)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(report)
	return string(b), err
}

func probeUDPRelay(ctx context.Context, address string) (UDPRelayReport, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return UDPRelayReport{}, errors.New("SOCKS5 address must be host:port")
	}
	portN, err := strconv.Atoi(port)
	if err != nil || portN < 1 || portN > 65535 {
		return UDPRelayReport{}, errors.New("invalid SOCKS5 port")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || ip.To4() == nil {
		return UDPRelayReport{}, errors.New("UDP preflight requires an IPv4 loopback SOCKS5 endpoint")
	}
	socksAddress := net.JoinHostPort(host, port)
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", socksAddress)
	if err != nil {
		return UDPRelayReport{}, fmt.Errorf("SOCKS5 TCP: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return UDPRelayReport{}, err
	}
	var ack [2]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return UDPRelayReport{}, err
	}
	if ack != [2]byte{5, 0} {
		return UDPRelayReport{}, errors.New("SOCKS5 no-auth handshake rejected")
	}
	// UDP ASSOCIATE: 0.0.0.0:0 indicates no previously allocated UDP port.
	if _, err := conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return UDPRelayReport{}, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return UDPRelayReport{}, err
	}
	if hdr[0] != 5 || hdr[1] != 0 || hdr[2] != 0 {
		return UDPRelayReport{}, errors.New("SOCKS5 UDP ASSOCIATE not supported")
	}
	var relayIP net.IP
	switch hdr[3] {
	case 1:
		var raw [4]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil { return UDPRelayReport{}, err }
		relayIP = net.IP(raw[:])
	case 4:
		// This first adapter is IPv4-only. Never silently fall back to IPv6.
		return UDPRelayReport{}, errors.New("IPv6 UDP relay not yet supported")
	default:
		return UDPRelayReport{}, errors.New("unsupported UDP relay address type")
	}
	var pbuf [2]byte
	if _, err := io.ReadFull(conn, pbuf[:]); err != nil { return UDPRelayReport{}, err }
	relayPort := int(binary.BigEndian.Uint16(pbuf[:]))
	if relayPort == 0 { return UDPRelayReport{}, errors.New("SOCKS5 returned UDP port zero") }
	if relayIP.IsUnspecified() { relayIP = ip }
	// Refuse relays outside loopback: a local SOCKS server should not force
	// a direct UDP packet to a third-party public address.
	if !relayIP.IsLoopback() || relayIP.To4() == nil {
		return UDPRelayReport{}, errors.New("SOCKS5 returned a non-loopback UDP relay")
	}

	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: relayIP, Port: relayPort})
	if err != nil { return UDPRelayReport{}, err }
	defer socket.Close()
	if deadline, ok := ctx.Deadline(); ok { _ = socket.SetDeadline(deadline) }
	// A fresh DNS query carried *inside* the UDP SOCKS framing. Receiving an
	// answer distinguishes a working UDP path from a false-positive ACK.
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil { return UDPRelayReport{}, err }
	query := []byte{nonce[0], nonce[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "com"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	frame := []byte{0, 0, 0, 1, 1, 1, 1, 1, 0, 53} // 1.1.1.1:53
	frame = append(frame, query...)
	if _, err := socket.Write(frame); err != nil { return UDPRelayReport{}, err }
	reply := make([]byte, 1500)
	n, err := socket.Read(reply)
	if err != nil { return UDPRelayReport{}, fmt.Errorf("UDP DNS response not received: %w", err) }
	// SOCKS5 UDP framing has RSV=0, FRAG=0, ATYP=IPv4 (10 bytes total)
	// followed by DNS response whose transaction ID and question must match.
	if n < 10+len(query) || reply[0] != 0 || reply[1] != 0 || reply[2] != 0 || reply[3] != 1 {
		return UDPRelayReport{}, errors.New("malformed SOCKS5 UDP response")
	}
	// The SOCKS UDP reply must identify the DNS endpoint requested, not
	// merely contain a plausible DNS packet with our transaction ID.
	if !net.IP(reply[4:8]).Equal(net.IPv4(1, 1, 1, 1)) || binary.BigEndian.Uint16(reply[8:10]) != 53 {
		return UDPRelayReport{}, errors.New("SOCKS UDP response source differs from DNS target")
	}
	packet := reply[10:n]
	if packet[0] != nonce[0] || packet[1] != nonce[1] ||
		packet[2]&0x80 == 0 || packet[3]&0x0f != 0 ||
		packet[3]&0x02 != 0 || binary.BigEndian.Uint16(packet[4:6]) != 1 ||
		binary.BigEndian.Uint16(packet[6:8]) == 0 {
		return UDPRelayReport{}, errors.New("DNS response was missing, truncated or did not match")
	}
	// The question is identical because the response reflects it verbatim.
	if !strings.EqualFold(string(packet[12:len(query)]), string(query[12:])) {
		return UDPRelayReport{}, errors.New("DNS question mismatch")
	}
	return UDPRelayReport{
		Ready: true, Relay: net.JoinHostPort(relayIP.String(), strconv.Itoa(relayPort)),
		DNSAnswered: true,
		Note: "SOCKS5 UDP ASSOCIATE and DNS response succeeded. Not proof of leak-free VPN or foreign UDP egress.",
	}, nil
}
