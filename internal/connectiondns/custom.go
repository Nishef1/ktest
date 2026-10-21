package connectiondns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// ProbeResult distinguishes a DNS reply from a DNS resolver that can actually
// reach a verified HTTPS endpoint. A working DNS socket alone is not Internet.
type ProbeResult struct {
	Server         string   `json:"server"`
	UDP            bool     `json:"udp"`
	TCP            bool     `json:"tcp"`
	DNS            bool     `json:"dns"`
	Internet       bool     `json:"internet"`
	DNSLatencyMS   int64    `json:"dns_latency_ms"`
	HTTPSLatencyMS int64    `json:"https_latency_ms"`
	HTTPSHost      string   `json:"https_host,omitempty"`
	Addresses      []string `json:"addresses,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// NormalizeServer accepts an IP literal, optionally followed by a port.
// Hostnames are intentionally rejected so the resolver being tested does not
// depend on the system DNS that may itself be filtered or poisoned.
func NormalizeServer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 256 {
		return "", errors.New("enter a DNS server IP, optionally followed by :port")
	}
	host, port := strings.Trim(raw, "[]"), "53"
	if net.ParseIP(host) == nil {
		var err error
		host, port, err = net.SplitHostPort(raw)
		if err != nil {
			return "", errors.New("use an IP address or IP:port; DNS hostnames are not accepted")
		}
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "", errors.New("DNS server must be an IPv4 or IPv6 address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("DNS port must be between 1 and 65535")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(portNumber)), nil
}

// ParseServerList accepts one IP (or IP:port) per line, and also commas or
// semicolons. It bounds user input and removes duplicate endpoints.
func ParseServerList(raw string) ([]string, error) {
	if len(raw) > 4096 {
		return nil, errors.New("DNS list is too long (maximum 4096 characters)")
	}
	raw = strings.NewReplacer(",", "\n", ";", "\n").Replace(raw)
	seen := make(map[string]bool)
	var servers []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		server, err := NormalizeServer(line)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		if seen[server] {
			continue
		}
		seen[server] = true
		servers = append(servers, server)
		if len(servers) > 12 {
			return nil, errors.New("test at most 12 DNS servers at once")
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("enter at least one DNS server IP")
	}
	return servers, nil
}

func resolverForServer(server, forcedNetwork string, dial smartproxy.DialFunc) (*net.Resolver, error) {
	address, err := NormalizeServer(server)
	if err != nil {
		return nil, err
	}
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if dial != nil {
				// SOCKS CONNECT is TCP-only. DNS-over-TCP preserves the
				// selected resolver without leaking a UDP query outside the exit.
				return dial(ctx, "tcp", address)
			}
			if forcedNetwork != "" {
				network = forcedNetwork
			}
			if network != "tcp" && network != "udp" {
				network = "udp"
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
		},
	}, nil
}

// ProbeServer performs actual A-record queries over UDP and TCP, then verifies
// a TLS handshake against the returned addresses using the real hostname.
func ProbeServer(parent context.Context, raw string) ProbeResult {
	server, err := NormalizeServer(raw)
	result := ProbeResult{Server: server}
	if err != nil {
		result.Server, result.Error = strings.TrimSpace(raw), err.Error()
		return result
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()

	type lookup struct {
		host, transport string
		ips             []net.IP
		elapsed         time.Duration
		err             error
	}
	hosts := []string{"www.cloudflare.com", "example.com"}
	transports := []string{"udp", "tcp"}
	lookups := make(chan lookup, len(hosts)*len(transports))
	var wg sync.WaitGroup
	for _, host := range hosts {
		for _, transport := range transports {
			host, transport := host, transport
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, rerr := resolverForServer(server, transport, nil)
				if rerr != nil {
					lookups <- lookup{host: host, transport: transport, err: rerr}
					return
				}
				qctx, stop := context.WithTimeout(ctx, 2300*time.Millisecond)
				started := time.Now()
				ips, qerr := r.LookupIP(qctx, "ip4", host)
				elapsed := time.Since(started)
				stop()
				var usable []net.IP
				for _, ip := range ips {
					if ip != nil && !smartproxy.Bogus(ip) && ip.IsGlobalUnicast() {
						usable = append(usable, ip)
					}
				}
				if len(usable) == 0 && qerr == nil {
					qerr = errors.New("DNS returned no usable public IPv4 address")
				}
				lookups <- lookup{host: host, transport: transport, ips: usable, elapsed: elapsed, err: qerr}
			}()
		}
	}
	go func() { wg.Wait(); close(lookups) }()
	byHost := map[string][]net.IP{}
	var dnsBest time.Duration
	for item := range lookups {
		if item.err != nil || len(item.ips) == 0 {
			continue
		}
		if item.transport == "udp" {
			result.UDP = true
		} else {
			result.TCP = true
		}
		if dnsBest == 0 || item.elapsed < dnsBest {
			dnsBest = item.elapsed
		}
		for _, ip := range item.ips {
			duplicate := false
			for _, old := range byHost[item.host] {
				duplicate = duplicate || old.Equal(ip)
			}
			if !duplicate {
				byHost[item.host] = append(byHost[item.host], ip)
			}
		}
	}
	result.DNS = result.UDP || result.TCP
	if dnsBest > 0 {
		result.DNSLatencyMS = dnsBest.Milliseconds()
	}
	var candidates []struct {
		host string
		ip   net.IP
	}
	seenIP := map[string]bool{}
	for _, host := range hosts {
		for _, ip := range byHost[host] {
			if !seenIP[ip.String()] {
				seenIP[ip.String()] = true
				result.Addresses = append(result.Addresses, ip.String())
			}
			if len(candidates) < 4 {
				candidates = append(candidates, struct {
					host string
					ip   net.IP
				}{host, ip})
			}
		}
	}
	if len(candidates) > 0 {
		type tlsResult struct {
			host    string
			elapsed time.Duration
			ok      bool
		}
		tlsCtx, stopTLS := context.WithTimeout(ctx, 2800*time.Millisecond)
		results := make(chan tlsResult, len(candidates))
		for _, candidate := range candidates {
			candidate := candidate
			wg.Add(1)
			go func() {
				defer wg.Done()
				started := time.Now()
				dialer := &tls.Dialer{
					NetDialer: &net.Dialer{Timeout: 2200 * time.Millisecond},
					Config:    &tls.Config{ServerName: candidate.host, MinVersion: tls.VersionTLS12},
				}
				conn, dialErr := dialer.DialContext(tlsCtx, "tcp", net.JoinHostPort(candidate.ip.String(), "443"))
				if conn != nil {
					_ = conn.Close()
				}
				results <- tlsResult{host: candidate.host, elapsed: time.Since(started), ok: dialErr == nil}
			}()
		}
		go func() { wg.Wait(); close(results) }()
		for item := range results {
			if item.ok && (!result.Internet || item.elapsed < time.Duration(result.HTTPSLatencyMS)*time.Millisecond) {
				result.Internet = true
				result.HTTPSHost = item.host
				result.HTTPSLatencyMS = item.elapsed.Milliseconds()
			}
		}
		stopTLS()
	}
	switch {
	case !result.DNS:
		result.Error = "No usable public DNS answer over UDP or TCP"
	case !result.Internet:
		result.Error = "DNS answered, but HTTPS/TLS to the tested destinations was not verified"
	}
	return result
}

// NewCustomWireDNS relays complete DNS wire messages to an explicitly selected
// resolver. Plain UDP/TCP is used only after the user selects an IP resolver;
// when dial is supplied, all queries use TCP through that dialer (e.g. SOCKS).
func NewCustomWireDNS(raw string, dial smartproxy.DialFunc) (func(context.Context, []byte) ([]byte, error), error) {
	server, err := NormalizeServer(raw)
	if err != nil {
		return nil, err
	}
	exchange := func(ctx context.Context, query []byte) ([]byte, error) {
		qend, err := wireQuestionEnd(query)
		if err != nil || query[2]&0x80 != 0 || query[2]&0x78 != 0 {
			return nil, errors.New("invalid DNS query")
		}
		if dial != nil {
			return exchangeWireTCP(ctx, server, query, qend, dial)
		}
		udpCtx, cancel := context.WithTimeout(ctx, 1600*time.Millisecond)
		response, udpErr := exchangeWireUDP(udpCtx, server, query, qend)
		cancel()
		if udpErr == nil && response[2]&0x02 == 0 {
			return response, nil
		}
		tcpResponse, tcpErr := exchangeWireTCP(ctx, server, query, qend, nil)
		if tcpErr == nil {
			return tcpResponse, nil
		}
		if udpErr != nil {
			return nil, fmt.Errorf("custom DNS UDP and TCP failed: %v; %w", udpErr, tcpErr)
		}
		return nil, fmt.Errorf("custom DNS response was truncated and TCP failed: %w", tcpErr)
	}
	return exchange, nil
}

func exchangeWireUDP(ctx context.Context, server string, query []byte, questionEnd int) ([]byte, error) {
	conn, err := (&net.Dialer{Timeout: 1600 * time.Millisecond}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	setConnDeadline(ctx, conn)
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	response := append([]byte(nil), buffer[:n]...)
	if err := validateWireDNSResponse(query, response, questionEnd); err != nil {
		return nil, err
	}
	return response, nil
}

func exchangeWireTCP(ctx context.Context, server string, query []byte, questionEnd int, dial smartproxy.DialFunc) ([]byte, error) {
	var conn net.Conn
	var err error
	if dial != nil {
		conn, err = dial(ctx, "tcp", server)
	} else {
		conn, err = (&net.Dialer{Timeout: 2200 * time.Millisecond}).DialContext(ctx, "tcp", server)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	setConnDeadline(ctx, conn)
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if err := writeFull(conn, append(frame, query...)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 17 || n > 65535 {
		return nil, errors.New("invalid DNS-over-TCP response length")
	}
	response := make([]byte, n)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	if err := validateWireDNSResponse(query, response, questionEnd); err != nil {
		return nil, err
	}
	return response, nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func setConnDeadline(ctx context.Context, conn net.Conn) {
	deadline := time.Now().Add(3 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
}

func wireQuestionEnd(message []byte) (int, error) {
	if len(message) < 17 || len(message) > 65535 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return 0, errors.New("DNS must contain one question")
	}
	offset := 12
	for {
		if offset >= len(message) || offset-12 > 253 {
			return 0, errors.New("invalid DNS name")
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(message) {
			return 0, errors.New("invalid DNS label")
		}
		offset += length
	}
	if offset+4 > len(message) {
		return 0, errors.New("truncated DNS question")
	}
	return offset + 4, nil
}

func validateWireDNSResponse(query, response []byte, questionEnd int) error {
	responseEnd, err := wireQuestionEnd(response)
	if err != nil || len(response) > 65535 || response[2]&0x80 == 0 ||
		response[2]&0x78 != query[2]&0x78 ||
		!bytes.Equal(query[:2], response[:2]) ||
		responseEnd != questionEnd ||
		!strings.EqualFold(string(query[12:questionEnd-4]), string(response[12:responseEnd-4])) ||
		!bytes.Equal(query[questionEnd-4:questionEnd], response[responseEnd-4:responseEnd]) {
		return errors.New("custom DNS returned an invalid or mismatched response")
	}
	return nil
}
