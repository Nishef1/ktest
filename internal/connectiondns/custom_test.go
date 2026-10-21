package connectiondns

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAndParseCustomDNSList(t *testing.T) {
	servers, err := ParseServerList("1.1.1.1\n[2606:4700:4700::1111]:53, 8.8.8.8:5353\n1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 unique servers, got %v", servers)
	}
	for _, want := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53", "8.8.8.8:5353"} {
		found := false
		for _, got := range servers {
			found = found || got == want
		}
		if !found {
			t.Fatalf("missing normalized server %q in %v", want, servers)
		}
	}
	for _, bad := range []string{"dns.google", "1.1.1.1:0", "1.1.1.1:65536", "https://dns.google/dns-query"} {
		if _, err := NormalizeServer(bad); err == nil {
			t.Fatalf("accepted unsupported DNS entry %q", bad)
		}
	}
	if _, err := ParseServerList(strings.Repeat("1.1.1.1\n", 13)); err == nil {
		t.Fatal("accepted more than 12 DNS candidates")
	}
}

func TestCustomWireDNSRelaysAndValidatesUDPResponses(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := listener.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		response := append([]byte(nil), query...)
		response[2] |= 0x80
		_, _ = listener.WriteTo(response, addr)
	}()
	host, port, err := net.SplitHostPort(listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	server := net.JoinHostPort(host, strconv.Itoa(p))
	exchange, err := NewCustomWireDNS(server, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	query := testWireDNSQuery()
	response, err := exchange(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) < 17 || response[2]&0x80 == 0 || string(response[:2]) != string(query[:2]) {
		t.Fatalf("invalid DNS response: %x", response)
	}
}

func testWireDNSQuery() []byte {
	return append([]byte{0x4b, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0},
		[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}...)
}

func TestCustomWireDNSRejectsMismatchedResponse(t *testing.T) {
	query := testWireDNSQuery()
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	response[0]++
	qend, err := wireQuestionEnd(query)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWireDNSResponse(query, response, qend); err == nil {
		t.Fatal("accepted response with a different transaction ID")
	}
}
