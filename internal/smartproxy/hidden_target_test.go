package smartproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// echExtension is an outer (type 0) or inner (type 1) encrypted_client_hello.
func echExtension(kind byte) []byte {
	return clientHelloExtension(0xfe0d, append([]byte{kind}, make([]byte, 40)...))
}

func dnsResponse(name string, ips ...net.IP) []byte {
	m := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, byte(len(ips)), 0, 0, 0, 0}
	for _, label := range splitLabels(name) {
		m = append(append(m, byte(len(label))), label...)
	}
	m = append(m, 0, 0, 1, 0, 1)
	for _, ip := range ips {
		typ, data := uint16(1), ip.To4()
		if data == nil {
			typ, data = 28, ip.To16()
		}
		m = append(m, 0xc0, 12) // compression pointer to the question
		m = binary.BigEndian.AppendUint16(m, typ)
		m = append(m, 0, 1, 0, 0, 0, 60)
		m = binary.BigEndian.AppendUint16(m, uint16(len(data)))
		m = append(m, data...)
	}
	return m
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return out
}

func TestClientHelloOffersOuterECHOnly(t *testing.T) {
	outer := helloWithExtensions(append(sniExtension("cloudflare-ech.com"), echExtension(0)...))
	if sni, _, ok := ParseClientHello(outer); !ok || sni != "cloudflare-ech.com" {
		t.Fatalf("ECH ClientHello no longer parses: %q %t", sni, ok)
	}
	if !ClientHelloOffersECH(outer) {
		t.Fatal("outer ECH extension not detected")
	}
	if ClientHelloOffersECH(helloWithExtensions(append(sniExtension("example.com"), echExtension(1)...))) {
		t.Fatal("an inner ECH marker is not a hidden outer name")
	}
	if ClientHelloOffersECH(helloWithExtensions(sniExtension("example.com"))) {
		t.Fatal("plain ClientHello reported as ECH")
	}
}

func TestDNSAnswersMapAddressesToTheQuestion(t *testing.T) {
	name, ips := dnsAddressAnswers(dnsResponse("chatgpt.com", net.ParseIP("104.18.32.47"), net.ParseIP("2606:4700::6812:202f")))
	if name != "chatgpt.com" || len(ips) != 2 || !ips[0].Equal(net.ParseIP("104.18.32.47")) || !ips[1].Equal(net.ParseIP("2606:4700::6812:202f")) {
		t.Fatalf("answers = %q %v", name, ips)
	}
	truncated := dnsResponse("chatgpt.com", net.ParseIP("104.18.32.47"))
	if _, ips := dnsAddressAnswers(truncated[:len(truncated)-2]); ips != nil {
		t.Fatalf("truncated response yielded %v", ips)
	}
}

func TestHiddenECHTargetDecision(t *testing.T) {
	protected := func(host string) bool { return host == "chatgpt.com" }
	p := &Proxy{cfg: Config{ExitOnly: protected}}
	if !p.hiddenTargetProtected("104.18.32.47") {
		t.Fatal("an address with no known name must fail closed")
	}
	p.learnDNS(dnsResponse("example.org", net.ParseIP("104.18.32.47")))
	if p.hiddenTargetProtected("104.18.32.47") {
		t.Fatal("an address known only for ordinary names was treated as protected")
	}
	// A shared CDN address is protected once any protected name used it.
	p.learnDNS(dnsResponse("chatgpt.com", net.ParseIP("104.18.32.47")))
	if !p.hiddenTargetProtected("104.18.32.47") {
		t.Fatal("shared address of a protected name was not protected")
	}
	local := &Proxy{cfg: Config{ExitOnly: protected, LocalOnly: true}}
	if local.hiddenTargetProtected("104.18.32.47") {
		t.Fatal("local-only mode would break every unknown ECH address")
	}
	none := &Proxy{}
	if none.hiddenTargetProtected("104.18.32.47") || none.exitOnly("104.18.32.47") {
		t.Fatal("modes without protected names changed")
	}
}

// An address-only ECH connection to a protected service must never take the
// local path just because its outer SNI is a provider's public name.
func TestAddressOnlyECHNeverUsesLocalPathForUnknownTarget(t *testing.T) {
	requested := make(chan string, 4)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				host, port, err := socksRequest(c)
				if err != nil {
					return
				}
				requested <- net.JoinHostPort(host, port)
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	p, err := New(Config{Upstreams: []Upstream{{Name: "local", Addr: l.Addr().String()}},
		ExitOnly: func(host string) bool { return host == "chatgpt.com" }, RecoverIPHostSNI: true,
		FirstByteTimeout: 200 * time.Millisecond, ConnectTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); front.Close() })
	go func() { _ = p.Serve(ctx, front) }()
	send := func(addr [4]byte, hello []byte) {
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte{5, 1, 0})
		_, _ = io.ReadFull(c, make([]byte, 2))
		_, _ = c.Write([]byte{5, 1, 0, 1, addr[0], addr[1], addr[2], addr[3], 1, 187})
		_, _ = io.ReadFull(c, make([]byte, 10))
		_, _ = c.Write(hello)
		_, _ = io.ReadAll(c)
	}
	send([4]byte{104, 18, 32, 47}, helloWithExtensions(append(sniExtension("cloudflare-ech.com"), echExtension(0)...)))
	select {
	case got := <-requested:
		t.Fatalf("hidden ECH target took the local path to %s", got)
	case <-time.After(300 * time.Millisecond):
	}
	if !p.exitOnly("104.18.32.47") {
		t.Fatal("hidden address not held as protected")
	}
	// A known ordinary address keeps its normal route.
	p.learnDNS(dnsResponse("example.org", net.ParseIP("104.18.32.48")))
	go send([4]byte{104, 18, 32, 48}, helloWithExtensions(append(sniExtension("cloudflare-ech.com"), echExtension(0)...)))
	select {
	case got := <-requested:
		if got != "104.18.32.48:443" {
			t.Fatalf("ordinary ECH address dialed %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ordinary ECH address was blocked")
	}
}

func TestAetherUDPCarrierOnlyForKnownOrdinaryDestinations(t *testing.T) {
	p, err := New(Config{
		Upstreams:    []Upstream{{Name: "carrier", Addr: "127.0.0.1:9", Exit: true}},
		ExitOnly:     func(host string) bool { return host == "chatgpt.com" },
		ExitRequired: func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.udpCandidates("www.youtube.com"); len(got) != 1 || got[0].Name != "carrier" {
		t.Fatalf("ordinary named UDP = %v, want the working carrier", got)
	}
	if got := p.udpCandidates("chatgpt.com"); len(got) != 0 {
		t.Fatalf("protected UDP used an Iran-located carrier: %v", got)
	}
	if got := p.udpCandidates("142.250.1.1"); len(got) != 0 {
		t.Fatalf("unknown address UDP used an Iran-located carrier: %v", got)
	}
	p.learnDNS(dnsResponse("www.youtube.com", net.ParseIP("142.250.1.1")))
	if got := p.udpCandidates("142.250.1.1"); len(got) != 1 {
		t.Fatalf("known ordinary address UDP = %v, want the carrier", got)
	}
	p.learnDNS(dnsResponse("chatgpt.com", net.ParseIP("142.250.1.1")))
	if got := p.udpCandidates("142.250.1.1"); len(got) != 0 {
		t.Fatalf("address shared with a protected name used the carrier: %v", got)
	}
	balanced, err := New(Config{
		Upstreams: []Upstream{{Name: "carrier", Addr: "127.0.0.1:9", Exit: true}},
		ExitOnly:  func(host string) bool { return host == "chatgpt.com" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := balanced.udpCandidates("www.youtube.com"); len(got) != 0 {
		t.Fatalf("modes without ExitRequired must keep foreign-only UDP: %v", got)
	}
}
