package exitnode

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type recordConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (r *recordConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func clientHello(body int) []byte {
	p := []byte{22, 3, 1, byte(body >> 8), byte(body)}
	for i := 0; i < body; i++ {
		p = append(p, byte(i))
	}
	return p
}

func TestPresetsParse(t *testing.T) {
	for _, name := range Presets() {
		m, err := Preset(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == PresetUDPNoise {
			if len(m.UDP) != 1 || len(m.UDP[0].Items) != 24 || m.UDP[0].Reset != (Range{28, 28}) {
				t.Fatalf("udp-noise = %+v", m.UDP)
			}
			if it := m.UDP[0].Items[0]; it.Rand != (Range{1200, 1230}) || it.Delay != (Range{10, 10}) || it.RandRange != (Range{0, 255}) {
				t.Fatalf("noise item = %+v", it)
			}
			continue
		}
		if len(m.TCP) != 2 || m.TCP[0].PacketsTo != 1 || m.TCP[1].PacketsFrom != 1 || m.TCP[1].MaxSplit != (Range{11, 11}) {
			t.Fatalf("%s = %+v", name, m.TCP)
		}
	}
}

// The tlshello mask alone re-frames the ClientHello as records of 0, 104 and
// then 1 byte, merged into one write because delays is exactly ["0"].
func TestTLSHelloRecords(t *testing.T) {
	m, _ := Preset(PresetTLSHelloZero)
	rec := &recordConn{}
	hello := clientHello(300)
	c := wrapTCP(rec, m.TCP[:1])
	if n, err := c.Write(hello); err != nil || n != len(hello) {
		t.Fatalf("write = %d, %v", n, err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("writes = %d, want one merged write", len(rec.writes))
	}
	out := rec.writes[0]
	var bodies []int
	var joined []byte
	for len(out) > 0 {
		if out[0] != 22 || !bytes.Equal(out[1:3], hello[1:3]) {
			t.Fatalf("bad record header % x", out[:5])
		}
		n := int(binary.BigEndian.Uint16(out[3:5]))
		bodies = append(bodies, n)
		joined = append(joined, out[5:5+n]...)
		out = out[5+n:]
	}
	if bodies[0] != 0 || bodies[1] != 104 || len(bodies) != 2+300-104 || bodies[2] != 1 {
		t.Fatalf("record sizes = %v...", bodies[:3])
	}
	if !bytes.Equal(joined, hello[5:]) {
		t.Fatal("records do not carry the original ClientHello")
	}
	// Only the first write is touched.
	_, _ = c.Write(hello)
	if len(rec.writes) != 2 || !bytes.Equal(rec.writes[1], hello) {
		t.Fatal("a later write was changed")
	}
}

// The "1-1" mask splits the first write into 114 bytes and then single bytes,
// eleven writes at most, and leaves the rest whole.
func TestFirstPacketSplit(t *testing.T) {
	m, _ := Preset(PresetTLSHello)
	rec := &recordConn{}
	c := &fragmentConn{Conn: rec, cfg: m.TCP[1]}
	p := clientHello(400)
	if n, err := c.Write(p); err != nil || n != len(p) {
		t.Fatalf("write = %d, %v", n, err)
	}
	if len(rec.writes) != 11 || len(rec.writes[0]) != 114 || len(rec.writes[1]) != 1 || len(rec.writes[10]) != len(p)-114-9 {
		t.Fatalf("splits = %d (first %d)", len(rec.writes), len(rec.writes[0]))
	}
	if !bytes.Equal(bytes.Join(rec.writes, nil), p) {
		t.Fatal("split bytes differ")
	}
}

// Xray stacks masks with the first innermost, so in PattNG's preset the "1-1"
// mask sees the ClientHello first and hands the tlshello mask a 114-byte
// piece, shorter than the record, which it passes on unchanged. On the wire
// the preset is therefore TCP segmentation of the first write, not records.
func TestPresetStackOrder(t *testing.T) {
	m, _ := Preset(PresetTLSHelloZero)
	rec := &recordConn{}
	hello := clientHello(400)
	_, _ = wrapTCP(rec, m.TCP).Write(hello)
	if len(rec.writes) != 11 || len(rec.writes[0]) != 114 || !bytes.Equal(bytes.Join(rec.writes, nil), hello) {
		t.Fatalf("writes = %d", len(rec.writes))
	}
}

type countPacketConn struct {
	net.PacketConn
	sizes []int
}

func (c *countPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.sizes = append(c.sizes, len(p))
	return len(p), nil
}

func TestNoiseBeforeFirstDatagram(t *testing.T) {
	m, _ := Preset(PresetUDPNoise)
	m.UDP[0].Items = m.UDP[0].Items[:3]
	for i := range m.UDP[0].Items {
		m.UDP[0].Items[i].Delay = Range{}
	}
	raw := &countPacketConn{}
	c := wrapUDP(raw, m.UDP)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2408}
	_, _ = c.WriteTo([]byte("hello"), addr)
	_, _ = c.WriteTo([]byte("again"), addr)
	if len(raw.sizes) != 5 || raw.sizes[3] != 5 || raw.sizes[4] != 5 {
		t.Fatalf("datagram sizes = %v", raw.sizes)
	}
	for _, n := range raw.sizes[:3] {
		if n < 1200 || n > 1230 {
			t.Fatalf("noise size %d", n)
		}
	}
}

func socksGreet(t *testing.T, addr string, cmd byte, target []byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 0})
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b != [2]byte{5, 0} {
		t.Fatalf("greeting %v %v", b, err)
	}
	c.Write(append([]byte{5, cmd, 0}, target...))
	return c
}

func readReply(t *testing.T, c net.Conn) *net.UDPAddr {
	t.Helper()
	var h [3]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[1] != 0 {
		t.Fatalf("reply %v %v", h, err)
	}
	a, err := readAddr(c)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := net.ResolveUDPAddr("udp", a)
	return u
}

func TestServerConnectAndAssociate(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	udp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer udp.Close()
	var seen sync.WaitGroup
	seen.Add(1)
	go func() {
		buf := make([]byte, 2048)
		noise := 0
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "ping" {
				if noise != 24 {
					t.Errorf("noise datagrams before ping = %d", noise)
				}
				udp.WriteToUDP([]byte("pong"), from)
				seen.Done()
				continue
			}
			noise++
		}
	}()

	m, _ := Preset(PresetTLSHelloZero)
	m.UDP = mustPreset(t, PresetUDPNoise).UDP
	s, err := Start(context.Background(), "127.0.0.1:0", m)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	echoAddr := echo.Addr().(*net.TCPAddr)
	c := socksGreet(t, s.Addr(), cmdConnect, encodeAddr(echoAddr))
	readReply(t, c)
	hello := clientHello(250)
	c.Write(hello)
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatalf("CONNECT changed the stream")
	}
	c.Close()

	ctl := socksGreet(t, s.Addr(), cmdAssociate, encodeAddr(&net.UDPAddr{IP: net.IPv4zero}))
	relay := readReply(t, ctl)
	defer ctl.Close()
	u, _ := net.DialUDP("udp", nil, relay)
	defer u.Close()
	u.Write(append(append([]byte{0, 0, 0}, encodeAddr(udp.LocalAddr())...), "ping"...))
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	target, payload, err := parseUDP(buf[:n])
	if err != nil || string(payload) != "pong" || target != udp.LocalAddr().String() {
		t.Fatalf("relay reply %q from %s: %v", payload, target, err)
	}
	seen.Wait()
}

func mustPreset(t *testing.T, name string) Mask {
	m, err := Preset(name)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStartRejectsNonLoopback(t *testing.T) {
	if _, err := Start(context.Background(), "0.0.0.0:0", Mask{}); err == nil {
		t.Fatal("listened on a public address")
	}
}

// A WARP scan probes many closed ports; their ICMP replies must not end the
// association (Windows reports them as WSAECONNRESET on the next read).
func TestAssociateSurvivesUnreachablePorts(t *testing.T) {
	udp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer udp.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udp.WriteToUDP(buf[:n], from)
		}
	}()
	closed, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	dead := closed.LocalAddr()
	closed.Close()

	s, err := Start(context.Background(), "127.0.0.1:0", Mask{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	ctl := socksGreet(t, s.Addr(), cmdAssociate, encodeAddr(&net.UDPAddr{IP: net.IPv4zero}))
	defer ctl.Close()
	u, _ := net.DialUDP("udp", nil, readReply(t, ctl))
	defer u.Close()
	send := func(to net.Addr, p string) {
		u.Write(append(append([]byte{0, 0, 0}, encodeAddr(to)...), p...))
	}
	for i := 0; i < 3; i++ {
		send(dead, "nobody")
		time.Sleep(20 * time.Millisecond)
	}
	send(udp.LocalAddr(), "alive")
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatalf("association died after unreachable ports: %v", err)
	}
	if _, payload, _ := parseUDP(buf[:n]); string(payload) != "alive" {
		t.Fatalf("payload %q", payload)
	}
}
