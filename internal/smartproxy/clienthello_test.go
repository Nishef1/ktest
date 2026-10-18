package smartproxy

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func clientHelloExtension(typ uint16, data []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

func helloWithExtensions(exts []byte) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0, 0x2f, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 3, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func sniExtension(host string) []byte {
	entry := append([]byte{0, byte(len(host) >> 8), byte(len(host))}, host...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	return clientHelloExtension(0, append(list, entry...))
}

func alpnExtension(names ...string) []byte {
	var entries []byte
	for _, name := range names {
		entries = append(entries, byte(len(name)))
		entries = append(entries, name...)
	}
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entries)))
	return clientHelloExtension(16, append(list, entries...))
}

func TestParseClientHelloValidVectors(t *testing.T) {
	exts := append(sniExtension("www.youtube.com"), alpnExtension("h2", "http/1.1")...)
	exts = append(exts, clientHelloExtension(0x0a0a, nil)...)
	hello := helloWithExtensions(exts)
	sni, protocols, ok := ParseClientHello(hello)
	if !ok || sni != "www.youtube.com" || len(protocols) != 2 || protocols[0] != "h2" || protocols[1] != "http/1.1" {
		t.Fatalf("valid ClientHello: sni=%q alpn=%v ok=%t", sni, protocols, ok)
	}
	// A ClientHello is permitted to span multiple TLS handshake records.
	wire := hello[5:]
	cut := 19
	first := append([]byte{22, 3, 3, 0, byte(cut)}, wire[:cut]...)
	rest := wire[cut:]
	second := append([]byte{22, 3, 3, byte(len(rest) >> 8), byte(len(rest))}, rest...)
	sni, protocols, ok = ParseClientHello(append(first, second...))
	if !ok || sni != "www.youtube.com" || len(protocols) != 2 {
		t.Fatalf("fragmented ClientHello: sni=%q alpn=%v ok=%t", sni, protocols, ok)
	}
	if _, _, ok := ParseClientHello(clientHello()); !ok {
		t.Fatal("valid TLS 1.2 ClientHello without extensions was rejected")
	}
}

func TestParseClientHelloRejectsMalformedOrAmbiguousExtensions(t *testing.T) {
	validSNI := sniExtension("www.youtube.com")
	validALPN := alpnExtension("h2", "http/1.1")
	badSNIList := append([]byte(nil), validSNI...)
	badSNIList[5]++ // advertised server_name_list is too long
	badSNIName := append([]byte(nil), validSNI...)
	badSNIName[8]++ // advertised hostname is too long
	badALPNList := append([]byte(nil), validALPN...)
	badALPNList[5]++ // advertised ProtocolNameList is too long
	badALPNEntry := append([]byte(nil), validALPN...)
	badALPNEntry[6] = 0 // empty ProtocolName
	cases := []struct {
		name string
		exts []byte
	}{
		{"trailing extension byte", append(append([]byte(nil), validSNI...), 0)},
		{"incomplete extension header", append(append([]byte(nil), validSNI...), 0, 0, 0)},
		{"mismatched SNI list", badSNIList},
		{"mismatched SNI name", badSNIName},
		{"empty SNI list", clientHelloExtension(0, []byte{0, 0})},
		{"duplicate SNI", append(append([]byte(nil), validSNI...), validSNI...)},
		{"mismatched ALPN list", badALPNList},
		{"empty ALPN entry", badALPNEntry},
		{"empty ALPN list", clientHelloExtension(16, []byte{0, 0})},
		{"duplicate ALPN", append(append([]byte(nil), validALPN...), validALPN...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if sni, protos, ok := ParseClientHello(helloWithExtensions(tc.exts)); ok {
				t.Fatalf("invalid ClientHello accepted: sni=%q alpn=%v", sni, protos)
			}
		})
	}
}

func TestMalformedClientHelloCannotEnterPathRace(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	malformed := helloWithExtensions(append(sniExtension("www.youtube.com"), 0))
	go func() {
		_, _ = b.Write(malformed)
	}()
	if _, _, err := readFirstFlight(a, 200*time.Millisecond); err == nil {
		t.Fatal("malformed TLS ClientHello entered upstream race")
	}
}
