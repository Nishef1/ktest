package smartproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// readServerHello waits for the complete, structurally valid first handshake
// message, including fragmentation across records. It preserves every byte
// read for the client. This is framing validation, not TLS authentication:
// certificates and negotiated parameters remain the client's responsibility.
// RFC 8446 sections 4.1.3 and 5.1; TLS 1.2 uses the same ServerHello framing.
func readServerHello(r io.Reader) ([]byte, error) {
	var wire, handshake []byte
	for {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, fmt.Errorf("incomplete TLS record header: %w", err)
		}
		n := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || n == 0 || n > 16384 {
			return nil, errors.New("invalid initial TLS handshake record")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("incomplete TLS record body: %w", err)
		}
		wire = append(wire, header[:]...)
		wire = append(wire, body...)
		handshake = append(handshake, body...)
		if len(handshake) < 4 {
			continue
		}
		length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 2 || length < 38 || length > 65535+72 {
			return nil, errors.New("invalid ServerHello handshake header")
		}
		if len(handshake) < 4+length {
			continue
		}
		hello := handshake[4 : 4+length]
		if hello[0] != 3 || hello[1] < 1 || hello[1] > 3 || hello[34] > 32 {
			return nil, errors.New("invalid ServerHello version or session ID")
		}
		end := 35 + int(hello[34]) + 3 // session ID, cipher suite, compression
		if end > len(hello) {
			return nil, errors.New("truncated ServerHello parameters")
		}
		if end != len(hello) { // TLS 1.2 may omit extensions entirely.
			if end+2 > len(hello) || int(binary.BigEndian.Uint16(hello[end:])) != len(hello)-end-2 {
				return nil, errors.New("invalid ServerHello extensions length")
			}
			for offset := end + 2; offset < len(hello); {
				if offset+4 > len(hello) {
					return nil, errors.New("truncated ServerHello extension")
				}
				n := int(binary.BigEndian.Uint16(hello[offset+2:]))
				offset += 4 + n
				if offset > len(hello) {
					return nil, errors.New("truncated ServerHello extension data")
				}
			}
		}
		return wire, nil
	}
}
