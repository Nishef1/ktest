package smartproxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const maxClientFlight = 256 << 10

func handshakeRecordSize(header []byte) (int, error) {
	n := int(binary.BigEndian.Uint16(header[3:5]))
	if header[0] != 22 || header[1] != 3 || n == 0 || n > 16384 {
		return 0, errors.New("invalid ClientHello TLS record")
	}
	return n, nil
}

func clientHelloLength(message []byte) (int, error) {
	if len(message) < 4 {
		return 0, nil
	}
	n := int(message[1])<<16 | int(message[2])<<8 | int(message[3])
	if message[0] != 1 || n < 41 || n > maxClientFlight-4 {
		return 0, errors.New("invalid ClientHello handshake length")
	}
	return n + 4, nil
}

func clientHelloMessage(wire []byte) ([]byte, bool) {
	if len(wire) > maxClientFlight {
		return nil, false
	}
	var message []byte
	for offset := 0; offset+5 <= len(wire); {
		n, err := handshakeRecordSize(wire[offset:])
		end := offset + 5 + n
		if err != nil || end > len(wire) {
			return nil, false
		}
		message = append(message, wire[offset+5:end]...)
		want, err := clientHelloLength(message)
		if err != nil {
			return nil, false
		}
		if want > 0 && len(message) >= want {
			return message[:want], true
		}
		offset = end
	}
	return nil, false
}

// Gather the whole ClientHello before choosing any upstream. Extra client
// records (including early data) stay for the selected connection only.
// Partial/malformed TLS is rejected instead of falling through to raw TCP.
func readFirstFlight(c net.Conn, firstByteWait time.Duration) (flight, extra []byte, err error) {
	_ = c.SetReadDeadline(time.Now().Add(firstByteWait))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 16*1024)
	n, readErr := c.Read(buf)
	buf = buf[:n]
	if n == 0 {
		if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
			return nil, nil, nil
		}
		if readErr == nil {
			readErr = io.EOF
		}
		return nil, nil, readErr
	} // server-first protocol or abandoned client
	if buf[0] != 22 || (len(buf) > 1 && buf[1] != 3) {
		return buf, nil, nil
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	ensure := func(want int) error {
		if want > maxClientFlight {
			return errors.New("ClientHello exceeds probe limit")
		}
		if len(buf) >= want {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		old := len(buf)
		buf = append(buf, make([]byte, want-old)...)
		_, err := io.ReadFull(c, buf[old:])
		return err
	}
	var message []byte
	for offset := 0; ; {
		if err := ensure(offset + 5); err != nil {
			return nil, nil, err
		}
		n, err := handshakeRecordSize(buf[offset:])
		if err != nil {
			return nil, nil, err
		}
		end := offset + 5 + n
		if err := ensure(end); err != nil {
			return nil, nil, err
		}
		message = append(message, buf[offset+5:end]...)
		want, err := clientHelloLength(message)
		if err != nil {
			return nil, nil, err
		}
		if want > 0 && len(message) >= want {
			if _, _, ok := ParseClientHello(buf[:end]); !ok {
				return nil, nil, errors.New("malformed ClientHello; no route attempted")
			}
			return buf[:end], buf[end:], nil
		}
		offset = end
	}
}

type pendingConn struct {
	net.Conn
	pending []byte
}

func (c *pendingConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
func (c *pendingConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
