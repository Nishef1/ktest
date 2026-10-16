package smartproxy

import "encoding/binary"

// ParseClientHello extracts the server name and the offered ALPN protocols from
// a ClientHello that fits in the single TLS record at the start of f. ok is
// false when f is not such a record.
func ParseClientHello(f []byte) (sni string, alpn []string, ok bool) {
	if len(f) < 9 || f[0] != 0x16 || f[5] != 0x01 {
		return "", nil, false
	}
	recEnd := 5 + int(binary.BigEndian.Uint16(f[3:5]))
	if recEnd > len(f) {
		return "", nil, false
	}
	p := 5 + 4 + 2 + 32
	skip := func(lenBytes int) bool {
		if p+lenBytes > recEnd {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(f[p+i])
		}
		p += lenBytes + n
		return p <= recEnd
	}
	if !skip(1) || !skip(2) || !skip(1) {
		return "", nil, false
	}
	if p+2 > recEnd {
		return "", nil, false
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(f[p:p+2]))
	p += 2
	if extEnd > recEnd {
		return "", nil, false
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(f[p : p+2])
		n := int(binary.BigEndian.Uint16(f[p+2 : p+4]))
		body := p + 4
		if body+n > extEnd {
			return "", nil, false
		}
		switch typ {
		case 0: // server_name
			if n >= 5 {
				nameLen := int(binary.BigEndian.Uint16(f[body+3 : body+5]))
				if nameLen > 0 && 5+nameLen <= n {
					sni = string(f[body+5 : body+5+nameLen])
				}
			}
		case 16: // application_layer_protocol_negotiation
			if n >= 2 {
				q, end := body+2, body+n
				for q < end {
					l := int(f[q])
					q++
					if q+l > end {
						break
					}
					alpn = append(alpn, string(f[q:q+l]))
					q += l
				}
			}
		}
		p = body + n
	}
	return sni, alpn, true
}
