package smartproxy

import "encoding/binary"

// ParseClientHello extracts SNI and ALPN from a complete ClientHello, including
// a handshake split across TLS records. Reject malformed or ambiguous vectors
// rather than routing a different name/protocol than the TLS peer requested.
func ParseClientHello(f []byte) (sni string, alpn []string, ok bool) {
	sni, alpn, _, ok = parseClientHello(f)
	return sni, alpn, ok
}

// ClientHelloOffersECH reports an outer encrypted_client_hello extension: the
// SNI is then only the provider's public name, not the real destination.
func ClientHelloOffersECH(f []byte) bool {
	_, _, ech, ok := parseClientHello(f)
	return ok && ech
}

func parseClientHello(f []byte) (sni string, alpn []string, ech bool, ok bool) {
	f, ok = clientHelloMessage(f)
	if !ok {
		return "", nil, false, false
	}
	recEnd := len(f)
	p := 4 + 2 + 32
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
		return "", nil, false, false
	}
	if p == recEnd {
		return "", nil, false, true // TLS 1.2 may omit extensions.
	}
	if p+2 > recEnd {
		return "", nil, false, false
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(f[p:p+2]))
	p += 2
	// Extensions form the final length-prefixed vector in ClientHello.
	if extEnd != recEnd {
		return "", nil, false, false
	}
	var seenSNI, seenALPN bool
	for p < extEnd {
		if p+4 > extEnd {
			return "", nil, false, false
		}
		typ := binary.BigEndian.Uint16(f[p : p+2])
		n := int(binary.BigEndian.Uint16(f[p+2 : p+4]))
		body := p + 4
		end := body + n
		if end > extEnd {
			return "", nil, false, false
		}
		switch typ {
		case 0: // server_name: uint16 list length, then typed names
			if seenSNI || n < 2 || int(binary.BigEndian.Uint16(f[body:body+2])) != n-2 {
				return "", nil, false, false
			}
			seenSNI = true
			for q := body + 2; q < end; {
				if q+3 > end {
					return "", nil, false, false
				}
				kind := f[q]
				size := int(binary.BigEndian.Uint16(f[q+1 : q+3]))
				q += 3
				if size == 0 || q+size > end {
					return "", nil, false, false
				}
				if kind == 0 {
					// A second host_name makes routing ambiguous.
					if sni != "" {
						return "", nil, false, false
					}
					sni = string(f[q : q+size])
				}
				q += size
			}
			if sni == "" {
				return "", nil, false, false
			}
		case 0xfe0d: // encrypted_client_hello; type 0 is the outer form
			ech = n > 0 && f[body] == 0
		case 16: // application_layer_protocol_negotiation
			if seenALPN || n < 2 || int(binary.BigEndian.Uint16(f[body:body+2])) != n-2 || n == 2 {
				return "", nil, false, false
			}
			seenALPN = true
			for q := body + 2; q < end; {
				size := int(f[q])
				q++
				if size == 0 || q+size > end {
					return "", nil, false, false
				}
				alpn = append(alpn, string(f[q:q+size]))
				q += size
			}
		}
		p = end
	}
	return sni, alpn, ech, true
}
