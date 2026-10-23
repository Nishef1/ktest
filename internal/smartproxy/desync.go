package smartproxy

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"time"
)

// This file is ktest's own, dependency-free ClientHello desync: it needs no
// raw sockets, no administrator rights and no external core. Each connection
// draws fresh random cut points and delays, so there is no fixed byte or
// timing pattern for a classifier to learn, and the race (not the user)
// decides which family works on the current network.
//
// Everything sent is valid TLS/TCP: a ClientHello may legally be split over
// several TLS records (RFC 8446 section 5.1) and over several TCP segments.
// Servers that do not accept it simply lose the race.

// sniRange returns the byte range of the host name inside a ClientHello flight
// (a single TLS handshake record), or ok=false if there is none.
func sniRange(f []byte) (start, end int, ok bool) {
	if len(f) < 9 || f[0] != 0x16 || f[5] != 0x01 {
		return 0, 0, false
	}
	recEnd := 5 + int(binary.BigEndian.Uint16(f[3:5]))
	if recEnd > len(f) {
		return 0, 0, false
	}
	p := 5 + 4 + 2 + 32 // record header, handshake header, version, random
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
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return 0, 0, false
	}
	if p+2 > recEnd {
		return 0, 0, false
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(f[p:p+2]))
	p += 2
	if extEnd > recEnd {
		return 0, 0, false
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(f[p : p+2])
		n := int(binary.BigEndian.Uint16(f[p+2 : p+4]))
		body := p + 4
		if body+n > extEnd {
			return 0, 0, false
		}
		if typ == 0 && n >= 5 { // server_name: list length, type, name length, name
			nameLen := int(binary.BigEndian.Uint16(f[body+3 : body+5]))
			if body+5+nameLen <= body+n && nameLen > 0 {
				return body + 5, body + 5 + nameLen, true
			}
			return 0, 0, false
		}
		p = body + n
	}
	return 0, 0, false
}

// splitRecords re-encodes the single handshake record of f as several records
// whose payloads are cut at the given absolute offsets (ascending, inside the
// payload).
func splitRecords(f []byte, cuts []int) ([][]byte, error) {
	if len(f) < 6 || f[0] != 0x16 {
		return nil, errors.New("not a handshake record")
	}
	payloadEnd := 5 + int(binary.BigEndian.Uint16(f[3:5]))
	if payloadEnd != len(f) {
		return nil, errors.New("flight is not exactly one record")
	}
	bounds := append([]int{5}, cuts...)
	bounds = append(bounds, payloadEnd)
	var out [][]byte
	for i := 0; i+1 < len(bounds); i++ {
		a, b := bounds[i], bounds[i+1]
		if a < 5 || b <= a || b > payloadEnd {
			return nil, errors.New("bad cut points")
		}
		rec := []byte{0x16, f[1], f[2], 0, 0}
		binary.BigEndian.PutUint16(rec[3:5], uint16(b-a))
		out = append(out, append(rec, f[a:b]...))
	}
	return out, nil
}

// SplitHelloInSNI re-encodes a ClientHello record as two TLS records cut inside
// the host name (RFC 8446 section 5.1), or returns nil when it cannot.
func SplitHelloInSNI(flight []byte) [][]byte {
	recs, err := splitRecords(flight, cutsInSNI(flight, 1))
	if err != nil || len(recs) < 2 {
		return nil
	}
	return recs
}

// cutsInSNI picks n distinct random offsets strictly inside the host name,
// falling back to early offsets when no SNI is present.
func cutsInSNI(f []byte, n int) []int {
	start, end, ok := sniRange(f)
	if !ok || end-start < n+1 {
		start, end = 6, 6+n+8
		if end >= len(f) {
			return nil
		}
	}
	set := map[int]bool{}
	for len(set) < n {
		set[start+1+rand.IntN(end-start-1)] = true
	}
	cuts := make([]int, 0, n)
	for c := range set {
		cuts = append(cuts, c)
	}
	for i := 1; i < len(cuts); i++ { // tiny insertion sort
		for j := i; j > 0 && cuts[j] < cuts[j-1]; j-- {
			cuts[j], cuts[j-1] = cuts[j-1], cuts[j]
		}
	}
	return cuts
}

func jitter() time.Duration { return time.Duration(8+rand.IntN(40)) * time.Millisecond }

// writeSegments sends each piece as its own TCP segment with a short random
// pause (TCP_NODELAY is on by default for Go connections).
func writeSegments(c net.Conn, pieces [][]byte) error {
	for i, piece := range pieces {
		if i > 0 {
			time.Sleep(jitter())
		}
		if _, err := c.Write(piece); err != nil {
			return err
		}
	}
	return nil
}

func concat(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// DesyncUpstreams are direct (system route, encrypted-DNS-resolved) paths that
// differ only in how the ClientHello is cut. They add no external process.
func DesyncUpstreams() []Upstream {
	v4 := []Upstream{
		{Name: "self: SNI split over 2 TCP segments", LocalDNS: true, Send: func(c net.Conn, f []byte) error {
			cuts := cutsInSNI(f, 1)
			if len(cuts) == 0 {
				_, err := c.Write(f)
				return err
			}
			return writeSegments(c, [][]byte{f[:cuts[0]], f[cuts[0]:]})
		}},
		{Name: "self: SNI split over 2 TLS records", LocalDNS: true, Send: func(c net.Conn, f []byte) error {
			recs, err := splitRecords(f, cutsInSNI(f, 1))
			if err != nil {
				_, werr := c.Write(f)
				return werr
			}
			_, err = c.Write(concat(recs))
			return err
		}},
		{Name: "self: TLS records and TCP segments", LocalDNS: true, Send: func(c net.Conn, f []byte) error {
			recs, err := splitRecords(f, cutsInSNI(f, 1))
			if err != nil {
				_, werr := c.Write(f)
				return werr
			}
			return writeSegments(c, recs)
		}},
	}
	// IPv6 twins of the record-splitting families: field reports show some
	// networks treat the two address families differently.
	out := append([]Upstream(nil), v4...)
	for i := range out {
		out[i].Rank = 3
	}
	for _, u := range v4[1:3] {
		u.Name = "self6: " + u.Name[len("self: "):]
		u.Network, u.Rank = "tcp6", 3
		out = append(out, u)
	}
	return out
}

// PlainUpstreams is the baseline: an ordinary connection with the ClientHello
// sent untouched. Some networks punish any cut ClientHello, even for sites
// that are not blocked, so the uncut path must always take part in the race.
func PlainUpstreams() []Upstream {
	return []Upstream{
		{Name: "plain: no cutting", LocalDNS: true, Rank: 0},
		{Name: "plain6: no cutting over IPv6", LocalDNS: true, Network: "tcp6", Rank: 1},
	}
}
