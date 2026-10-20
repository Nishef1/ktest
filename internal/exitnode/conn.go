package exitnode

import (
	"net"
	"sync"
	"time"
)

// fragmentConn is Xray's finalmask/fragment client conn.
type fragmentConn struct {
	net.Conn
	cfg   Fragment
	count uint64
}

func (c *fragmentConn) lengthFor(seg int) Range {
	if seg >= len(c.cfg.Lengths) {
		seg = len(c.cfg.Lengths) - 1
	}
	return c.cfg.Lengths[seg]
}

func (c *fragmentConn) delayFor(seg int) Range {
	if seg >= len(c.cfg.Delays) {
		seg = len(c.cfg.Delays) - 1
	}
	return c.cfg.Delays[seg]
}

func sleepBetween(r Range) {
	if r.Max > 0 {
		time.Sleep(time.Duration(randBetween(r.Min, r.Max)) * time.Millisecond)
	}
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	c.count++
	if c.cfg.PacketsFrom == 0 && c.cfg.PacketsTo == 1 {
		return c.writeTLSHello(p)
	}
	if c.cfg.PacketsFrom != 0 && (c.count < uint64(c.cfg.PacketsFrom) || c.count > uint64(c.cfg.PacketsTo)) {
		return c.Conn.Write(p)
	}
	maxSplit := randBetween(c.cfg.MaxSplit.Min, c.cfg.MaxSplit.Max)
	var split int64
	for from := 0; ; {
		l := c.lengthFor(int(split))
		to := from + int(randBetween(l.Min, l.Max))
		if to > len(p) || (maxSplit > 0 && split+1 >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		sleepBetween(c.delayFor(int(split)))
		split++
		if from >= len(p) {
			return from, nil
		}
	}
}

// writeTLSHello splits the first TLS handshake record into several records.
// With delays exactly ["0"] the records are merged into one write.
func (c *fragmentConn) writeTLSHello(p []byte) (int, error) {
	if c.count != 1 || len(p) <= 5 || p[0] != 22 {
		return c.Conn.Write(p)
	}
	recordLen := 5 + (int(p[3])<<8 | int(p[4]))
	if len(p) < recordLen {
		return c.Conn.Write(p)
	}
	data := p[5:recordLen]
	merge := len(c.cfg.Delays) == 1 && c.cfg.Delays[0].Max == 0
	maxSplit := randBetween(c.cfg.MaxSplit.Min, c.cfg.MaxSplit.Max)
	var hello []byte
	var split int64
	for from := 0; ; {
		l := c.lengthFor(int(split))
		to := from + int(randBetween(l.Min, l.Max))
		if to > len(data) || (maxSplit > 0 && split+1 >= maxSplit) {
			to = len(data)
		}
		n := to - from
		record := make([]byte, 5+n)
		copy(record[:3], p)
		record[3], record[4] = byte(n>>8), byte(n)
		copy(record[5:], data[from:to])
		from = to
		if merge {
			hello = append(hello, record...)
		} else {
			_, err := c.Conn.Write(record)
			sleepBetween(c.delayFor(int(split)))
			if err != nil {
				return 0, err
			}
		}
		split++
		if from == len(data) {
			break
		}
	}
	if len(hello) > 0 {
		if _, err := c.Conn.Write(hello); err != nil {
			return 0, err
		}
	}
	if len(p) > recordLen {
		n, err := c.Conn.Write(p[recordLen:])
		if err != nil {
			return recordLen + n, err
		}
	}
	return len(p), nil
}

// wrapTCP stacks the masks the way Xray does: the first wraps the socket.
func wrapTCP(conn net.Conn, masks []Fragment) net.Conn {
	for _, m := range masks {
		conn = &fragmentConn{Conn: conn, cfg: m}
	}
	return conn
}

// noiseConn is Xray's finalmask/noise client conn: before the first datagram
// to an address, and again once it was idle longer than Reset seconds, it
// sends the configured noise datagrams to that address.
type noiseConn struct {
	net.PacketConn
	cfg  Noise
	mu   sync.Mutex
	next map[string]time.Time
}

func (c *noiseConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := addr.String()
	t := c.next[key]
	if t.IsZero() || (c.cfg.Reset.Max > 0 && time.Now().After(t)) {
		for _, item := range c.cfg.Items {
			_, _ = c.PacketConn.WriteTo(item.build(), addr)
			sleepBetween(item.Delay)
		}
	}
	c.next[key] = time.Now().Add(time.Duration(randBetween(c.cfg.Reset.Min, c.cfg.Reset.Max)) * time.Second)
	return c.PacketConn.WriteTo(p, addr)
}

func (it NoiseItem) build() []byte {
	if it.Rand.Max <= 0 {
		return it.Packet
	}
	b := make([]byte, randBetween(it.Rand.Min, it.Rand.Max))
	for i := range b {
		b[i] = byte(randBetween(it.RandRange.Min, it.RandRange.Max+1)) // Xray's range is inclusive
	}
	return b
}

func wrapUDP(conn net.PacketConn, masks []Noise) net.PacketConn {
	for _, m := range masks {
		conn = &noiseConn{PacketConn: conn, cfg: m, next: map[string]time.Time{}}
	}
	return conn
}
