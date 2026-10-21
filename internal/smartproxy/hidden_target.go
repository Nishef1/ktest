package smartproxy

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// An Encrypted Client Hello hides the real server name: the outer SNI is only
// the provider's public name. When the SOCKS request carries just an address
// (Android HEV), neither the request nor the ClientHello says whether the
// connection belongs to a protected (ExitOnly) service. The answer comes from
// names this proxy itself resolved to that address (a shared CDN address is
// protected if any protected name used it), and an address with no known name
// fails closed onto the foreign exit rather than a local or ISP route.

const (
	hiddenNameTTL    = 10 * time.Minute
	hiddenNameLimit  = 4096
	hiddenNamesPerIP = 8
)

type resolvedNames struct {
	mu     sync.Mutex
	byIP   map[string]resolvedEntry
	hidden map[string]time.Time // addresses currently routed as protected
}

type resolvedEntry struct {
	names []string
	until time.Time
}

func (r *resolvedNames) learn(name string, ips []net.IP, now time.Time) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(ips) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byIP == nil {
		r.byIP = map[string]resolvedEntry{}
	}
	if len(r.byIP) >= hiddenNameLimit {
		for ip, e := range r.byIP {
			if now.After(e.until) {
				delete(r.byIP, ip)
			}
		}
		// Forgetting a mapping is safe: an unknown address fails closed.
		for ip := range r.byIP {
			if len(r.byIP) < hiddenNameLimit/2 {
				break
			}
			delete(r.byIP, ip)
		}
	}
	for _, ip := range ips {
		key := ip.String()
		e := r.byIP[key]
		if now.After(e.until) {
			e.names = nil
		}
		known := false
		for _, n := range e.names {
			known = known || n == name
		}
		if !known {
			if len(e.names) >= hiddenNamesPerIP {
				e.names = e.names[1:]
			}
			e.names = append(e.names, name)
		}
		e.until = now.Add(hiddenNameTTL)
		r.byIP[key] = e
	}
}

// names returns the live names resolved to ip.
func (r *resolvedNames) names(ip string, now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byIP[ip]
	if !ok || now.After(e.until) {
		return nil
	}
	return append([]string(nil), e.names...)
}

func (r *resolvedNames) markHidden(ip string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hidden == nil {
		r.hidden = map[string]time.Time{}
	}
	if len(r.hidden) >= hiddenNameLimit {
		for k, until := range r.hidden {
			if now.After(until) {
				delete(r.hidden, k)
			}
		}
	}
	r.hidden[ip] = now.Add(hiddenNameTTL)
}

func (r *resolvedNames) isHidden(ip string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.hidden[ip]
	return ok && now.Before(until)
}

// exitOnly is the protected-destination test every routing decision uses:
// the configured names, plus addresses whose hidden (ECH) target may be one.
func (p *Proxy) exitOnly(host string) bool {
	if p.cfg.ExitOnly == nil {
		return false
	}
	if p.cfg.ExitOnly(host) {
		return true
	}
	return net.ParseIP(host) != nil && p.resolved.isHidden(host, time.Now())
}

// hiddenTargetProtected decides an address-only ECH connection. Known names
// decide it (any protected name wins); with none, it is protected only where
// a foreign exit may carry it, since a local-only mode would just break it.
func (p *Proxy) hiddenTargetProtected(ip string) bool {
	if p.cfg.ExitOnly == nil {
		return false
	}
	names := p.resolved.names(ip, time.Now())
	for _, n := range names {
		if p.cfg.ExitOnly(n) {
			return true
		}
	}
	return len(names) == 0 && !p.cfg.LocalOnly && !p.cfg.RejectExits
}

// learnDNS records the A/AAAA answers of a DNS response under its question.
func (p *Proxy) learnDNS(response []byte) {
	if p.cfg.ExitOnly == nil {
		return
	}
	if name, ips := dnsAddressAnswers(response); len(ips) > 0 {
		p.resolved.learn(name, ips, time.Now())
	}
}

// dnsAddressAnswers parses a one-question response; anything malformed yields
// nothing, which leaves the address unknown (and so protected).
func dnsAddressAnswers(m []byte) (string, []net.IP) {
	if len(m) < 12 || m[2]&0x80 == 0 || m[3]&0x0f != 0 {
		return "", nil
	}
	end, err := dnsQuestionEnd(m)
	if err != nil {
		return "", nil
	}
	var labels []string
	for o := 12; m[o] != 0; o += int(m[o]) + 1 {
		labels = append(labels, string(m[o+1:o+1+int(m[o])]))
	}
	answers := int(binary.BigEndian.Uint16(m[6:8]))
	var ips []net.IP
	o := end
	for i := 0; i < answers; i++ {
		// Owner name: labels, possibly ending in a compression pointer.
		for {
			if o >= len(m) {
				return "", nil
			}
			l := int(m[o])
			if l&0xc0 == 0xc0 {
				o += 2
				break
			}
			if l&0xc0 != 0 {
				return "", nil
			}
			o += 1 + l
			if l == 0 {
				break
			}
		}
		if o+10 > len(m) {
			return "", nil
		}
		typ := binary.BigEndian.Uint16(m[o : o+2])
		class := binary.BigEndian.Uint16(m[o+2 : o+4])
		size := int(binary.BigEndian.Uint16(m[o+8 : o+10]))
		o += 10
		if o+size > len(m) {
			return "", nil
		}
		if class == 1 && ((typ == 1 && size == 4) || (typ == 28 && size == 16)) {
			ips = append(ips, net.IP(append([]byte(nil), m[o:o+size]...)))
		}
		o += size
	}
	return strings.Join(labels, "."), ips
}
