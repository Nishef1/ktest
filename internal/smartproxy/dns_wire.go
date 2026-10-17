package smartproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"
)

// NewWireDoH preserves complete RFC 8484 DNS messages, including AAAA, HTTPS,
// DNSSEC and negative answers. Unlike an A/AAAA-only resolver this can serve
// the DNS traffic from a TUN. No plaintext DNS fallback is performed.
// Call closeIdle when the owning connection session ends.
func NewWireDoH(endpoints []DoHEndpoint, dial DialFunc, roots *x509.CertPool) (
	exchange func(context.Context, []byte) ([]byte, error), closeIdle func(),
) {
	clients := make([]*http.Client, len(endpoints))
	for i, ep := range endpoints {
		clients[i] = newDoHClient(ep, dial, roots)
	}
	closeIdle = func() {
		for _, client := range clients {
			client.CloseIdleConnections()
		}
	}
	exchange = func(ctx context.Context, query []byte) ([]byte, error) {
		questionEnd, err := dnsQuestionEnd(query)
		if err != nil || query[2]&0x80 != 0 || query[2]&0x78 != 0 {
			return nil, errors.New("invalid DNS query")
		}
		if len(endpoints) == 0 {
			return nil, errors.New("no wire DoH endpoint configured")
		}
		working, cancel := context.WithCancel(ctx)
		defer cancel()
		queryOne := func(i int, ep DoHEndpoint) ([]byte, error) {
			u, err := url.Parse(ep.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				return nil, errors.New("wire DoH requires HTTPS without credentials")
			}
			req, err := http.NewRequestWithContext(working, http.MethodPost, ep.URL, bytes.NewReader(query))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/dns-message")
			req.Header.Set("Accept", "application/dns-message")
			resp, err := clients[i].Do(req)
			if err != nil {
				return nil, err
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65536))
			_ = resp.Body.Close()
			media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
			if readErr != nil || resp.StatusCode != http.StatusOK || media != "application/dns-message" {
				return nil, fmt.Errorf("wire DoH rejected response (HTTP %d, type %q)", resp.StatusCode, media)
			}
			end, err := dnsQuestionEnd(body)
			if err != nil || len(body) > 65535 || body[2]&0x80 == 0 || body[2]&0x78 != 0 ||
				!bytes.Equal(query[:2], body[:2]) || end != questionEnd || !bytes.Equal(query[12:questionEnd], body[12:end]) {
				return nil, errors.New("wire DoH returned a mismatched DNS response")
			}
			return body, nil
		}
		type result struct {
			body []byte
			err  error
		}
		results := make(chan result, len(endpoints))
		for i, ep := range endpoints {
			go func() {
				timer := time.NewTimer(min(time.Duration(i)*150*time.Millisecond, 400*time.Millisecond))
				defer timer.Stop()
				select {
				case <-working.Done():
					return
				case <-timer.C:
				}
				body, err := queryOne(i, ep)
				results <- result{body, err}
			}()
		}
		var last error
		for range endpoints {
			select {
			case <-working.Done():
				return nil, working.Err()
			case found := <-results:
				if found.err == nil {
					return found.body, nil
				}
				last = found.err
			}
		}
		return nil, fmt.Errorf("encrypted packet DNS unavailable: %w; resolver IP, TLS/SNI or protocol may be blocked; no plaintext fallback", last)
	}
	return exchange, closeIdle
}

func (p *Proxy) serveDNSStream(ctx context.Context, client net.Conn) {
	for {
		_ = client.SetDeadline(time.Now().Add(8 * time.Second))
		var size [2]byte
		if _, err := io.ReadFull(client, size[:]); err != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(client, query); err != nil {
			return
		}
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		response, err := p.cfg.ExchangeDNS(dctx, query)
		cancel()
		if err != nil || len(response) > 65535 {
			if err != nil && ctx.Err() == nil {
				p.emit(ctx, Event{Host: "DNS", Port: "53", Site: "DNS", Err: err.Error()})
			}
			return
		}
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(response)))
		if _, err := client.Write(append(frame, response...)); err != nil {
			return
		}
	}
}

// A single ordinary uncompressed DNS question is required. Resource records
// (including OPT) are preserved; malformed or compressed questions fail closed.
func dnsQuestionEnd(message []byte) (int, error) {
	if len(message) < 17 || len(message) > 65535 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return 0, errors.New("DNS must contain one question")
	}
	offset := 12
	for {
		if offset >= len(message) || offset-12 > 253 {
			return 0, errors.New("invalid DNS name")
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(message) {
			return 0, errors.New("invalid DNS label")
		}
		offset += length
	}
	if offset+4 > len(message) {
		return 0, errors.New("truncated DNS question")
	}
	return offset + 4, nil
}
