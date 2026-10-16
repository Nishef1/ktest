package front

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
)

// Encrypted Client Hello without DNS.
//
// Normally a client learns a site's ECH configuration from a DNS HTTPS record,
// which is exactly what a poisoned or filtered network denies. But a server
// that cannot decrypt an ECH extension answers with retry_configs, which the
// client verifies against the configuration's public name. So ktest sends a
// well-formed configuration that nobody holds the key to, takes the fresh
// configuration from the rejection, and handshakes again with it. Cloudflare's
// public name is cloudflare-ech.com, shared by every site behind it, so one
// bootstrap serves all of them and the wire only ever shows that name.

// dummyECHConfig builds an ECHConfigList with one X25519/HKDF-SHA256/AES-128-GCM
// entry for public, whose private key does not exist.
func dummyECHConfig(public string) []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	id := make([]byte, 1)
	_, _ = rand.Read(id)
	var c []byte
	c = append(c, id[0])
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(key)))
	c = append(c, key...)
	c = binary.BigEndian.AppendUint16(c, 4) // one cipher suite: 4 bytes
	c = binary.BigEndian.AppendUint16(c, 1) // HKDF-SHA256
	c = binary.BigEndian.AppendUint16(c, 1) // AES-128-GCM
	c = append(c, 64)                       // maximum_name_length
	c = append(c, byte(len(public)))
	c = append(c, public...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	var cfg []byte
	cfg = binary.BigEndian.AppendUint16(cfg, 0xfe0d)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(c)))
	cfg = append(cfg, c...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(cfg)))
	return append(list, cfg...)
}

func (f *Fronter) echConfig(public string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ech[public]
}

func (f *Fronter) storeECH(public string, list []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ech == nil {
		f.ech = map[string][]byte{}
	}
	f.ech[public] = list
}

// tryECH reaches name through an ECH service. connect opens a fresh TCP
// connection to an edge address each time it is called.
func (f *Fronter) tryECH(ctx context.Context, fr Front, name string, protos []string, connect func() (net.Conn, error)) (net.Conn, error) {
	list := f.echConfig(fr.ECH)
	if list == nil {
		list = dummyECHConfig(fr.ECH)
	}
	for round := 0; ; round++ {
		raw, err := connect()
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		c := tls.Client(raw, &tls.Config{
			ServerName:                     name,
			EncryptedClientHelloConfigList: list,
			MinVersion:                     tls.VersionTLS13,
			NextProtos:                     protos,
			RootCAs:                        f.cfg.Roots,
		})
		err = c.HandshakeContext(ctx)
		if !stop() {
			_ = raw.Close()
			return nil, context.Canceled
		}
		if err == nil {
			st := c.ConnectionState()
			switch {
			case !st.ECHAccepted:
				_ = raw.Close()
				return nil, errors.New("the edge did not accept Encrypted Client Hello")
			case len(protos) == 1 && st.NegotiatedProtocol != protos[0]:
				_ = raw.Close()
				return nil, fmt.Errorf("edge chose %q instead of %q", st.NegotiatedProtocol, protos[0])
			}
			return c, nil
		}
		_ = raw.Close()
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) && len(rej.RetryConfigList) > 0 && round < 2 {
			list = rej.RetryConfigList
			f.storeECH(fr.ECH, list)
			continue
		}
		return nil, fmt.Errorf("handshake: %w", err)
	}
}

// shuffled returns a copy of s in random order, so that one dead hint does not
// stay first for every connection.
func shuffled(s []string) []string {
	out := append([]string(nil), s...)
	mrand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
