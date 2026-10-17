package smartproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerHelloFramingRejectsTruncationAndPreservesFragmentedRecords(t *testing.T) {
	for n := 0; n < len(serverHello); n++ {
		if _, err := readServerHello(bytes.NewReader(serverHello[:n])); err == nil {
			t.Fatalf("accepted truncated response at %d", n)
		}
	}
	for split := 1; split < len(serverHello)-5; split++ {
		var wire []byte
		for _, part := range [][]byte{serverHello[5 : 5+split], serverHello[5+split:]} {
			header := []byte{22, 3, 3, 0, 0}
			binary.BigEndian.PutUint16(header[3:], uint16(len(part)))
			wire = append(wire, header...)
			wire = append(wire, part...)
		}
		got, err := readServerHello(bytes.NewReader(wire))
		if err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("fragment %d: %x, %v", split, got, err)
		}
	}
	for _, header := range [][]byte{{22, 3, 3, 0, 0}, {22, 3, 3, 0x40, 1}, {23, 3, 3, 0, 1}} {
		if _, err := readServerHello(bytes.NewReader(header)); err == nil {
			t.Fatalf("accepted invalid record %x", header)
		}
	}
}

func TestTLS12AndTLS13StillAuthenticateAndTransferThroughProxy(t *testing.T) {
	for _, tc := range []struct {
		version    uint16
		fragmented bool
	}{{tls.VersionTLS12, false}, {tls.VersionTLS12, true}, {tls.VersionTLS13, false}, {tls.VersionTLS13, true}} {
		version := tc.version
		label := tls.VersionName(version)
		if tc.fragmented {
			label += "/fragmented-client"
		}
		t.Run(label, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "usable application data") }))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			defer server.Close()
			_, addr := startProxy(t, PlainUpstreams())
			host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			raw, err := DialVia(ctx, addr, host, port, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			var wire net.Conn = raw
			if tc.fragmented {
				wire = &firstWriteConn{Conn: raw, send: func(c net.Conn, f []byte) error {
					parts, err := splitRecords(f, []int{6, len(f) - 8})
					if err != nil {
						return err
					}
					for _, part := range parts {
						if _, err := c.Write(part); err != nil {
							return err
						}
					}
					return nil
				}}
			}
			client := tls.Client(wire, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: version, MaxVersion: version})
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			if err := client.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			_, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(client)
			if err != nil || !bytes.Contains(body, []byte("usable application data")) {
				t.Fatalf("response %q, %v", body, err)
			}
		})
	}
}
