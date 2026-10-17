package smartproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func wireQuery() []byte {
	return append([]byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0},
		[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 65, 0, 1}...)
}

func TestWireDoHPreservesRecordTypesAndRejectsUntrustedTLS(t *testing.T) {
	query := wireQuery() // HTTPS type 65, not just an A/AAAA lookup.
	response := append([]byte(nil), query...)
	response[2], response[3] = 0x81, 0x83 // authenticated HTTPS NXDOMAIN
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || !bytes.Equal(body, query) {
			http.Error(w, "query changed", 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	exchange, closeIdle := NewWireDoH([]DoHEndpoint{{URL: server.URL}}, nil, pool)
	defer closeIdle()
	got, err := exchange(context.Background(), query)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("wire response changed: %x, %v", got, err)
	}
	untrusted, closeUntrusted := NewWireDoH([]DoHEndpoint{{URL: server.URL}}, nil, nil)
	defer closeUntrusted()
	if _, err := untrusted(context.Background(), query); err == nil {
		t.Fatal("untrusted DNS TLS accepted")
	}
}

func TestWireDoHRejectsMismatchRedirectsAndWrongMedia(t *testing.T) {
	for _, kind := range []string{"transaction", "question", "redirect", "media"} {
		t.Run(kind, func(t *testing.T) {
			query := wireQuery()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "redirect" {
					http.Redirect(w, r, "/elsewhere", 302)
					return
				}
				response := append([]byte(nil), query...)
				response[2] |= 0x80
				if kind == "transaction" {
					response[0]++
				}
				if kind == "question" {
					response[14]++
				}
				if kind != "media" {
					w.Header().Set("Content-Type", "application/dns-message")
				}
				_, _ = w.Write(response)
			}))
			defer server.Close()
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			exchange, closeIdle := NewWireDoH([]DoHEndpoint{{URL: server.URL}}, nil, pool)
			defer closeIdle()
			if _, err := exchange(context.Background(), query); err == nil {
				t.Fatal("unsafe DNS response accepted")
			}
		})
	}
}

func TestWireDoHDoesNotLetDeadFirstEndpointStarveFallback(t *testing.T) {
	query := wireQuery()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/dead" {
			<-r.Context().Done()
			return
		}
		response := append([]byte(nil), query...)
		response[2] |= 0x80
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	exchange, closeIdle := NewWireDoH([]DoHEndpoint{{URL: server.URL + "/dead"}, {URL: server.URL + "/good"}}, nil, pool)
	defer closeIdle()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exchange(ctx, query); err != nil {
		t.Fatal(err)
	}
}
