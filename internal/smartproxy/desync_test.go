package smartproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// capturedClientHello returns the first flight a real Go TLS client sends.
func capturedClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = c.Handshake() // fails once b is closed; only the first flight matters
	}()
	buf := make([]byte, 16*1024)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	return buf[:n]
}

func TestSNIRangeFindsTheHostName(t *testing.T) {
	f := capturedClientHello(t, "www.youtube.com")
	start, end, ok := sniRange(f)
	if !ok || string(f[start:end]) != "www.youtube.com" {
		t.Fatalf("range %d-%d ok=%v", start, end, ok)
	}
	if _, _, ok := sniRange([]byte("GET / HTTP/1.1\r\n\r\n")); ok {
		t.Fatal("non-TLS data parsed")
	}
}

func TestSplitRecordsPreserveThePayload(t *testing.T) {
	f := capturedClientHello(t, "www.youtube.com")
	cuts := cutsInSNI(f, 2)
	start, end, _ := sniRange(f)
	if len(cuts) != 2 || cuts[0] <= start || cuts[1] >= end || cuts[0] >= cuts[1] {
		t.Fatalf("cuts %v not strictly inside SNI %d-%d", cuts, start, end)
	}
	recs, err := splitRecords(f, cuts)
	if err != nil || len(recs) != 3 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	var payload []byte
	for _, r := range recs {
		if r[0] != 0x16 || int(r[3])<<8|int(r[4]) != len(r)-5 {
			t.Fatalf("bad record header % x", r[:5])
		}
		payload = append(payload, r[5:]...)
	}
	if !bytes.Equal(payload, f[5:]) {
		t.Fatal("payload changed by splitting")
	}
}

// A real TLS server must complete the handshake for every family: this is
// what proves the cut flights are valid TLS, not just well-formed bytes.
func TestEveryDesyncFamilyCompletesARealHandshake(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	for _, u := range DesyncUpstreams() {
		u := u
		t.Run(u.Name, func(t *testing.T) {
			raw, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			c := tls.Client(&firstWriteConn{Conn: raw, send: u.Send}, &tls.Config{ServerName: "example.com", RootCAs: pool})
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			if err := c.Handshake(); err != nil {
				t.Fatalf("handshake failed: %v", err)
			}
		})
	}
}

// firstWriteConn routes the first Write (the ClientHello) through the family.
type firstWriteConn struct {
	net.Conn
	send func(net.Conn, []byte) error
	done bool
}

func (c *firstWriteConn) Write(p []byte) (int, error) {
	if !c.done {
		c.done = true
		if err := c.send(c.Conn, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}
