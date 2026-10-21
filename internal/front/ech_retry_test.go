package front

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// echEdge is a TLS server holding a real ECH key: it rejects any other
// configuration with retry_configs, as a Cloudflare edge does.
func echEdge(t *testing.T, public, inner string) (addr string, roots *testPublicCA, list []byte, accepted *atomic.Int32) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list = echConfigList(public, key.PublicKey().Bytes())
	ca := &testPublicCA{}
	ca.init(t)
	cert := ca.issue(t, public, inner)
	accepted = &atomic.Int32{}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config: list[2:], PrivateKey: key.Bytes(), SendAsRetry: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() == nil && tc.ConnectionState().ECHAccepted {
					accepted.Add(1)
				}
			}()
		}
	}()
	return ln.Addr().String(), ca, list, accepted
}

// The whole bootstrap: a dummy configuration is rejected, the retry list is
// used once, the edge accepts ECH, and only then is the list cached.
func TestECHRetryThenAcceptanceCachesOnlyTheAcceptedList(t *testing.T) {
	addr, ca, list, accepted := echEdge(t, CloudflareECH, "x.com")
	f := New(Config{Roots: ca.pool})
	connect := func() (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
	}
	c, err := f.tryECH(context.Background(), Front{ECH: CloudflareECH}, "x.com", []string{"http/1.1"}, connect)
	if err != nil {
		t.Fatalf("retry did not reach an accepted ECH handshake: %v", err)
	}
	if !c.(*tls.Conn).ConnectionState().ECHAccepted {
		t.Fatal("connection returned without ECH")
	}
	c.Close()
	if got := f.echConfig(CloudflareECH); !bytes.Equal(got, list) {
		t.Fatal("accepted retry list was not cached")
	}
	// The cached list is used directly: no second rejection round.
	c, err = f.tryECH(context.Background(), Front{ECH: CloudflareECH}, "x.com", []string{"http/1.1"}, connect)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for accepted.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if accepted.Load() != 2 {
		t.Fatalf("edge accepted ECH %d times, want 2", accepted.Load())
	}
	// An expired entry is relearned rather than reused indefinitely.
	f.mu.Lock()
	e := f.ech[CloudflareECH]
	e.accepted = time.Now().Add(-2 * echTTL)
	f.ech[CloudflareECH] = e
	f.mu.Unlock()
	if f.echConfig(CloudflareECH) != nil {
		t.Fatal("expired ECH configuration was still served")
	}
}

// A rotated key: the cached list is rejected, the new retry list is accepted
// and replaces it.
func TestECHRotatedKeyReplacesCacheAfterAcceptance(t *testing.T) {
	addr, ca, list, _ := echEdge(t, CloudflareECH, "x.com")
	f := New(Config{Roots: ca.pool})
	stale := dummyECHConfig(CloudflareECH)
	f.storeECH(CloudflareECH, stale)
	connect := func() (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", addr)
	}
	c, err := f.tryECH(context.Background(), Front{ECH: CloudflareECH}, "x.com", []string{"http/1.1"}, connect)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := f.echConfig(CloudflareECH); !bytes.Equal(got, list) {
		t.Fatal("rotated key did not replace the stale cached list")
	}
}

// A blocked bootstrap (cloudflare-ech.com refused) is remembered so automatic
// callers do not repeat the handshakes on every attempt; a success is shared.
func TestSharedECHBootstrapRemembersDefiniteResults(t *testing.T) {
	t.Cleanup(func() {
		echBootstrap.Lock()
		echBootstrap.config, echBootstrap.edge, echBootstrap.err, echBootstrap.at = nil, "", nil, time.Time{}
		echBootstrap.Unlock()
	})
	echBootstrap.Lock()
	echBootstrap.err, echBootstrap.at = errors.New("connection reset"), time.Now()
	echBootstrap.Unlock()
	began := time.Now()
	if _, _, err := SharedCloudflareECH(context.Background()); err == nil || time.Since(began) > time.Second {
		t.Fatalf("recent failure not reused: %v after %s", err, time.Since(began))
	}
	echBootstrap.Lock()
	echBootstrap.config, echBootstrap.edge, echBootstrap.err = []byte{1, 2}, "104.16.0.1", nil
	echBootstrap.Unlock()
	if cfg, edge, err := SharedCloudflareECH(context.Background()); err != nil || edge != "104.16.0.1" || len(cfg) != 2 {
		t.Fatalf("shared success = %v %q %v", cfg, edge, err)
	}
}

// A blackholed bootstrap outlasts a short caller; its result must still be
// stored so the next attempt does not wait again.
func TestSharedECHBootstrapStoresResultAfterCallerGivesUp(t *testing.T) {
	release := make(chan struct{})
	echBootstrap.Lock()
	echBootstrap.config, echBootstrap.err, echBootstrap.at = nil, nil, time.Time{}
	echBootstrap.fetch = func(context.Context) ([]byte, string, error) {
		<-release
		return nil, "", errors.New("i/o timeout")
	}
	echBootstrap.Unlock()
	t.Cleanup(func() {
		echBootstrap.Lock()
		echBootstrap.config, echBootstrap.edge, echBootstrap.err, echBootstrap.at, echBootstrap.fetch = nil, "", nil, time.Time{}, nil
		echBootstrap.Unlock()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := SharedCloudflareECH(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("short caller = %v", err)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		echBootstrap.Lock()
		stored := echBootstrap.err != nil
		echBootstrap.Unlock()
		if stored {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background result was never stored")
		}
		time.Sleep(10 * time.Millisecond)
	}
	began := time.Now()
	if _, _, err := SharedCloudflareECH(context.Background()); err == nil || time.Since(began) > 100*time.Millisecond {
		t.Fatalf("stored failure not reused: %v after %s", err, time.Since(began))
	}
}
