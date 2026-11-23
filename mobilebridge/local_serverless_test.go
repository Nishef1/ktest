package mobilebridge

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServerlessSOCKSReadyRequiresARealSOCKS5Handshake(t *testing.T) {
	for _, valid := range []bool{false, true} {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			var hello [3]byte
			if _, err := io.ReadFull(conn, hello[:]); err == nil {
				if valid {
					_, _ = conn.Write([]byte{5, 0})
				} else {
					_, _ = conn.Write([]byte{0, 0})
				}
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		got := serverlessSOCKSReady(ctx, listener.Addr().String())
		cancel()
		_ = listener.Close()
		<-finished
		if got != valid {
			t.Fatalf("valid=%v, SOCKS-ready=%v", valid, got)
		}
	}
}

func TestServerlessErrorTailIsBoundedAndRedactsPrivatePaths(t *testing.T) {
	var log serverlessErrorTail
	private, native := "/data/user/0/private", "/data/app/native"
	message := private + "/xray-profile.json " + native + "/libxray.so: bad config"
	_, _ = log.Write([]byte(message))
	got := log.summary(native, private)
	if strings.Contains(got, private) || strings.Contains(got, native) ||
		!strings.Contains(got, "[app-private]") || !strings.Contains(got, "[apk-native]") {
		t.Fatalf("unredacted native failure: %q", got)
	}
	_, _ = log.Write([]byte(strings.Repeat("x", 8192)))
	if got := log.summary(native, private); len(got) > 320 {
		t.Fatalf("unbounded native error: %d bytes", len(got))
	}
}
