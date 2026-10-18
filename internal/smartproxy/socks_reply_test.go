package smartproxy

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestSOCKSConnectRejectsMalformedUpstreamReply(t *testing.T) {
	for _, bad := range []struct {
		name   string
		header [4]byte
	}{
		{"wrong SOCKS version", [4]byte{4, 0, 0, 1}},
		{"nonzero reserved byte", [4]byte{5, 0, 1, 1}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			c, server := net.Pipe()
			defer c.Close()
			defer server.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				var greeting [3]byte
				if _, err := io.ReadFull(server, greeting[:]); err != nil {
					return
				}
				_, _ = server.Write([]byte{5, 0})
				var connect [10]byte
				if _, err := io.ReadFull(server, connect[:]); err != nil {
					return
				}
				_, _ = server.Write(bad.header[:])
			}()
			if err := socksConnect(c, "198.51.100.10", "443"); err == nil || !strings.Contains(err.Error(), "invalid upstream SOCKS5") {
				t.Fatalf("malformed CONNECT reply accepted: %v", err)
			}
			<-done
		})
	}
}
