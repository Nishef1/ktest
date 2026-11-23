package connectiondns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestServerlessDNSFailsClosedWithoutLocalRoute(t *testing.T) {
	if _, _, err := MobileResolversWithCustom("serverless", "", ""); err == nil {
		t.Fatal("Serverless resolver leaked without a local proxy")
	}
	if _, _, err := MobilePacketDNSWithCustom("serverless", "", ""); err == nil {
		t.Fatal("Serverless packet DNS leaked without a local proxy")
	}
	if _, _, err := MobileResolversWithCustom("serverless", "127.0.0.1:10808", "8.8.8.8"); err == nil {
		t.Fatal("Serverless resolver accepted custom plaintext DNS")
	}
	if _, _, err := MobilePacketDNSWithCustom("serverless", "127.0.0.1:10808", "8.8.8.8"); err == nil {
		t.Fatal("Serverless packet DNS accepted custom plaintext DNS")
	}
}

// A local fake Xray SOCKS peer must receive the raw DNS question on port 53;
// a separate HTTPS DoH request would fail this test.
func TestServerlessPacketDNSUsesNativeSOCKS53(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var hello [3]byte
		if _, err := io.ReadFull(conn, hello[:]); err != nil || hello != [3]byte{5, 1, 0} {
			return
		}
		_, _ = conn.Write([]byte{5, 0})
		var request [10]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil ||
			request != [10]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 53} {
			return
		}
		_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, query); err != nil || len(query) < 17 {
			return
		}
		query[2] |= 0x80
		_, _ = conn.Write(append(size[:], query...))
	}()
	exchange, closeDNS, err := MobilePacketDNS("serverless", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDNS()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := exchange(ctx, testWireDNSQuery())
	if err != nil || len(response) < 17 || response[2]&0x80 == 0 {
		t.Fatalf("native DNS exchange failed: %x %v", response, err)
	}
}
