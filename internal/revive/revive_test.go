package revive

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

const sample = `[
{"remarks":"Serverless-v52-fragA","inbounds":[{"protocol":"mixed","port":10808}],"outbounds":[{"protocol":"freedom"}]},
{"remarks":"Serverless-v52-fragB","inbounds":[{"protocol":"mixed","port":9999,"listen":"0.0.0.0"}],"outbounds":[{"protocol":"freedom"}]}
]`

func TestSelectBOfflineAndLoopback(t *testing.T) {
	b, err := SelectProfile([]byte(sample), "B")
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Remarks  string `json:"remarks"`
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root.Remarks != "Serverless-v52-fragB" || len(root.Inbounds) != 1 ||
		root.Inbounds[0].Listen != "127.0.0.1" || root.Inbounds[0].Port != 10808 {
		t.Fatalf("unsafe or wrong profile: %+v", root)
	}
}

func TestRejectWrongProfileAndUnexpectedInbound(t *testing.T) {
	if _, err := SelectProfile([]byte(sample), "C"); err == nil {
		t.Fatal("unknown variant accepted")
	}
	if _, err := SelectProfile([]byte(`{"remarks":"fragB","inbounds":[{"protocol":"socks"}]}`), "B"); err == nil {
		t.Fatal("unexpected inbound accepted")
	}
	if _, err := SelectProfile([]byte(`{"remarks":"fragB","inbounds":[{"protocol":"mixed"},{"protocol":"mixed"}]}`), "B"); err == nil {
		t.Fatal("multiple listeners accepted")
	}
	if _, err := SelectProfile([]byte(`// comment
{"remarks":"fragB"}`), "B"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestVersionGate(t *testing.T) {
	if err := CheckVersion("Xray 26.10.1 (Xray, Penetrates Everything.)"); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion("Xray 26.6.27"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Xray 26.6.26", "Xray 25.10.10", "something else"} {
		if err := CheckVersion(s); err == nil {
			t.Fatalf("old or invalid version accepted: %s", strings.TrimSpace(s))
		}
	}
}

func TestLocalTCPProfilesCannotImportRemoteRoutesOrRequireTLS(t *testing.T) {
	for _, variant := range []string{"A", "B"} {
		data, err := LocalTCPProfile(11808, variant)
		if err != nil {
			t.Fatal(err)
		}
		var root struct {
			Inbounds []struct {
				Listen   string `json:"listen"`
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
				Settings struct {
					UDP bool `json:"udp"`
				} `json:"settings"`
			} `json:"inbounds"`
			Outbounds []struct {
				Protocol       string                     `json:"protocol"`
				Settings       map[string]json.RawMessage `json:"settings"`
				ProxySettings  json.RawMessage            `json:"proxySettings"`
				StreamSettings json.RawMessage            `json:"streamSettings"`
			} `json:"outbounds"`
			Routing json.RawMessage `json:"routing"`
			DNS     json.RawMessage `json:"dns"`
		}
		if err := json.Unmarshal(data, &root); err != nil {
			t.Fatal(err)
		}
		if len(root.Inbounds) != 1 || root.Inbounds[0].Listen != "127.0.0.1" || root.Inbounds[0].Port != 11808 || root.Inbounds[0].Protocol != "socks" || root.Inbounds[0].Settings.UDP {
			t.Fatalf("unsafe local inbound: %s", data)
		}
		if len(root.Outbounds) != 1 || root.Outbounds[0].Protocol != "freedom" || len(root.Outbounds[0].Settings) != 1 || root.Outbounds[0].Settings["fragment"] == nil || root.Outbounds[0].ProxySettings != nil || root.Outbounds[0].StreamSettings != nil || root.Routing != nil || root.DNS != nil {
			t.Fatalf("local TCP profile can redirect traffic or bypass fragmentation: %s", data)
		}
		var fragment struct {
			Packets string `json:"packets"`
		}
		if err := json.Unmarshal(root.Outbounds[0].Settings["fragment"], &fragment); err != nil {
			t.Fatal(err)
		}
		if fragment.Packets == "" || fragment.Packets == "tlshello" {
			t.Fatalf("raw OpenVPN needs TCP stream slicing, got %q", fragment.Packets)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := LocalTCPProfile(port, "A"); err == nil {
			t.Fatalf("accepted port %d", port)
		}
	}
	if _, err := LocalTCPProfile(11808, "imported"); err == nil {
		t.Fatal("accepted unknown fragment profile")
	}
	if err := RunLocalTCP(context.Background(), Config{XrayBinary: "unused", Profile: "untrusted.json", Variant: "A"}); err == nil {
		t.Fatal("local launcher accepted an imported profile")
	}
}

// Opt in with an installed official core; normal Go CI does not download one.
func TestLocalTCPNativeXrayPreservesOpaqueStream(t *testing.T) {
	bin := os.Getenv("KTEST_XRAY_TEST_BINARY")
	if bin == "" {
		t.Skip("set KTEST_XRAY_TEST_BINARY to test the installed Xray executable")
	}
	for _, variant := range []string{"A", "B"} {
		t.Run(variant, func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				c, err := echo.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := reserve.Addr().(*net.TCPAddr)
			_ = reserve.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			done := make(chan struct{})
			var runErr error
			go func() {
				runErr = RunLocalTCP(ctx, Config{XrayBinary: bin, Variant: variant, Port: addr.Port, Output: io.Discard})
				close(done)
			}()
			defer func() {
				cancel()
				<-done
				if runErr != nil {
					t.Error(runErr)
				}
			}()
			var c net.Conn
			for c == nil {
				c, _ = net.DialTimeout("tcp", addr.String(), 100*time.Millisecond)
				if c != nil {
					break
				}
				select {
				case <-done:
					t.Fatalf("core exited before accepting SOCKS: %v", runErr)
				case <-ctx.Done():
					t.Fatal("core did not become ready")
				case <-time.After(50 * time.Millisecond):
				}
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			_, _ = c.Write([]byte{5, 1, 0})
			greeting := make([]byte, 2)
			if _, err := io.ReadFull(c, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
				t.Fatalf("SOCKS greeting %x: %v", greeting, err)
			}
			request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
			binary.BigEndian.PutUint16(request[8:], uint16(echo.Addr().(*net.TCPAddr).Port))
			_, _ = c.Write(request)
			reply := make([]byte, 10)
			if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
				t.Fatalf("SOCKS CONNECT %x: %v", reply, err)
			}
			for _, payload := range [][]byte{bytes.Repeat([]byte{0, 0x0e, 0x38, 0xff, 0x80, 1, 2, 3}, 32), []byte("second opaque frame\x00\xff")} {
				if _, err := c.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("raw TCP bytes changed: %x, %v", got, err)
				}
			}
		})
	}
}
