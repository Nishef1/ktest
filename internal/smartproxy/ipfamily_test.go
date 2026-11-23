package smartproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSingleFamilySendsNumericDestinationToSOCKS(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			seen := make(chan string, 1)
			go func() {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				host, _, err := socksRequest(conn)
				if err == nil {
					seen <- host
					_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
					_, _ = io.Copy(io.Discard, conn)
				}
			}()
			v4 := func(context.Context, string) ([]string, error) { return []string{"1.1.1.1"}, nil }
			v6 := func(context.Context, string) ([]string, error) { return []string{"1.1.1.1", "2606:4700::1111"}, nil }
			p, err := New(Config{DestinationFamily: family, Resolve: v4, Resolve6: v6,
				Upstreams: []Upstream{{Name: "native", Addr: l.Addr().String()}}, ConnectTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := p.dial(ctx, p.ups[0], "example.com", "443")
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			want, wrong := "1.1.1.1", "2606:4700::1111"
			if family == "ipv6" {
				want, wrong = wrong, want
			}
			select {
			case got := <-seen:
				if got != want {
					t.Fatalf("SOCKS received %s, want %s", got, want)
				}
			case <-ctx.Done():
				t.Fatal("SOCKS destination was not sent")
			}
			if _, err := p.dial(ctx, p.ups[0], wrong, "443"); err == nil {
				t.Fatal("wrong-family literal accepted")
			}
		})
	}
}

func TestStrictFamilyNeverFallsBackToOppositeDNS(t *testing.T) {
	wrong := func(context.Context, string) ([]string, error) { return []string{"1.1.1.1"}, nil }
	p, err := New(Config{DestinationFamily: "ipv6", Resolve6: wrong,
		Upstreams: []Upstream{{Name: "direct"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.familyTarget(context.Background(), "example.com"); err == nil {
		t.Fatal("wrong-family DNS address accepted")
	}
	if _, err := New(Config{DestinationFamily: "ipv6", Upstreams: []Upstream{{Name: "direct"}}}); err == nil {
		t.Fatal("strict family without trusted resolver accepted")
	}
}

func TestSingleFamilyDNSReturnsNODATAForDisallowedType(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		query := wireQuery()
		qtype := uint16(28)
		if family == "ipv6" {
			qtype = 1
		}
		binary.BigEndian.PutUint16(query[len(query)-4:len(query)-2], qtype)
		exchange := familyDNS(family, func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("must not contact external DNS")
		})
		response, err := exchange(context.Background(), query)
		if err != nil || response[2]&0x80 == 0 || response[3]&15 != 0 ||
			binary.BigEndian.Uint16(response[6:8]) != 0 {
			t.Fatalf("%s: expected NODATA, got %x (%v)", family, response, err)
		}
	}
}

func TestSingleFamilyRequiresFreshForeignProof(t *testing.T) {
	resolver := func(context.Context, string) ([]string, error) { return []string{"2606:4700::1111"}, nil }
	calls := 0
	p, err := New(Config{DestinationFamily: "ipv6", Resolve6: resolver,
		Upstreams: []Upstream{{Name: "exit", Addr: "127.0.0.1:1", Exit: true, AIEligible: true}},
		VerifyExit: func(context.Context, Upstream) error {
			calls++
			return errors.New("no IPv6 foreign egress")
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.verifyExit(context.Background(), p.ups[0]); err == nil || calls != 1 {
		t.Fatalf("generic startup proof incorrectly authorized IPv6: %v calls=%d", err, calls)
	}
}
