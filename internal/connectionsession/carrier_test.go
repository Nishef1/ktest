package connectionsession

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestLocalCarrierHasAnIndependentListenerAndStopsWithItsOwner(t *testing.T) {
	source, _ := smartproxy.New(smartproxy.Config{Upstreams: smartproxy.PlainUpstreams(), EnsureExit: func(context.Context) error { t.Fatal("carrier recursively requested its own exit"); return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrier, err := StartLocalCarrier(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	address := carrier.SOCKS.Addr().String()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	cancel()
	carrier.Stop()
	if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("private carrier listener survived session shutdown")
	}
}
