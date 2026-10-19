package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"

	"github.com/Nishef1/ktest/internal/packetdesync"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/systemtun"
)

func localZapretUpstreams(base string) []smartproxy.Upstream {
	if runtime.GOOS != "windows" || !systemtun.IsAdmin() || packetdesync.VerifyBundle(filepath.Join(base, "cores", "zapret2")) != nil {
		return nil
	}
	dialer := packetdesync.NewDialer(base)
	var routes []smartproxy.Upstream
	for _, strategy := range []packetdesync.Strategy{packetdesync.Split, packetdesync.Fake, packetdesync.Combo} {
		routes = append(routes, smartproxy.Upstream{Name: "Zapret2 " + string(strategy), LocalDNS: true, Network: "tcp4", LocalBypass: true, Rank: 4, Late: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.Dial(ctx, network, address, strategy)
			}})
	}
	return routes
}
