package connectionsession

import (
	"context"

	"github.com/Nishef1/ktest/internal/connectiondns"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// StartLocalCarrier reuses already-running local routes. Its DNS never
// depends on the foreign tunnel it is responsible for establishing.
func StartLocalCarrier(ctx context.Context, source *smartproxy.Proxy) (*Session, error) {
	return StartLocalCarrierWithDNS(ctx, source, "")
}

// StartLocalCarrierWithDNS is the mobile-only variant that optionally uses an
// explicitly selected resolver while keeping SOCKS-carried queries on TCP.
func StartLocalCarrierWithDNS(ctx context.Context, source *smartproxy.Proxy, customDNS string) (*Session, error) {
	if source == nil {
		var err error
		source, err = smartproxy.New(smartproxy.Config{Upstreams: append(smartproxy.PlainUpstreams(), smartproxy.DesyncUpstreams()...)})
		if err != nil {
			return nil, err
		}
	}
	cfg := source.LocalCarrierConfig()
	var err error
	cfg.Resolve, cfg.Resolve6, err = connectiondns.MobileResolversWithCustom("fast", "", customDNS)
	if err != nil {
		return nil, err
	}
	p, err := smartproxy.New(cfg)
	if err != nil {
		return nil, err
	}
	return Start(ctx, p, "127.0.0.1:0")
}
