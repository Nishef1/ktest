package mobilebridge

import (
	"context"
	"errors"

	"github.com/Nishef1/ktest/internal/connectiondns"
	"github.com/Nishef1/ktest/internal/connectionpolicy"
	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// fastCarrier is a private, adaptive Fast-mode proxy that only the packaged
// Aether process uses as its --upstream. It gives WARP registration and the
// MASQUE/Gool H2 tunnel the same Go cuts and ByeDPI race that Fast uses,
// for networks where Aether cannot reach Cloudflare directly.
type fastCarrier struct {
	address string
	cancel  context.CancelFunc
	session *connectionsession.Session
	cores   *localCoreSet
}

func startFastCarrier(ctx context.Context, nativeDir, privateDir string) (_ *fastCarrier, err error) {
	if nativeDir == "" {
		return nil, errors.New("Fast carrier needs the packaged core directory")
	}
	cores, err := launchAndroidLocalCores(ctx, nativeDir, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			cores.stop()
		}
	}()
	rules, err := smartproxy.NewAIDomainRules("")
	if err != nil {
		return nil, err
	}
	config := smartproxy.Config{
		Upstreams:        append(append(smartproxy.PlainUpstreams(), smartproxy.DesyncUpstreams()...), cores.upstreams...),
		RecoverIPHostSNI: true,
	}
	connectionpolicy.Configure("fast", &config, rules.Match)
	if config.Resolve, config.Resolve6, err = connectiondns.MobileResolvers("fast", ""); err != nil {
		return nil, err
	}
	proxy, err := smartproxy.New(config)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	session, err := connectionsession.Start(runCtx, proxy, "127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, err
	}
	c := &fastCarrier{address: session.SOCKS.Addr().String(), cancel: cancel, session: session, cores: cores}
	for _, child := range cores.cores {
		go func() {
			select {
			case <-runCtx.Done():
			case <-child.done:
				proxy.Remove(child.method)
			}
		}()
	}
	return c, nil
}

func (c *fastCarrier) stop() {
	c.cancel()
	c.session.Stop()
	c.cores.stop()
}

// StartNativeProxyViaFast runs packaged Aether with its traffic carried by a
// private Fast proxy. Only TCP (H2) Aether methods can be carried this way.
func StartNativeProxyViaFast(method, libraryDir, stateDir, privateDir string) (string, error) {
	return StartNativeModeViaFast("aether", method, libraryDir, stateDir, privateDir)
}

// StartNativeModeViaFast runs Aether, Psiphon or Tor with every outbound
// connection carried by a private Fast proxy (Go ClientHello cuts, ByeDPI and
// learned priors). Psiphon and Tor need no WARP: they dial through the carrier
// directly, and Psiphon's CDN fronting also gets this network's verified edges.
func StartNativeModeViaFast(mode, method, libraryDir, stateDir, privateDir string) (string, error) {
	if mode != "aether" && mode != "tor" && mode != "psiphon" {
		return "", errors.New("only Aether, Psiphon and Tor can run through Fast")
	}
	return startProxy(mode, "", &nativeOptions{method: method, libraryDir: libraryDir, stateDir: stateDir, viaFast: true, privateDir: privateDir}, "")
}
