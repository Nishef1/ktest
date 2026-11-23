package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/connectiondns"
	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

var serverlessVariants = []struct{ key, variant, label string }{
	{"1", "A", "Fragment A"},
	{"2", "B", "Fragment B"},
	{"3", "OOB", "Out-of-band (OOB)"},
}

func validServerlessVariant(variant string) bool {
	return variant == "A" || variant == "B" || variant == "OOB"
}

// serverlessMenu stores the choice separately from CLI flags and TUN coverage.
func (t *terminal) serverlessMenu(base string, in *input) bool {
	for {
		t.ui.menuView()
		t.ui.Heading("Serverless v65", "PattNG Xray · local ISP route, NOT Psiphon or a foreign VPN")
		t.ui.Note("Your public IP remains the ISP's. Configure apps to use this local proxy.")
		for _, option := range serverlessVariants {
			t.ui.menuOption(option.key, option.label, "HTTP/SOCKS5 · 127.0.0.1:10808")
		}
		t.ui.menuOption("0", "Back", "")
		t.ui.Printf("  Profile > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if answer == "" || isBackChoice(answer) {
			return true
		}
		var variant string
		for _, option := range serverlessVariants {
			if answer == option.key {
				variant = option.variant
				break
			}
		}
		if !validServerlessVariant(variant) {
			t.ui.Line(toneWarn, "Select 1, 2, 3 or 0.")
			continue
		}
		t.settings.LastConnection = "serverless"
		t.settings.ServerlessVariant = variant
		t.savePreferences() // A deliberate choice survives an unsuccessful core start.
		return t.startServerless(base, in, variant)
	}
}

// startServerless validates the inspectable portable JSON but executes only
// the embedded, pinned profile. It never changes system routes or proxies.
func (t *terminal) startServerless(base string, in *input, variant string) bool {
	if !validServerlessVariant(variant) {
		t.ui.Line(toneWarn, "Invalid saved Serverless method; select 7 to repair it.")
		return true
	}
	binary := filepath.Join(base, "cores", "xray.exe")
	profile := filepath.Join(base, "profiles", "Serverless-for-Iran.json")
	if _, err := os.Stat(binary); err != nil {
		t.ui.Line(toneWarn, "Bundled Xray is missing; install the Windows portable ZIP.")
		return true
	}
	if err := revive.VerifyPinnedSubscriptionFile(profile); err != nil {
		t.ui.Line(toneWarn, "Serverless profile verification failed: %v. Reinstall the portable ZIP.", err)
		return true
	}
	t.ui.leaveMenu()
	family := t.options.destinationFamily
	if family != "" && family != "both" {
		t.ui.Note("Serverless %s · %s · ISP IP · SOCKS 127.0.0.1:10808; HTTP 127.0.0.1:10809. Press Enter to stop.", variant, familyLabel(family))
		return t.tool(in, func(ctx context.Context) {
			if err := runFamilyServerless(ctx, binary, filepath.Join(base, "cores"), variant, family, t.ui); err != nil && ctx.Err() == nil {
				t.ui.Line(toneWarn, "%v", err)
			}
		})
	}
	t.ui.Note("Serverless %s · ISP IP · proxy 127.0.0.1:10808. Press Enter to stop.", variant)
	return t.tool(in, func(ctx context.Context) {
		err := revive.RunPinned(ctx, revive.Config{
			XrayBinary: binary, Variant: variant,
			AssetDir: filepath.Join(base, "cores"), Port: revive.DefaultPort, Output: os.Stderr,
		})
		if err != nil && ctx.Err() == nil {
			t.ui.Line(toneWarn, "Serverless %s: %v", variant, err)
		}
	})
}

// runFamilyServerless keeps the audited Xray profile unchanged and exposes
// only KTest's family-enforcing application listeners on the usual ports.
// The native loopback helper is not a managed public endpoint.
func runFamilyServerless(parent context.Context, binary, assets, variant, family string, t *term) error {
	if family != "ipv4" && family != "ipv6" {
		return errors.New("invalid single-family Serverless mode")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	var runErr error
	logs := &tailBuffer{max: 4096}
	go func() {
		defer close(done)
		runErr = revive.RunPinned(ctx, revive.Config{XrayBinary: binary, Variant: variant,
			AssetDir: assets, Port: port, Output: logs})
	}()
	defer func() { cancel(); <-done }()
	ready, finish := context.WithTimeout(ctx, 20*time.Second)
	ok := byedpi.WaitReady(ready, done, address)
	finish()
	if !ok {
		select {
		case <-done:
			return fmt.Errorf("Serverless Xray failed: %v", runErr)
		default:
			return errors.New("Serverless Xray listener did not become ready")
		}
	}
	a, aaaa, err := connectiondns.MobileResolversPolicy("serverless", address, "", true)
	if err != nil {
		return err
	}
	exchange, closeDNS, err := connectiondns.MobilePacketDNS("serverless", address)
	if err != nil {
		return err
	}
	defer closeDNS()
	proxy, err := smartproxy.New(smartproxy.Config{
		DestinationFamily: family, Resolve: a, Resolve6: aaaa, ExchangeDNS: exchange,
		Upstreams: []smartproxy.Upstream{{Name: "Serverless " + variant, Addr: address, LocalBypass: true}},
	})
	if err != nil {
		return err
	}
	session, err := connectionsession.Start(ctx, proxy, "127.0.0.1:10808")
	if err != nil {
		return err
	}
	defer session.Stop()
	if _, err := session.StartHTTP("127.0.0.1:10809", nil); err != nil {
		return err
	}
	t.Note("Serverless family-enforced proxy listening; public reachability is not yet verified.")
	select {
	case <-parent.Done():
		return nil
	case <-done:
		return fmt.Errorf("Serverless Xray exited: %v", runErr)
	case <-session.Done():
		return session.Err()
	}
}
