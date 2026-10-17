package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/revive"
)

func fileOK(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// runDoctor is `ktest doctor`: diagnose, change nothing.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "portable folder holding cores/ and profiles/")
	noNet := fs.Bool("no-net", false, "skip the network characterization")
	modeText := fs.String("mode", "balanced", "balanced, fast, aether, psiphon, tor, or windscribe; check the relevant prerequisites")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest doctor [-mode balanced|fast|aether|psiphon|tor|windscribe] [-no-net]")
		return 2
	}
	mode, err := parseConnectionMode(*modeText)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if runDoctorMode(ctx, newTerm(os.Stdout), *base, *noNet, mode) {
		return 1
	}
	return 0
}

// runDoctorMode inspects the package and the network without starting a core or
// changing anything, and says which layer to look at first. It reports whether
// a blocking problem was found.
func runDoctorMode(ctx context.Context, u *term, base string, noNet bool, mode ConnectionMode) (failed bool) {
	description := "Reads the package and measures this network. Changes nothing."
	if noNet {
		description = "Reads the package and checks local ports. Network tests are disabled."
	}
	u.Heading("diagnose", description)
	u.Note("Selected policy: %s. Missing optional cores disable their own paths; they do not prove every route is blocked.", mode)
	warns := 0
	line := func(k tone, name, detail string) {
		switch k {
		case toneFail:
			failed = true
		case toneWarn:
			warns++
		}
		u.Line(k, "%-24s %s", name, detail)
	}
	section := func(name string) { u.Println("\n  " + u.Bold(name)) }

	cores := filepath.Join(base, "cores")
	exeName := func(name string) string {
		if runtime.GOOS == "windows" {
			return name + ".exe"
		}
		return name
	}

	// 1. Package contents.
	section("Package")
	xray := filepath.Join(cores, exeName("xray"))
	profile := filepath.Join(base, "profiles", "Serverless-for-Iran.json")
	needs := []struct{ name, path string }{
		{"Xray core", xray},
		{"Xray geoip.dat", filepath.Join(cores, "geoip.dat")},
		{"Xray geosite.dat", filepath.Join(cores, "geosite.dat")},
		{"Serverless profile", profile},
		{"ByeDPI core", byeDPIBinary(base)},
	}
	if mode == ModeWindscribe {
		needs = []struct{ name, path string }{{"Xray local TCP core", xray}, {"ByeDPI core", byeDPIBinary(base)}}
	}
	if mode.exitOnly() {
		needs = []struct{ name, path string }{{"Aether exit core", aetherBinary(base)}}
	}
	if mode == ModePsiphon {
		needs = append(needs, struct{ name, path string }{"Psiphon helper", psiphonCore(base)})
	}
	for _, need := range needs {
		if fileOK(need.path) {
			line(toneOK, need.name, u.Dim(need.path))
		} else {
			line(toneWarn, need.name, "unavailable: "+need.path+"; this optional path cannot run")
		}
	}
	if runtime.GOOS == "windows" && mode != ModeWindscribe {
		for _, name := range []string{"sing-box.exe", "wintun.dll"} {
			if fileOK(filepath.Join(cores, name)) {
				line(toneOK, name, u.Dim("only for the optional TUN"))
			} else {
				line(toneWarn, name, "missing; the TUN option will be unavailable")
			}
		}
	}
	if fileOK(xray) && !mode.exitOnly() {
		vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err := exec.CommandContext(vctx, xray, "version").CombinedOutput()
		cancel()
		switch {
		case err != nil:
			line(toneWarn, "Xray version", fmt.Sprintf("cannot run %s: %v; Xray paths unavailable", xray, err))
		default:
			if err := revive.CheckVersion(string(out)); err != nil {
				line(toneWarn, "Xray version", err.Error())
			} else {
				line(toneOK, "Xray version", "26.6.27 or newer")
			}
		}
	}
	if fileOK(profile) && mode != ModeWindscribe && !mode.exitOnly() {
		data, err := os.ReadFile(profile)
		if err != nil {
			line(toneWarn, "Profile", err.Error())
		} else {
			for _, variant := range []string{"A", "B"} {
				if _, err := revive.SelectProfile(data, variant); err != nil {
					line(toneWarn, "Profile fragment "+variant, err.Error())
				} else {
					line(toneOK, "Profile fragment "+variant, u.Dim("parses, one loopback inbound"))
				}
			}
		}
	}
	if !mode.exitOnly() {
		if list, source, err := loadStrategies(base); err != nil {
			line(toneWarn, "ByeDPI strategies", err.Error())
		} else {
			line(toneOK, "ByeDPI strategies", fmt.Sprintf("%d from %s", len(list), u.Dim(source)))
		}
	}

	// 2. Local ports.
	section("Local ports")
	for _, p := range []struct {
		port int
		name string
	}{{connectPort, "Connect SOCKS"}, {connectHTTPPort, "Connect HTTP"}, {xrayPort, "Xray"}} {
		if err := portFree(p.port); err != nil {
			line(toneInfo, fmt.Sprintf("Port %d (%s)", p.port, p.name), "listener already present; ownership/health not inferred from an open port")
		} else {
			line(toneOK, fmt.Sprintf("Port %d (%s)", p.port, p.name), "free")
		}
	}

	if mode == ModeWindscribe {
		for _, name := range activeKtestTUNs() {
			line(toneFail, "Conflicting TUN", name+" is up; Windscribe bridge cannot share ktest's TUN")
		}
		cli, err := windscribeCLIPath("")
		status := readWSStatus(ctx, cli)
		if err != nil || status.err != nil {
			line(toneWarn, "Windscribe CLI", "unavailable; login/protocol/VPN state unverified")
		} else {
			line(toneInfo, "Windscribe state", status.state.String())
			if status.protocol != "" {
				line(toneInfo, "Windscribe protocol", status.protocol)
			}
			if status.state == windscribeConnected && status.ip != "" {
				line(toneInfo, "VPN IP (CLI)", status.ip+"; reported exit, not independently measured")
			}
			if (status.state == windscribeConnected || status.state == windscribeConnecting) && status.protocol != "" && !strings.HasPrefix(strings.ToLower(status.protocol), "tcp:") {
				line(toneWarn, "Proxy compatibility", "use OpenVPN TCP; the selected protocol does not use this HTTP bridge")
			}
		}
		u.Note("Windscribe Proxy Settings: HTTP 127.0.0.1:10801, OpenVPN TCP 443. UI proxy settings were not inspected.")
		u.Note("MITM website fronting/CA and foreign exits are not used by this bridge. Imported Xray profiles are not required.")
		if !noNet {
			ip, poisoned, err := systemDNS(ctx, "windscribe.com")
			if err != nil || poisoned {
				line(toneWarn, "Windscribe API DNS", "system answer unusable; trusted DNS/anti-DPI API path required")
			} else {
				line(toneInfo, "Windscribe API DNS", ip+"; DNS only, no API/VPN reachability claim")
			}
		}
		u.Note("For fixed-entry SNI tests use menu 10 or windscribe-test -target <location/TCP IP>.")
		u.Note("OpenVPN authentication was not attempted. For one connected-VPN data check use windscribe-test -verify-vpn.")
		if ctx.Err() != nil {
			u.Note("Diagnostics cancelled.")
			return failed
		}
		if failed {
			u.Box("RESOLVE CONFLICTS", toneFail, []string{"Resolve the reported conflicts before starting the Windscribe bridge."})
		} else {
			u.Box("WINDSCRIBE PREREQUISITES CHECKED", toneInfo, []string{"CLI/package checks are not a completed VPN handshake. Use the carrier and connected-VPN tests separately."})
		}
		return failed
	}

	// 3. The network, measured without any proxy.
	if !noNet {
		section("Network")
		cli, _ := windscribeCLIPath("")
		if status := readWSStatus(ctx, cli); status.state == windscribeConnected || status.state == windscribeConnecting {
			u.Note("Windscribe is %s: probes use the current system route, which may include its VPN; ISP-only reachability is not established.", status.state)
		}
		dns := dnscheck.CheckGoogleDNS(ctx)
		switch {
		case dns.UDP && dns.TCP:
			line(toneOK, "Google DNS 8.8.8.8", "UDP and TCP answer a real query")
		case dns.UDP || dns.TCP:
			line(toneWarn, "Google DNS 8.8.8.8", fmt.Sprintf("UDP=%t TCP=%t; only one transport answers", dns.UDP, dns.TCP))
		default:
			line(toneWarn, "Google DNS 8.8.8.8", "no answer (UDP and TCP); plain public DNS is filtered here")
		}
		directCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		direct := quickcheck.RunDirect(directCtx, 8*time.Second)
		cancel()
		for _, r := range direct {
			if r.Success {
				line(toneOK, "Direct "+r.Target, "reachable without any proxy")
			} else {
				line(toneInfo, "Direct "+r.Target, "not reachable without a proxy "+u.Dim(trimDetail(r.Detail)))
			}
		}
		prog := u.Progress("Probing DNS, encrypted DNS, packet shapes", 3)
		pctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		rep := probeNetwork(pctx, func(done int) { prog.Set(done, "") })
		cancel()
		prog.Finish(toneOK, "")
		rep.print(u)
		fprog := u.Progress("Probing domain fronting", 1)
		fctx, fcancel := context.WithTimeout(ctx, 25*time.Second)
		checks := probeFronts(fctx)
		fcancel()
		fprog.Finish(toneOK, "")
		printFronts(u, checks)
		printECHDoH(ctx, u)
		u.Println("")
		verdict := wrapText(rep.verdictText, 76)
		for _, c := range checks {
			if c.working() > 0 {
				verdict = append(verdict, "")
				verdict = append(verdict, wrapText("Domain fronting gets through for "+c.family+" sites. It does not cut the ClientHello, so it also works where cutting is punished. `ktest ca -install` enables it in Connect.", 76)...)
				break
			}
		}
		u.Box("VERDICT", rep.verdict, verdict)
		u.Note("Coverage: a few DNS, TLS/packet-shape and website-fronting samples. No exhaustive SNI scan, OpenVPN authentication or all-app VPN test.")
	} else {
		u.Note("Network checks skipped (-no-net).")
	}

	// Result.
	if ctx.Err() != nil {
		u.Note("Diagnostics cancelled.")
		return failed
	}
	u.Println("")
	switch {
	case failed:
		u.Box("FIX FIRST", toneFail, []string{"Resolve the blocking items above; other results apply only to the checks that actually ran."})
	case warns > 0:
		u.Box("CHECKS FINISHED WITH NOTES", toneWarn, []string{fmt.Sprintf("%d note(s) above. Availability depends on the selected policy and tested destinations.", warns)})
	case noNet:
		u.Box("PACKAGE CHECKS PASSED", toneOK, []string{"Network access was not tested. Run `ktest doctor` for network diagnostics."})
	default:
		u.Box("CHECKS FINISHED", toneInfo, []string{"Read the sampled network verdict above. Passing package checks does not prove universal access or a working VPN."})
	}
	return failed
}

func activeKtestTUNs() []string {
	ifaces, _ := net.Interfaces()
	var names []string
	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if iface.Flags&net.FlagUp != 0 && (strings.Contains(name, "sing-tun") || strings.Contains(name, "ktest-tun")) {
			names = append(names, iface.Name)
		}
	}
	return names
}
