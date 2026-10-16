package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/revive"
)

type doctorReport struct {
	failed bool
}

func (d *doctorReport) line(level, name, detail string) {
	if level == "FAIL" {
		d.failed = true
	}
	fmt.Printf("%-5s %-22s %s\n", level, name, detail)
}

func fileOK(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// runDoctor inspects the package and the network without starting a core or
// changing anything, and says which layer to look at first.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	exe, _ := os.Executable()
	base := fs.String("base", filepath.Dir(exe), "portable folder holding cores/ and profiles/")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest doctor [-base DIR]")
		return 2
	}
	ctx := context.Background()
	d := &doctorReport{}
	cores := filepath.Join(*base, "cores")
	exeName := func(name string) string {
		if runtime.GOOS == "windows" {
			return name + ".exe"
		}
		return name
	}

	// 1. Package contents.
	xray := filepath.Join(cores, exeName("xray"))
	profile := filepath.Join(*base, "profiles", "Serverless-for-Iran.json")
	for _, need := range []struct{ name, path string }{
		{"xray core", xray},
		{"xray geoip.dat", filepath.Join(cores, "geoip.dat")},
		{"xray geosite.dat", filepath.Join(cores, "geosite.dat")},
		{"serverless profile", profile},
		{"ByeDPI core", filepath.Join(cores, exeName("ciadpi"))},
	} {
		if fileOK(need.path) {
			d.line("OK", need.name, need.path)
		} else {
			d.line("FAIL", need.name, "missing: "+need.path+" (extract the complete portable ZIP, both layers)")
		}
	}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"sing-box.exe", "wintun.dll"} {
			if fileOK(filepath.Join(cores, name)) {
				d.line("OK", name, "needed only for the optional TUN")
			} else {
				d.line("WARN", name, "missing; menu item 6 (TUN) will be unavailable")
			}
		}
	}

	// 2. Xray version and profile.
	if fileOK(xray) {
		vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err := exec.CommandContext(vctx, xray, "version").CombinedOutput()
		cancel()
		switch {
		case err != nil:
			d.line("FAIL", "xray version", fmt.Sprintf("cannot run %s: %v (antivirus quarantine or blocked download?)", xray, err))
		default:
			if err := revive.CheckVersion(string(out)); err != nil {
				d.line("FAIL", "xray version", err.Error())
			} else {
				d.line("OK", "xray version", "26.6.27 or newer")
			}
		}
	}
	if fileOK(profile) {
		data, err := os.ReadFile(profile)
		if err != nil {
			d.line("FAIL", "profile", err.Error())
		} else {
			for _, variant := range []string{"A", "B"} {
				if _, err := revive.SelectProfile(data, variant); err != nil {
					d.line("FAIL", "profile Fragment "+variant, err.Error())
				} else {
					d.line("OK", "profile Fragment "+variant, "parses and has one loopback inbound")
				}
			}
		}
	}

	// 3. Local ports.
	for _, p := range []struct {
		port int
		name string
	}{{xrayPort, "Xray"}, {byeDPIPort, "ByeDPI"}} {
		if err := portFree(p.port); err != nil {
			d.line("FAIL", fmt.Sprintf("port %d (%s)", p.port, p.name), err.Error())
		} else {
			d.line("OK", fmt.Sprintf("port %d (%s)", p.port, p.name), "free")
		}
	}

	// 4. Network, measured without any proxy.
	dns := dnscheck.CheckGoogleDNS(ctx)
	switch {
	case dns.UDP && dns.TCP:
		d.line("OK", "Google DNS 8.8.8.8", "UDP and TCP answer a real TXT query")
	case dns.UDP || dns.TCP:
		d.line("WARN", "Google DNS 8.8.8.8", fmt.Sprintf("UDP=%t TCP=%t; only one transport answers", dns.UDP, dns.TCP))
	default:
		d.line("WARN", "Google DNS 8.8.8.8", "no answer; encrypted DNS inside the profile may still work")
	}
	directCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	direct := quickcheck.RunDirect(directCtx, 8*time.Second)
	cancel()
	open := 0
	for _, r := range direct {
		if r.Success {
			open++
			d.line("OK", "direct "+r.Target, "reachable without any proxy")
		} else {
			d.line("INFO", "direct "+r.Target, "not reachable without a proxy: "+r.Detail)
		}
	}
	if open == len(direct) && open > 0 {
		d.line("INFO", "interpretation", "every target already works directly, so ktest can only report BASELINE. If another VPN is connected, disconnect it to test a bypass; otherwise this network is not blocking them now.")
	}

	if d.failed {
		fmt.Println("\nFix the FAIL lines first; nothing else is meaningful until they pass.")
		return 1
	}
	fmt.Println("\nNo blocking problems found. Run `ktest auto` to find a working method.")
	return 0
}
