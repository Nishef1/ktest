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

func fileOK(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// runDoctor is `ktest doctor`: diagnose, change nothing.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "portable folder holding cores/ and profiles/")
	noNet := fs.Bool("no-net", false, "skip the network characterization")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest doctor [-no-net]")
		return 2
	}
	if runDoctorView(newTerm(os.Stdout), *base, *noNet) {
		return 1
	}
	return 0
}

// runDoctorView inspects the package and the network without starting a core or
// changing anything, and says which layer to look at first. It reports whether
// a blocking problem was found.
func runDoctorView(u *term, base string, noNet bool) (failed bool) {
	ctx := context.Background()
	u.Heading("diagnose", "Reads the package and measures this network. Changes nothing.")
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
	for _, need := range []struct{ name, path string }{
		{"Xray core", xray},
		{"Xray geoip.dat", filepath.Join(cores, "geoip.dat")},
		{"Xray geosite.dat", filepath.Join(cores, "geosite.dat")},
		{"Serverless profile", profile},
		{"ByeDPI core", byeDPIBinary(base)},
	} {
		if fileOK(need.path) {
			line(toneOK, need.name, u.Dim(need.path))
		} else {
			line(toneFail, need.name, "missing: "+need.path+" (extract the complete portable ZIP, both layers)")
		}
	}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"sing-box.exe", "wintun.dll"} {
			if fileOK(filepath.Join(cores, name)) {
				line(toneOK, name, u.Dim("only for the optional TUN"))
			} else {
				line(toneWarn, name, "missing; the TUN option will be unavailable")
			}
		}
	}
	if fileOK(xray) {
		vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err := exec.CommandContext(vctx, xray, "version").CombinedOutput()
		cancel()
		switch {
		case err != nil:
			line(toneFail, "Xray version", fmt.Sprintf("cannot run %s: %v (antivirus quarantine?)", xray, err))
		default:
			if err := revive.CheckVersion(string(out)); err != nil {
				line(toneFail, "Xray version", err.Error())
			} else {
				line(toneOK, "Xray version", "26.6.27 or newer")
			}
		}
	}
	if fileOK(profile) {
		data, err := os.ReadFile(profile)
		if err != nil {
			line(toneFail, "Profile", err.Error())
		} else {
			for _, variant := range []string{"A", "B"} {
				if _, err := revive.SelectProfile(data, variant); err != nil {
					line(toneFail, "Profile fragment "+variant, err.Error())
				} else {
					line(toneOK, "Profile fragment "+variant, u.Dim("parses, one loopback inbound"))
				}
			}
		}
	}
	if list, source, err := loadStrategies(base); err != nil {
		line(toneFail, "ByeDPI strategies", err.Error())
	} else {
		line(toneOK, "ByeDPI strategies", fmt.Sprintf("%d from %s", len(list), u.Dim(source)))
	}

	// 2. Local ports.
	section("Local ports")
	for _, p := range []struct {
		port int
		name string
	}{{connectPort, "Connect"}, {xrayPort, "Xray"}, {byeDPIPort, "ByeDPI"}} {
		if err := portFree(p.port); err != nil {
			line(toneWarn, fmt.Sprintf("Port %d (%s)", p.port, p.name), "in use: another ktest, v2rayN or a leftover core (netstat -ano | findstr :"+fmt.Sprint(p.port)+")")
		} else {
			line(toneOK, fmt.Sprintf("Port %d (%s)", p.port, p.name), "free")
		}
	}

	// 3. The network, measured without any proxy.
	section("Network")
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
	open := 0
	for _, r := range direct {
		if r.Success {
			open++
			line(toneOK, "Direct "+r.Target, "reachable without any proxy")
		} else {
			line(toneInfo, "Direct "+r.Target, "not reachable without a proxy "+u.Dim(trimDetail(r.Detail)))
		}
	}
	if !noNet {
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
	} else if open == len(direct) && open > 0 {
		u.Note("Everything tested already works directly: no filtering is visible on this path (or another VPN carries it).")
	}

	// Result.
	u.Println("")
	switch {
	case failed:
		u.Box("FIX FIRST", toneFail, []string{"Resolve the lines marked with a cross; nothing else is meaningful until they pass."})
	case warns > 0:
		u.Box("OK WITH NOTES", toneWarn, []string{fmt.Sprintf("%d note(s) above. Connect (menu 1, or `ktest connect`) can run now.", warns)})
	default:
		u.Box("ALL GOOD", toneOK, []string{"Nothing blocks ktest. Run Connect (menu 1, or `ktest connect`)."})
	}
	return failed
}

// wrapText breaks s into lines of at most width runes at spaces.
func wrapText(s string, width int) []string {
	var lines []string
	line := ""
	for _, w := range splitWords(s) {
		if line != "" && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		if line == "" {
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func splitWords(s string) []string {
	var words []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				words = append(words, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		words = append(words, cur)
	}
	return words
}
