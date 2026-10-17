package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

type wsCLIStatus struct {
	state        windscribeState
	protocol, ip string
	err          error
}

func readWSStatus(ctx context.Context, cli string) wsCLIStatus {
	if cli == "" {
		return wsCLIStatus{err: fmt.Errorf("Windscribe CLI unavailable")}
	}
	out, err := (&windscribeMonitor{cli: cli}).command(ctx, "status")
	state, loggedIn := parseWindscribeStatus(string(out))
	if err != nil || !loggedIn || state == windscribeUnknown {
		return wsCLIStatus{err: fmt.Errorf("CLI status unavailable or not logged in")}
	}
	return wsCLIStatus{state: state, protocol: parseWindscribeProtocol(string(out)), ip: parseWindscribeVPNIP(string(out))}
}

func tracePublicIP(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			return parseWindscribeVPNIP("VPN IP: " + value)
		}
	}
	return ""
}

func validateWSDataResult(before, after wsCLIStatus, measured string) error {
	if before.err != nil || after.err != nil || before.state != windscribeConnected || after.state != windscribeConnected || after.ip != before.ip || after.protocol != before.protocol {
		return fmt.Errorf("VPN state/IP changed or was unavailable during the HTTPS check; result inconclusive")
	}
	ip, expected := net.ParseIP(measured), net.ParseIP(before.ip)
	if ip == nil || expected == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return fmt.Errorf("HTTPS reply or CLI had no valid public IP; VPN data not verified")
	}
	if !ip.Equal(expected) {
		return fmt.Errorf("system HTTPS IP=%s differs from CLI VPN IP=%s; check split-tunnel exclusions/routing for curl", measured, before.ip)
	}
	return nil
}

// One certificate-verified HTTPS request, through a separate system process.
// Equality with a stable CLI-reported IP is evidence for this request only;
// split-tunnel exclusions and other applications are not certified.
func verifyWindscribeVPN(ctx context.Context, cli string, u *term) int {
	before := readWSStatus(ctx, cli)
	if before.err != nil || before.state != windscribeConnected || before.ip == "" {
		u.Line(toneWarn, "VPN verification needs a confirmed CLI Connected state and a public VPN IP; no reconnect requested")
		return 1
	}
	u.Note("CLI: connected, protocol=%s, VPN IP=%s", before.protocol, before.ip)
	u.Note("This data check does not associate the session with a particular SNI/carrier or inspect the app's proxy settings.")
	if !strings.HasPrefix(strings.ToLower(before.protocol), "tcp:") {
		u.Note("This protocol does not verify ktest's OpenVPN TCP bridge or any tested SNI.")
	}
	name := "curl"
	if runtime.GOOS == "windows" {
		name = "curl.exe"
	}
	bin, err := exec.LookPath(name)
	if err != nil {
		u.Line(toneWarn, "System HTTPS check unavailable: curl executable not found")
		return 1
	}
	var stdout, stderr tailBuffer
	stdout.max, stderr.max = 4097, 1024
	cmd := exec.CommandContext(ctx, bin, "--disable", "--silent", "--show-error", "--fail", "--max-time", "10", "--max-filesize", "4096", "--noproxy", "*", "--proxy", "", "https://www.cloudflare.com/cdn-cgi/trace")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		u.Line(toneWarn, "System HTTPS check failed: %s", trimDetail(stderr.lastLine()))
		return 1
	}
	measured := tracePublicIP(string(stdout.data))
	after := readWSStatus(ctx, cli)
	if err := validateWSDataResult(before, after, measured); err != nil {
		u.Line(toneWarn, "%v", err)
		return 1
	}
	u.Line(toneOK, "HTTPS data verified: measured exit=%s matches stable Windscribe CLI VPN IP", measured)
	u.Note("This verifies one system HTTPS request. Other destinations/apps and split-tunnel rules were not tested.")
	return 0
}
