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

// Decode only known status fields. Never echo arbitrary CLI output: it may
// contain account names or sensitive diagnostic details.
func windscribeStatusIssue(raw string, state windscribeState, loggedIn bool) string {
	if !loggedIn {
		for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
			field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			if ok && strings.EqualFold(strings.TrimSpace(field), "Login state") {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "error:") {
					return "Windscribe account API failed; login is unverified, which does not establish that the VPN disconnected"
				}
				if !strings.EqualFold(strings.TrimSpace(value), "logged in") {
					return "Windscribe desktop app is not logged in; open the app and log in"
				}
			}
		}
		return "Windscribe CLI returned no recognizable login state; inspect windscribe-cli status"
	}
	if state == windscribeUnknown {
		return "Windscribe CLI returned an unrecognized connection state"
	}
	return ""
}

func readWSStatus(ctx context.Context, cli string) wsCLIStatus {
	if cli == "" {
		return wsCLIStatus{err: fmt.Errorf("Windscribe CLI executable not found; check its installed path")}
	}
	out, err := (&windscribeMonitor{cli: cli}).command(ctx, "status")
	if err != nil {
		return wsCLIStatus{err: fmt.Errorf("Windscribe CLI status command failed: %w", err)}
	}
	state, loggedIn := parseWindscribeStatus(string(out))
	if !loggedIn && state != windscribeConnected && state != windscribeConnecting {
		return wsCLIStatus{err: fmt.Errorf("%s", windscribeStatusIssue(string(out), state, loggedIn))}
	}
	if state == windscribeUnknown {
		return wsCLIStatus{err: fmt.Errorf("Windscribe CLI returned an unrecognized connection state")}
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
func verifyWindscribeVPN(ctx context.Context, cli string, u *term, expected ...string) int {
	before := readWSStatus(ctx, cli)
	if before.err != nil || before.state != windscribeConnected {
		u.Line(toneWarn, "VPN verification needs a confirmed Windscribe CLI Connected state; no reconnect requested")
		if before.err != nil {
			u.Note("CLI: %v", before.err)
		}
		return 1
	}
	reference := before.ip
	referenceSource := "Windscribe CLI"
	if len(expected) > 0 && expected[0] != "" {
		ip := net.ParseIP(expected[0])
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			u.Line(toneFail, "Expected VPN IP must be a public IP copied from the Windscribe app")
			return 2
		}
		if reference != "" && !net.ParseIP(reference).Equal(ip) {
			u.Line(toneWarn, "Expected VPN IP does not match the CLI-reported VPN IP; check the reference first")
			return 1
		}
		reference = ip.String()
		referenceSource = "Windscribe app IP supplied by user"
	}
	u.Note("CLI: connected, protocol=%s; only one system HTTPS request will be checked", before.protocol)
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
	if before.err != nil || after.err != nil || before.state != windscribeConnected || after.state != windscribeConnected ||
		before.protocol != after.protocol || (before.ip != "" && after.ip != before.ip) {
		u.Line(toneWarn, "VPN state, protocol or CLI IP changed during HTTPS check; result inconclusive")
		return 1
	}
	ip := net.ParseIP(measured)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		u.Line(toneWarn, "HTTPS endpoint returned no valid public IP; VPN data not verified")
		return 1
	}
	u.Note("System HTTPS observed public IP: %s", measured)
	if reference == "" {
		u.Line(toneWarn, "CLI did not report a VPN IP, so Windscribe's routing cannot be independently verified from this measurement")
		u.Note("Compare with the VPN IP displayed in the Windscribe app; for an exact comparison use windscribe-test -verify-vpn -expected-vpn-ip <app-IP>")
		return 1
	}
	if !ip.Equal(net.ParseIP(reference)) {
		u.Line(toneWarn, "System HTTPS IP=%s differs from %s=%s; inspect split-tunnel and routing settings", measured, referenceSource, reference)
		return 1
	}
	u.Line(toneOK, "HTTPS exit IP=%s matches %s; Windscribe remained connected during the check", measured, referenceSource)
	u.Note("This confirms the sampled request matches the reference IP; other destinations, apps, DNS and the particular SNI/carrier were not tested.")
	return 0
}
