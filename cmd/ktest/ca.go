package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/systemtun"
)

// caDir is where the fronting CA lives (per user, never inside the portable
// folder, so the private key is not zipped or shared by accident).
func caDir() string {
	d, err := front.DefaultDir()
	if err != nil {
		return ""
	}
	return d
}

// loadFrontCA returns the CA when it exists; the second result says whether the
// operating system trusts it.
func loadFrontCA() (*front.CA, bool) {
	dir := caDir()
	if dir == "" || !front.Exists(dir) {
		return nil, false
	}
	ca, err := front.Load(dir)
	if err != nil {
		return nil, false
	}
	return ca, ca.TrustedBySystem()
}

const caUsage = `usage: ktest ca [-install | -uninstall | -delete]

  (no flag)   show the state of the domain-fronting CA
  -install    create the CA if needed and trust it for your Windows user
              (Windows shows its own confirmation dialog)
  -uninstall  stop trusting it; the files stay
  -renew      replace the CA by a new one that covers every site this ktest can front
  -delete     stop trusting it and delete the CA and its key
`

// runCA is `ktest ca`.
func runCA(args []string) int {
	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	install := fs.Bool("install", false, "")
	uninstall := fs.Bool("uninstall", false, "")
	del := fs.Bool("delete", false, "")
	renew := fs.Bool("renew", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, caUsage) }
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	// Contradictory trust-store actions must not silently choose the first.
	actions := 0
	for _, selected := range []bool{*install, *uninstall, *del, *renew} {
		if selected {
			actions++
		}
	}
	if actions > 1 {
		fmt.Fprintln(os.Stderr, "choose exactly one CA operation")
		return 2
	}
	u := newTerm(os.Stdout)
	switch {
	case *install:
		return caInstall(u)
	case *renew:
		if code := caRemove(u, true); code != 0 {
			return code
		}
		return caInstall(u)
	case *uninstall:
		return caRemove(u, false)
	case *del:
		return caRemove(u, true)
	}
	caStatus(u)
	return 0
}

// caStatus prints where the CA stands and what the next step is.
func caStatus(u *term) {
	u.Heading("domain fronting", "A local, name-constrained CA lets ktest show a harmless name on the wire.")
	dir := caDir()
	status := inspectCertificate()
	if status.state == "missing" {
		u.Line(toneInfo, "No CA yet. It is optional; without it Connect still works with every other method.")
		u.Note("`ktest ca -install` creates it and asks Windows to trust it for your user.")
		return
	}
	if status.state == "invalid" {
		u.Line(toneFail, "The CA in %s cannot be used: %s", dir, status.detail)
		u.Note("Repair the local files or use `ktest ca -delete` then `ktest ca -install`.")
		return
	}
	ca := status.ca
	u.Line(toneInfo, "CA folder    %s", dir)
	u.Line(toneInfo, "Thumbprint   %s   expires %s", ca.Fingerprint(), ca.Expires().Format("2006-01-02"))
	u.Line(toneInfo, "CA requests constrained to %d domains; enforcement of root constraints depends on each client trust store", len(ca.Permitted()))
	if missing := caMissing(ca); len(missing) > 0 {
		u.Line(toneWarn, "This CA predates %d site(s) this ktest can front: %s", len(missing), strings.Join(firstN(missing, 6), ", "))
		u.Note("`ktest ca -renew` replaces it by one that covers them (a CA's constraints cannot be extended).")
	}
	if status.state == "outdated" {
		u.Line(toneWarn, "Renew required: %s", status.detail)
		u.Note("`ktest ca -renew` replaces and installs it after confirmation.")
	} else if status.state == "ok" {
		u.Line(toneOK, "Installed, trusted by this system and up to date.")
		u.Note("Firefox keeps its own store: set security.enterprise_roots.enabled to true in about:config, or import %s.", ca.CertPath())
	} else {
		u.Line(toneWarn, "Not trusted by this system yet, so Connect leaves domain fronting off.")
		u.Note("`ktest ca -install`, or import %s into the trust store of the application you use.", ca.CertPath())
	}
}

// caInstall creates the CA when needed and trusts it for the current user.
func caInstall(u *term) int {
	dir := caDir()
	if dir == "" {
		u.Line(toneFail, "No per-user configuration folder is available; set KTEST_CA_DIR.")
		return 1
	}
	ca, err := loadOrCreateCA(dir)
	if err != nil {
		u.Line(toneFail, "%v", err)
		return 1
	}
	if ca.TrustedBySystem() {
		u.Line(toneOK, "The CA is already trusted.")
		return 0
	}
	if runtime.GOOS != "windows" {
		u.Line(toneInfo, "CA created: %s", ca.CertPath())
		u.Println("  Trust it with your system's tools, for example:")
		switch runtime.GOOS {
		case "darwin":
			u.Println("    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + ca.CertPath())
		default:
			u.Println("    sudo cp " + ca.CertPath() + " /usr/local/share/ca-certificates/ktest-ca.crt && sudo update-ca-certificates")
		}
		return 0
	}
	u.Line(toneInfo, "Windows will ask you to confirm adding the ktest CA to your trusted roots.")
	out, err := exec.Command("certutil", "-user", "-addstore", "-f", "Root", ca.CertPath()).CombinedOutput()
	if err != nil {
		u.Line(toneFail, "certutil failed: %v", err)
		u.Note("%s", lastLines(string(out), 3))
		u.Note("You declined, or it was blocked. Import %s by hand (double-click, Install Certificate, Current User, Trusted Root Certification Authorities).", ca.CertPath())
		return 1
	}
	if !ca.TrustedBySystem() {
		u.Line(toneWarn, "certutil finished but the system does not report the CA as trusted yet.")
		return 1
	}
	u.Line(toneOK, "Local CA trusted. Restart the browser to test optional website fronting. This does not establish a WARP tunnel or guarantee any site's reachability.")
	u.Note("Firefox: set security.enterprise_roots.enabled to true in about:config.")
	return 0
}

// caRemove stops trusting the CA, and with del also deletes its files.
func caRemove(u *term, del bool) int {
	dir := caDir()
	_, certErr := os.Stat(filepath.Join(dir, front.CertFile))
	_, keyErr := os.Stat(filepath.Join(dir, front.KeyFile))
	if dir == "" || (os.IsNotExist(certErr) && os.IsNotExist(keyErr)) {
		u.Line(toneInfo, "There is no ktest CA.")
		return 0
	}
	ca, err := front.Load(dir)
	if err == nil && runtime.GOOS == "windows" {
		out, cerr := exec.Command("certutil", "-user", "-delstore", "Root", ca.Fingerprint()).CombinedOutput()
		if cerr != nil && ca.TrustedBySystem() {
			u.Line(toneFail, "certutil could not remove it: %v", cerr)
			u.Note("%s", lastLines(string(out), 3))
			return 1
		}
		u.Line(toneOK, "The ktest CA is no longer trusted.")
	}
	if del {
		for _, name := range []string{front.CertFile, front.KeyFile} {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
				u.Line(toneFail, "cannot delete %s: %v", name, err)
				return 1
			}
		}
		u.Line(toneOK, "Deleted the CA certificate and private key from %s.", dir)
	}
	return 0
}

func loadOrCreateCA(dir string) (*front.CA, error) {
	if front.Exists(dir) {
		return front.Load(dir)
	}
	return front.Create(dir, front.PermittedDomains(front.DefaultFamilies()))
}

// caMissing lists the domains this ktest can front that the CA may not sign.
func caMissing(ca *front.CA) []string {
	return front.Uncovered(front.DefaultFamilies(), ca.Permitted())
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "...")
	}
	return s
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, " | "))
}

// frontSetup returns to Setup on Enter or Ctrl+C; trust changes require an
// explicit action here and remain subject to the operating system's approval.
func (t *terminal) frontSetup(readLine func() (string, bool)) bool {
	u := t.ui
	for {
		caStatus(u)
		status := inspectCertificate()
		switch status.state {
		case "ok", "outdated":
			u.Printf("  Type RENEW to replace and install the certificate, REMOVE to delete it, or Enter to go back > ")
			ans, ok := readLine()
			if !ok {
				return false
			}
			if ans == "" || isBackChoice(ans) {
				return true
			}
			switch strings.ToUpper(ans) {
			case "RENEW":
				if caRemove(u, true) == 0 {
					caInstall(u)
				}
			case "REMOVE":
				caRemove(u, true)
			default:
				u.Line(toneWarn, "Select RENEW, REMOVE, or 0 to go back.")
			}
		case "invalid":
			u.Printf("  Repair the files shown above; Enter / 0 = back > ")
			ans, ok := readLine()
			if !ok {
				return false
			}
			if ans == "" || isBackChoice(ans) {
				return true
			}
			u.Line(toneWarn, "Press Enter or 0 to go back.")
		default:
			u.Printf("  Type y to create/install trust (Windows asks for confirmation), or Enter to go back > ")
			ans, ok := readLine()
			if !ok {
				return false
			}
			if ans == "" || isBackChoice(ans) {
				return true
			}
			if isYes(ans) || strings.EqualFold(ans, "INSTALL") {
				caInstall(u)
			} else {
				u.Line(toneWarn, "Select y, or 0 to go back.")
			}
		}
	}
}

type certificateStatus struct {
	state, detail string
	ca            *front.CA
}

func inspectCertificate() certificateStatus {
	dir := caDir()
	if dir == "" {
		return certificateStatus{state: "invalid", detail: "configuration directory unavailable"}
	}
	_, certErr := os.Stat(filepath.Join(dir, front.CertFile))
	_, keyErr := os.Stat(filepath.Join(dir, front.KeyFile))
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		return certificateStatus{state: "missing"}
	}
	ca, err := front.Load(dir)
	if err != nil {
		return certificateStatus{state: "invalid", detail: err.Error()}
	}
	return classifyCertificate(ca, ca.TrustedBySystem(), time.Now())
}

func classifyCertificate(ca *front.CA, trusted bool, now time.Time) certificateStatus {
	status := certificateStatus{state: "outdated", ca: ca}
	switch {
	case !ca.ValidAt(now):
		status.detail = "certificate is expired or not yet valid; check the system clock"
	case ca.Expires().Sub(now) <= 30*24*time.Hour:
		status.detail = "expires within 30 days"
	case len(caMissing(ca)) > 0:
		status.detail = "new fronting domains need a replacement certificate"
	case !trusted:
		status.state = "untrusted"
	default:
		status.state = "ok"
	}
	return status
}

func (s certificateStatus) summary(u *term) string {
	switch s.state {
	case "ok":
		return u.Green("Installed / trusted / up to date")
	case "outdated":
		return u.Yellow("Renew - " + s.detail)
	case "untrusted":
		return u.Yellow("Install trust - not trusted by this system")
	case "invalid":
		return u.Red("Repair - certificate files cannot be used")
	default:
		return "Install - not set up"
	}
}

// certState includes validity dates, supported domains and system trust.
func certState() string { return inspectCertificate().state }

// ensureCert leaves a trusted, up-to-date certificate behind, creating or
// renewing it as needed. Windows asks the user to confirm the trust step.
func ensureCert(u *term) bool {
	switch certState() {
	case "ok":
		u.Line(toneOK, "The ktest certificate is set up.")
		return true
	case "outdated":
		u.Line(toneInfo, "The certificate needs renewal for its validity period or supported sites.")
		if caRemove(u, true) != 0 {
			return false
		}
	}
	return caInstall(u) == 0
}

const elevatedSessionArg = "-internal-elevated-session"

// Carry the full effective policy across UAC, including saved AI additions.
// Windows may use a different administrator's profile for the child process.
func elevatedConnectArgs(o connectOptions) []string {
	args := []string{"connect", elevatedSessionArg}
	connectFlagSet(&o).VisitAll(func(f *flag.Flag) {
		if f.Name != "cert" {
			args = append(args, "-"+f.Name+"="+f.Value.String())
		}
	})
	return args
}

// relaunchElevated asks Windows to reopen the chosen policy with Administrator rights.
func relaunchElevated(u *term, o connectOptions) int {
	args := elevatedConnectArgs(o)
	u.Line(toneInfo, "The system-wide tunnel needs Administrator. Windows will ask for permission and open a new window.")
	if err := systemtun.Elevate(args); err != nil {
		u.Line(toneFail, "%v", err)
		u.Note("Open the terminal as Administrator and run the same command again.")
		return 1
	}
	u.Line(toneOK, "Continue in the new window. This one can be closed.")
	return 0
}
