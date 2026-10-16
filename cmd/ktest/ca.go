package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

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
	if dir == "" || !front.Exists(dir) {
		u.Line(toneInfo, "No CA yet. It is optional; without it Connect still works with every other method.")
		u.Note("`ktest ca -install` creates it and asks Windows to trust it for your user.")
		return
	}
	ca, err := front.Load(dir)
	if err != nil {
		u.Line(toneFail, "The CA in %s cannot be used: %v", dir, err)
		u.Note("`ktest ca -delete` removes it; `ktest ca -install` makes a new one.")
		return
	}
	u.Line(toneInfo, "CA folder    %s", dir)
	u.Line(toneInfo, "Thumbprint   %s   expires %s", ca.Fingerprint(), ca.Expires().Format("2006-01-02"))
	u.Line(toneInfo, "Limited to   %d domains (it cannot vouch for any other site, even if its key leaks)", len(ca.Permitted()))
	if missing := caMissing(ca); len(missing) > 0 {
		u.Line(toneWarn, "This CA predates %d site(s) this ktest can front: %s", len(missing), strings.Join(firstN(missing, 6), ", "))
		u.Note("`ktest ca -renew` replaces it by one that covers them (a CA's constraints cannot be extended).")
	}
	if ca.TrustedBySystem() {
		u.Line(toneOK, "Trusted by this system: Connect will use domain fronting for Google, YouTube, Meta and Fastly-hosted sites.")
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
	u.Line(toneOK, "Trusted. Restart the browser, then run Connect: Google, YouTube and Meta sites will use domain fronting.")
	u.Note("Firefox: set security.enterprise_roots.enabled to true in about:config.")
	return 0
}

// caRemove stops trusting the CA, and with del also deletes its files.
func caRemove(u *term, del bool) int {
	dir := caDir()
	if dir == "" || !front.Exists(dir) {
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
		if err := os.RemoveAll(dir); err != nil {
			u.Line(toneFail, "cannot delete %s: %v", dir, err)
			return 1
		}
		u.Line(toneOK, "Deleted %s (the key is gone).", dir)
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

// frontSetup is the Advanced menu entry for the CA: show the state, then offer
// the one step that makes sense. Windows asks for its own confirmation as well.
func (t *terminal) frontSetup(readLine func() (string, bool)) {
	u := t.ui
	caStatus(u)
	ca, trusted := loadFrontCA()
	switch {
	case ca != nil && trusted && len(caMissing(ca)) > 0:
		u.Printf("  Type RENEW to replace the CA by one covering every site (Windows asks you to confirm), or press Enter to keep it > ")
		if ans, ok := readLine(); ok && strings.EqualFold(ans, "RENEW") {
			if caRemove(u, true) == 0 {
				caInstall(u)
			}
		}
	case ca != nil && trusted:
		u.Printf("  Type REMOVE to stop trusting and delete the CA, or press Enter to keep it > ")
		if ans, ok := readLine(); ok && strings.EqualFold(ans, "REMOVE") {
			caRemove(u, true)
		}
	default:
		u.Printf("  Type YES to create the CA and trust it for your Windows user (Windows asks you to confirm) > ")
		if ans, ok := readLine(); ok && strings.EqualFold(ans, "YES") {
			caInstall(u)
		} else {
			u.Line(toneInfo, "Cancelled; nothing was changed.")
		}
	}
}

// certState says whether the fronting certificate needs attention: "ok",
// "missing", "outdated" (made before this ktest knew more sites) or
// "untrusted" (not accepted by the system store yet).
func certState() string {
	ca, trusted := loadFrontCA()
	switch {
	case ca == nil:
		return "missing"
	case len(caMissing(ca)) > 0:
		return "outdated"
	case !trusted:
		return "untrusted"
	}
	return "ok"
}

// ensureCert leaves a trusted, up-to-date certificate behind, creating or
// renewing it as needed. Windows asks the user to confirm the trust step.
func ensureCert(u *term) bool {
	switch certState() {
	case "ok":
		u.Line(toneOK, "The ktest certificate is set up.")
		return true
	case "outdated":
		u.Line(toneInfo, "The certificate predates sites this ktest can front; renewing it.")
		if caRemove(u, true) != 0 {
			return false
		}
	}
	return caInstall(u) == 0
}

// relaunchElevated reopens this command in an Administrator window; Windows
// shows its own permission prompt, so nothing is elevated without a decision.
func relaunchElevated(u *term, o connectOptions) int {
	args := []string{"connect", "-tun", "-base", o.base, "-listen", o.listen}
	if o.verbose {
		args = append(args, "-v")
	}
	u.Line(toneInfo, "The system-wide tunnel needs Administrator. Windows will ask for permission and open a new window.")
	if err := systemtun.Elevate(args); err != nil {
		u.Line(toneFail, "%v", err)
		u.Note("Open the terminal as Administrator and run the same command again.")
		return 1
	}
	u.Line(toneOK, "Continue in the new window. This one can be closed.")
	return 0
}
