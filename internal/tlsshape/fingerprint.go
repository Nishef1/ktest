// Package tlsshape is F&F (Fragment + Fingerprint) for Aether's MASQUE
// handshakes, and the choice of their server name (--masque-sni): which
// ClientHello the core sends, how its first flight is cut, and which name it
// carries. Fingerprints are PattNG's (AetherFingerprint in PattNG's
// AetherOption.kt): only the TLS 1.2 cipher suites and GREASE change, which is
// all Aether's BoringSSL lets a caller change (--tls-ciphers,
// --disable-grease). Fragments are Aether's own --fragment ranges and PattNG's
// exit-node finalMask presets. What passes is a property of the network, so
// by default ktest measures it (Calibrate) instead of picking for the user.
package tlsshape

import "strings"

// Fingerprint is one ClientHello of PattNG's list.
type Fingerprint struct {
	Name    string
	Title   string
	Ciphers string // Aether's --tls-ciphers: the TLS 1.2 suites, BoringSSL names
	Grease  bool
	// ids are the same TLS 1.2 suites in the order the core offers them, for
	// the calibration ClientHello.
	ids []uint16
}

const (
	Chrome     = "chrome"
	Firefox    = "firefox"
	SemiPython = "semi-python"
	Go         = "go"
)

// Fingerprints in PattNG's menu order. Chrome is the core's default.
var Fingerprints = []Fingerprint{
	{Name: Chrome, Title: "Chrome", Ciphers: "ALL:!aPSK:!ECDSA+SHA1:!3DES", Grease: true,
		ids: []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}},
	{Name: Firefox, Title: "Firefox",
		Ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" +
			"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:" +
			"AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
		ids: []uint16{0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}},
	// Python's first ten TLS 1.2 suites, AES-256-CBC-SHA in place of the
	// SHA-384 CBC suites BoringSSL lacks; Patterniha's choice for MASQUE H2.
	{Name: SemiPython, Title: "Semi-Python",
		Ciphers: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
			"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:" +
			"ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
		ids: []uint16{0xc02c, 0xc030, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc014, 0xc023, 0xc027}},
	{Name: Go, Title: "Go",
		Ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
			"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:" +
			"ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA",
		ids: []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014}},
}

// FingerprintByName finds a fingerprint by its PattNG name.
func FingerprintByName(name string) (Fingerprint, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, f := range Fingerprints {
		if f.Name == name {
			return f, true
		}
	}
	return Fingerprint{}, false
}

// Args are the core options of this fingerprint. Chrome is the core's own
// default and adds none, so existing profiles keep their identity.
func (f Fingerprint) Args() []string {
	if f.Name == Chrome || f.Name == "" {
		return nil
	}
	args := []string{"--tls-ciphers", f.Ciphers}
	if !f.Grease {
		args = append(args, "--disable-grease")
	}
	return args
}

// fingerprintOfArgs names the fingerprint a profile's arguments select.
func fingerprintOfArgs(ciphers string) string {
	if ciphers == "" {
		return Chrome
	}
	for _, f := range Fingerprints {
		if f.Ciphers == ciphers {
			return f.Name
		}
	}
	return "custom"
}
