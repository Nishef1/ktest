package front

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// File names inside the CA directory.
const (
	CertFile = "ktest-ca.crt"
	KeyFile  = "ktest-ca.key"
	caName   = "ktest local CA (limited to fronted sites)"
)

// DefaultDir is where the CA lives: the per-user configuration directory, not
// the program folder, so that the private key is never zipped or copied along
// with the portable package. KTEST_CA_DIR overrides it.
func DefaultDir() (string, error) {
	if d := os.Getenv("KTEST_CA_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "ktest", "ca"), nil
}

// CA is ktest's own certificate authority. It exists only so that an
// application can talk TLS to ktest while ktest talks to the real site with a
// different server name (domain fronting needs to read the request).
//
// It is deliberately weak as an attack tool: it is name-constrained (X.509
// name constraints, marked critical) to the sites ktest can front, so even a
// leaked key cannot impersonate a bank or a mail provider that is not on the
// list, in any browser or operating system that honors constraints.
type CA struct {
	Dir  string
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*leaf
}

type leaf struct {
	cert    *tls.Certificate
	expires time.Time
}

// Exists reports whether a CA was created in dir.
func Exists(dir string) bool {
	_, err1 := os.Stat(filepath.Join(dir, CertFile))
	_, err2 := os.Stat(filepath.Join(dir, KeyFile))
	return err1 == nil && err2 == nil
}

// Create makes a new CA constrained to permitted (each entry covers the domain
// and its subdomains) and writes it to dir. It refuses to replace an existing
// CA: that would silently invalidate the one the user already trusts.
func Create(dir string, permitted []string) (*CA, error) {
	if Exists(dir) {
		return nil, fmt.Errorf("a CA already exists in %s", dir)
	}
	if len(permitted) == 0 {
		return nil, errors.New("a CA without any permitted domain would be unconstrained")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: caName, Organization: []string{"ktest"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(2, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return Load(dir)
}

// Load reads the CA from dir.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("CA files are not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("the CA key does not belong to the CA certificate")
	}
	if !cert.IsCA || len(cert.PermittedDNSDomains) == 0 {
		return nil, errors.New("the CA is not name-constrained; refusing to use it (delete the folder and create a new one)")
	}
	return &CA{Dir: dir, cert: cert, der: cb.Bytes, key: key, leaves: map[string]*leaf{}}, nil
}

// CertPath is the file the user imports into a trust store.
func (c *CA) CertPath() string { return filepath.Join(c.Dir, CertFile) }

// Name is the certificate's subject, which Windows shows and certutil needs to
// remove it again.
func (c *CA) Name() string { return c.cert.Subject.CommonName }

// Fingerprint is the SHA-1 thumbprint Windows tools display.
func (c *CA) Fingerprint() string {
	sum := sha1.Sum(c.der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Expires is when the CA stops being valid.
func (c *CA) Expires() time.Time { return c.cert.NotAfter }

// ValidAt includes the CA's activation time, not just its expiry date.
func (c *CA) ValidAt(now time.Time) bool {
	return !now.Before(c.cert.NotBefore) && now.Before(c.cert.NotAfter)
}

// Permitted lists the domains the CA may issue for.
func (c *CA) Permitted() []string { return append([]string(nil), c.cert.PermittedDNSDomains...) }

// Permits reports whether the CA's constraints allow issuing for host. A
// family added to ktest after the CA was created is simply not fronted until
// the user creates a new CA.
func (c *CA) Permits(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range c.cert.PermittedDNSDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Leaf returns a short-lived certificate for host, signed by the CA.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !c.Permits(host) {
		return nil, fmt.Errorf("%s is outside the CA's name constraints", host)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.leaves[host]; ok && time.Until(l.expires) > 12*time.Hour {
		return l.cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(72 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	c.leaves[host] = &leaf{cert: cert, expires: tmpl.NotAfter}
	if len(c.leaves) > 2048 {
		for h, l := range c.leaves {
			if time.Until(l.expires) < 24*time.Hour {
				delete(c.leaves, h)
			}
		}
	}
	return cert, nil
}

// TrustedBySystem reports whether the operating system's trust store accepts
// certificates from this CA. That is what browsers other than Firefox use, and
// the only honest answer to "will an application accept what ktest presents".
func (c *CA) TrustedBySystem() bool {
	l, err := c.Leaf("www.youtube.com")
	if err != nil {
		return false
	}
	cert, err := x509.ParseCertificate(l.Certificate[0])
	if err != nil {
		return false
	}
	_, err = cert.Verify(x509.VerifyOptions{DNSName: "www.youtube.com"})
	return err == nil
}

// Pool returns a certificate pool holding only this CA (for tests and checks).
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
