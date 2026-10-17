package aether

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/pelletier/go-toml/v2"
	"io"
	"net"
	"os"
	"time"
)

// Match Aether v2.3.0's persisted identity, without logging credentials or
// asking Aether to load it (Aether can rename damaged files or call the API).
func CheckIdentity(path, protocol string) error {
	if protocol != "masque" && protocol != "wg" {
		return errors.New("identity protocol must be masque or wg")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return errors.New("identity cannot be read")
	}
	var id struct {
		Device  string `toml:"device_id"`
		Token   string `toml:"access_token"`
		IPv4    string `toml:"ipv4"`
		IPv6    string `toml:"ipv6"`
		Private string `toml:"wg_private_key"`
		Peer    string `toml:"wg_peer_public_key"`
		Cert    string `toml:"cert_pem"`
		Key     string `toml:"key_pem"`
	}
	if len(data) > 1<<20 || toml.Unmarshal(data, &id) != nil {
		return errors.New("invalid identity TOML; saved file kept")
	}
	if id.Device == "" || id.Token == "" || net.ParseIP(id.IPv4) == nil || (id.IPv6 != "" && net.ParseIP(id.IPv6) == nil) {
		return errors.New("identity is incomplete; saved file kept")
	}
	for _, key := range []string{id.Private, id.Peer} {
		b, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(b) != 32 {
			return errors.New("invalid WireGuard key; saved file kept")
		}
	}
	if protocol == "masque" {
		pair, err := tls.X509KeyPair([]byte(id.Cert), []byte(id.Key))
		if err != nil {
			return errors.New("invalid MASQUE certificate/key pair; saved file kept")
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		now := time.Now()
		if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return errors.New("MASQUE certificate expired or not yet valid; check the clock or explicitly remove and register again")
		}
	}
	return nil
}
