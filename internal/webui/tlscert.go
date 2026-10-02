package webui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// certificate loads the UI's TLS certificate: web-ui-cert/web-ui-key if
// given, else a self-signed one made on first start and kept next to
// server.conf (web-ui.crt, web-ui.key), so the browser's exception for it
// stays valid. If that directory is read-only, the certificate lives only
// as long as the process.
func certificate(o *Options, log *slog.Logger) (tls.Certificate, error) {
	if o.CertFile != "" {
		c, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return c, fmt.Errorf("web-ui-cert/web-ui-key: %w", err)
		}
		return c, nil
	}
	var certFile, keyFile string
	if o.ConfigDir != "" {
		certFile, keyFile = filepath.Join(o.ConfigDir, "web-ui.crt"), filepath.Join(o.ConfigDir, "web-ui.key")
		if c, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
			return c, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return c, fmt.Errorf("web UI certificate: %w", err)
		}
	}
	certPEM, keyPEM, err := selfSigned()
	if err != nil {
		return tls.Certificate{}, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return c, err
	}
	saved := false
	if certFile != "" {
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err == nil {
			if err := os.WriteFile(certFile, certPEM, 0o644); err == nil {
				saved = true
			} else {
				os.Remove(keyFile)
			}
		}
	}
	fp := sha256.Sum256(c.Certificate[0])
	if saved {
		log.Info("web UI: created a self-signed TLS certificate", "file", certFile, "sha256", fingerprint(fp[:]))
	} else {
		log.Warn("web UI: using a temporary self-signed TLS certificate (no writable directory to keep it in; set web-ui-cert and web-ui-key)",
			"sha256", fingerprint(fp[:]))
	}
	return c, nil
}

func selfSigned() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: "softvpn web UI"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

func fingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}
