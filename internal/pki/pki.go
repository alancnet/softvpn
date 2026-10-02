// Package pki provides a minimal certificate authority (the softvpn
// equivalent of easy-rsa), the server's TLS configuration, and client
// profile (.ovpn) generation.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Role selects the extended key usage of an issued certificate. Servers only
// accept certificates with ClientAuth, and clients only accept ServerAuth,
// so a client certificate can never impersonate the server (the equivalent
// of OpenVPN's remote-cert-tls).
type Role int

const (
	RoleServer Role = iota
	RoleClient
)

// CA is a loaded certificate authority.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func encodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// NewCA creates a self-signed CA.
func NewCA(name string, validity time.Duration) (*CA, []byte, error) {
	key, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: encodeCert(der)}, keyPEM, nil
}

// LoadCA reads a CA certificate and key from PEM.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA key must be ECDSA")
	}
	if !cert.IsCA {
		return nil, errors.New("certificate is not a CA")
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

// Issue signs a new leaf certificate. For servers, sans may contain DNS
// names and IP addresses the server is reachable at (optional: OpenVPN
// clients check the CA chain and, with remote-cert-tls, the role; names are
// only checked with verify-x509-name).
func (ca *CA) Issue(cn string, role Role, sans []string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if role == RoleServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = append(tmpl.DNSNames, cn)
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if s != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return encodeCert(der), keyPEM, nil
}

func certPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("no certificates found in CA bundle")
	}
	return pool, nil
}

// ServerTLS builds the TLS configuration for the OpenVPN control channel:
// every client must present a certificate issued by the CA for client use.
func ServerTLS(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	pool, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("server cert/key: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // also enforces ExtKeyUsageClientAuth
	}, nil
}

// Dir is an on-disk PKI layout: ca.crt, ca.key, NAME.crt, NAME.key and
// NAME.ovpn client profiles.
type Dir struct {
	Path string
	// Shared makes private keys and profiles readable by every user. Only
	// for demos where containers running as different users share a volume.
	Shared bool
}

func (d Dir) path(name string) string { return filepath.Join(d.Path, name) }

func (d Dir) privateMode() os.FileMode {
	if d.Shared {
		return 0o644
	}
	return 0o600
}

// Exists reports whether a file is present in the directory.
func (d Dir) Exists(name string) bool {
	_, err := os.Stat(d.path(name))
	return err == nil
}

func (d Dir) write(name string, data []byte, mode os.FileMode) error {
	p := d.path(name)
	if d.Exists(name) {
		return fmt.Errorf("%s already exists, refusing to overwrite", p)
	}
	return os.WriteFile(p, data, mode)
}

// Init creates the CA and a server certificate.
func (d Dir) Init(serverName string, sans []string, validity time.Duration) error {
	if err := os.MkdirAll(d.Path, 0o755); err != nil {
		return err
	}
	ca, caKey, err := NewCA("softvpn CA", validity)
	if err != nil {
		return err
	}
	if err := d.write("ca.crt", ca.CertPEM, 0o644); err != nil {
		return err
	}
	if err := d.write("ca.key", caKey, 0o600); err != nil {
		return err
	}
	return d.issue(ca, serverName, RoleServer, sans, validity)
}

// Issue creates a certificate signed by the CA in this directory.
func (d Dir) Issue(name string, role Role, sans []string, validity time.Duration) error {
	ca, err := d.LoadCA()
	if err != nil {
		return err
	}
	return d.issue(ca, name, role, sans, validity)
}

func (d Dir) issue(ca *CA, name string, role Role, sans []string, validity time.Duration) error {
	if name == "" || name == "ca" || filepath.Base(name) != name {
		return fmt.Errorf("invalid certificate name %q", name)
	}
	cert, key, err := ca.Issue(name, role, sans, validity)
	if err != nil {
		return err
	}
	if err := d.write(name+".crt", cert, 0o644); err != nil {
		return err
	}
	return d.write(name+".key", key, d.privateMode())
}

func (d Dir) LoadCA() (*CA, error) {
	c, err := os.ReadFile(d.path("ca.crt"))
	if err != nil {
		return nil, err
	}
	k, err := os.ReadFile(d.path("ca.key"))
	if err != nil {
		return nil, err
	}
	return LoadCA(c, k)
}

// Read returns the PEM contents of a file in the directory.
func (d Dir) Read(name string) ([]byte, error) { return os.ReadFile(d.path(name)) }

// Profile renders a .ovpn client profile with the certificates inlined, for
// the stock OpenVPN client. proto is "udp" or "tcp".
func (d Dir) Profile(name, remote string, port int, proto string) (string, error) {
	switch proto {
	case "udp":
	case "tcp":
		proto = "tcp-client"
	default:
		return "", fmt.Errorf("proto must be udp or tcp")
	}
	ca, err := d.Read("ca.crt")
	if err != nil {
		return "", err
	}
	cert, err := d.Read(name + ".crt")
	if err != nil {
		return "", err
	}
	key, err := d.Read(name + ".key")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# softvpn client profile for %q (stock OpenVPN 2.5+ client)\n", name)
	fmt.Fprintf(&b, "client\ndev tun\nproto %s\nremote %s %d\n", proto, remote, port)
	b.WriteString("nobind\nresolv-retry infinite\npersist-key\nremote-cert-tls server\nverb 3\n")
	fmt.Fprintf(&b, "<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", ca, cert, key)
	return b.String(), nil
}

// WriteProfile writes NAME.ovpn into the directory, replacing any old one.
func (d Dir) WriteProfile(name, remote string, port int, proto string) error {
	p, err := d.Profile(name, remote, port, proto)
	if err != nil {
		return err
	}
	return os.WriteFile(d.path(name+".ovpn"), []byte(p), d.privateMode())
}
