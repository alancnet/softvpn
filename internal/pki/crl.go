package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrRevoked is returned (wrapped) for a certificate listed in the CRL.
var ErrRevoked = errors.New("certificate revoked")

// ParseCRL parses a certificate revocation list in PEM or DER form.
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	if b, _ := pem.Decode(data); b != nil {
		if b.Type != "X509 CRL" {
			return nil, fmt.Errorf("expected an X509 CRL, found %s", b.Type)
		}
		data = b.Bytes
	}
	return x509.ParseRevocationList(data)
}

// CRL is a revocation list file (crl-verify) checked against client
// certificates. It notices when the file changes and re-reads it, so
// revoking a certificate takes effect without a restart.
//
// Like OpenVPN, it fails closed: while the file is missing or invalid, every
// certificate is rejected. Its nextUpdate time is not enforced.
type CRL struct {
	path    string
	issuers []*x509.Certificate

	mu      sync.Mutex
	stamp   os.FileInfo
	revoked map[string]bool // serial numbers (decimal)
	err     error
}

// OpenCRL loads a CRL file, which must be signed by one of the certificates
// in caPEM.
func OpenCRL(path string, caPEM []byte) (*CRL, error) {
	c := &CRL{path: path}
	for rest := caPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
			c.issuers = append(c.issuers, cert)
		}
	}
	if len(c.issuers) == 0 {
		return nil, errors.New("no CA certificates to verify the CRL with")
	}
	if _, err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// Path is the CRL file.
func (c *CRL) Path() string { return c.path }

// Reload re-reads the file if it changed. It reports whether it did, and
// the error if the new contents are unusable.
func (c *CRL) Reload() (changed bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reload()
}

func (c *CRL) reload() (bool, error) {
	fi, err := os.Stat(c.path)
	if err == nil && c.stamp != nil && c.err == nil && sameFile(c.stamp, fi) {
		return false, nil
	}
	if err == nil {
		var revoked map[string]bool
		if revoked, err = c.load(); err == nil {
			c.stamp, c.revoked, c.err = fi, revoked, nil
			return true, nil
		}
	}
	err = fmt.Errorf("crl-verify %s: %w", c.path, err)
	changed := c.err == nil
	c.stamp, c.revoked, c.err = nil, nil, err
	return changed, err
}

func (c *CRL) load() (map[string]bool, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, err
	}
	rl, err := ParseCRL(data)
	if err != nil {
		return nil, err
	}
	var sigErr error
	for _, ca := range c.issuers {
		if sigErr = rl.CheckSignatureFrom(ca); sigErr == nil {
			break
		}
	}
	if sigErr != nil {
		return nil, fmt.Errorf("not signed by the CA: %w", sigErr)
	}
	revoked := map[string]bool{}
	for _, e := range rl.RevokedCertificateEntries {
		revoked[e.SerialNumber.String()] = true
	}
	return revoked, nil
}

func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// Len is the number of revoked certificates.
func (c *CRL) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.revoked)
}

// Check returns an error wrapping ErrRevoked if cert is revoked, or another
// error if the CRL is currently unusable.
func (c *CRL) Check(cert *x509.Certificate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if c.err != nil {
		return c.err
	}
	if c.revoked[cert.SerialNumber.String()] {
		return fmt.Errorf("%w: %q (serial %X)", ErrRevoked, cert.Subject.CommonName, cert.SerialNumber)
	}
	return nil
}

// CRLFile is the revocation list a Dir maintains, for crl-verify.
const CRLFile = "crl.pem"

// Revoked lists the revocations in the directory's CRL (none if there is
// no CRL yet).
func (d Dir) Revoked() ([]x509.RevocationListEntry, error) {
	data, err := d.Read(CRLFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rl, err := ParseCRL(data)
	if err != nil {
		return nil, err
	}
	return rl.RevokedCertificateEntries, nil
}

// WriteCRL (re)signs the directory's CRL with the CA, keeping the existing
// entries and adding extra ones. Servers using it with crl-verify pick up
// the new file without a restart.
func (d Dir) WriteCRL(validity time.Duration, extra ...x509.RevocationListEntry) error {
	ca, err := d.LoadCA()
	if err != nil {
		return err
	}
	number := big.NewInt(1)
	var entries []x509.RevocationListEntry
	if data, err := d.Read(CRLFile); err == nil {
		rl, err := ParseCRL(data)
		if err != nil {
			return fmt.Errorf("%s: %w", d.path(CRLFile), err)
		}
		if err := rl.CheckSignatureFrom(ca.Cert); err != nil {
			return fmt.Errorf("%s is not signed by this CA: %w", d.path(CRLFile), err)
		}
		entries = rl.RevokedCertificateEntries
		if rl.Number != nil {
			number.Add(rl.Number, big.NewInt(1))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries = append(entries, extra...)
	now := time.Now()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now.Add(-time.Hour),
		NextUpdate:                now.Add(validity),
		RevokedCertificateEntries: entries,
	}, ca.Cert, ca.Key)
	if err != nil {
		return err
	}
	return d.replace(CRLFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644)
}

// replace writes a file atomically, so readers see the old or the new
// contents, never a partial file.
func (d Dir) replace(name string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(d.Path, "."+name+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), d.path(name))
}

// Revoke revokes the client certificate NAME.crt: it adds it to the CRL and
// moves NAME.crt, NAME.key and NAME.ovpn to revoked/NAME-SERIAL.*, so the
// name can be issued again.
func (d Dir) Revoke(name string, crlValidity time.Duration) error {
	if name == "" || name == "ca" || filepath.Base(name) != name {
		return fmt.Errorf("invalid certificate name %q", name)
	}
	cert, err := d.Certificate(name)
	if err != nil {
		return err
	}
	ca, err := d.LoadCA()
	if err != nil {
		return err
	}
	if cert.CheckSignatureFrom(ca.Cert) != nil {
		return fmt.Errorf("%s.crt was not issued by this CA", name)
	}
	if err := d.WriteCRL(crlValidity, x509.RevocationListEntry{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
	}); err != nil {
		return err
	}
	if err := os.MkdirAll(d.path("revoked"), 0o755); err != nil {
		return err
	}
	base := fmt.Sprintf("%s-%X", name, cert.SerialNumber)
	for _, ext := range []string{".crt", ".key", ".ovpn"} {
		if d.Exists(name + ext) {
			if err := os.Rename(d.path(name+ext), d.path(filepath.Join("revoked", base+ext))); err != nil {
				return err
			}
		}
	}
	return nil
}

// Certificate loads NAME.crt.
func (d Dir) Certificate(name string) (*x509.Certificate, error) {
	data, err := d.Read(name + ".crt")
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s.crt: no certificate found", name)
	}
	return x509.ParseCertificate(b.Bytes)
}

// CertInfo describes an issued certificate.
type CertInfo struct {
	Name      string // file name without .crt
	Serial    *big.Int
	NotAfter  time.Time
	Client    bool // issued for client use (as opposed to the server)
	Revoked   bool
	RevokedAt time.Time
}

// List returns the certificates issued from this directory: the current
// NAME.crt files and the revoked ones kept under revoked/.
func (d Dir) List() ([]CertInfo, error) {
	revoked, err := d.Revoked()
	if err != nil {
		return nil, err
	}
	when := map[string]time.Time{}
	for _, e := range revoked {
		when[e.SerialNumber.String()] = e.RevocationTime
	}
	var out []CertInfo
	for _, dir := range []string{"", "revoked"} {
		files, _ := filepath.Glob(filepath.Join(d.Path, dir, "*.crt"))
		for _, f := range files {
			name := strings.TrimSuffix(filepath.Base(f), ".crt")
			if name == "ca" {
				continue
			}
			cert, err := Dir{Path: filepath.Dir(f)}.Certificate(name)
			if err != nil {
				return nil, err
			}
			if dir == "revoked" {
				name = strings.TrimSuffix(name, fmt.Sprintf("-%X", cert.SerialNumber))
			}
			ci := CertInfo{Name: name, Serial: cert.SerialNumber, NotAfter: cert.NotAfter}
			for _, u := range cert.ExtKeyUsage {
				ci.Client = ci.Client || u == x509.ExtKeyUsageClientAuth
			}
			ci.RevokedAt, ci.Revoked = when[cert.SerialNumber.String()]
			out = append(out, ci)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
