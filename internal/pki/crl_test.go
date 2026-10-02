package pki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func loadCert(t *testing.T, d Dir, name string) *x509.Certificate {
	t.Helper()
	c, err := d.Certificate(name)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRevokeAndCRL(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	const year = 365 * 24 * time.Hour
	if err := d.Init("server", nil, year); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", "bob"} {
		if err := d.Issue(n, RoleClient, nil, year); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.WriteProfile("alice", "vpn.example.com", 1194, "udp"); err != nil {
		t.Fatal(err)
	}
	alice, bob := loadCert(t, d, "alice"), loadCert(t, d, "bob")
	caPEM, _ := d.Read("ca.crt")

	// Init writes an empty CRL so crl-verify works from the start.
	crl, err := OpenCRL(d.path(CRLFile), caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.Check(alice); err != nil {
		t.Fatalf("before revoking: %v", err)
	}

	time.Sleep(10 * time.Millisecond) // distinct mtime
	if err := d.Revoke("alice", year); err != nil {
		t.Fatal(err)
	}
	if err := crl.Check(alice); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after revoking: Check = %v, want ErrRevoked", err)
	}
	if err := crl.Check(bob); err != nil {
		t.Fatalf("bob: %v", err)
	}
	if d.Exists("alice.crt") || d.Exists("alice.key") || d.Exists("alice.ovpn") {
		t.Fatal("revoked files left in place")
	}
	// The name can be issued again, and the new certificate is valid.
	if err := d.Issue("alice", RoleClient, nil, year); err != nil {
		t.Fatal(err)
	}
	if err := crl.Check(loadCert(t, d, "alice")); err != nil {
		t.Fatalf("reissued alice: %v", err)
	}
	if err := d.Revoke("bob", year); err != nil {
		t.Fatal(err)
	}
	if err := crl.Check(alice); !errors.Is(err, ErrRevoked) {
		t.Fatal("earlier revocation lost when re-signing the CRL")
	}
	if crl.Len() != 2 {
		t.Fatalf("Len = %d", crl.Len())
	}

	list, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range list {
		s := c.Name
		if c.Revoked {
			s += "(revoked)"
		}
		got = append(got, s)
	}
	if strings.Join(got, " ") != "alice alice(revoked) bob(revoked) server" &&
		strings.Join(got, " ") != "alice(revoked) alice bob(revoked) server" {
		t.Fatalf("List = %v", got)
	}

	// DER works too.
	data, _ := d.Read(CRLFile)
	b, _ := pem.Decode(data)
	der := d.path("crl.der")
	os.WriteFile(der, b.Bytes, 0o644)
	dc, err := OpenCRL(der, caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(dc.Check(bob), ErrRevoked) {
		t.Fatal("DER CRL: bob not revoked")
	}
}

func TestCRLFailsClosed(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if err := d.Init("server", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	d.Issue("alice", RoleClient, nil, time.Hour)
	alice := loadCert(t, d, "alice")
	caPEM, _ := d.Read("ca.crt")
	crl, err := OpenCRL(d.path(CRLFile), caPEM)
	if err != nil {
		t.Fatal(err)
	}

	// A CRL from another CA is rejected.
	other := Dir{Path: t.TempDir()}
	other.Init("server", nil, time.Hour)
	foreign, _ := other.Read(CRLFile)
	if _, err := OpenCRL(other.path(CRLFile), caPEM); err == nil {
		t.Fatal("CRL signed by another CA accepted")
	}
	os.WriteFile(d.path(CRLFile), foreign, 0o644)
	if err := crl.Check(alice); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("foreign CRL: Check = %v, want a load error", err)
	}
	os.Remove(d.path(CRLFile))
	if err := crl.Check(alice); err == nil {
		t.Fatal("missing CRL: certificate accepted")
	}
	if err := d.WriteCRL(time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := crl.Check(alice); err != nil {
		t.Fatalf("restored CRL: %v", err)
	}
}

func TestProfileOptions(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	d.Init("server", nil, time.Hour)
	d.Issue("alice", RoleClient, nil, time.Hour)
	p, err := d.Profile("alice", "vpn", 1194, "udp", ProfileOptions{AuthUserPass: true})
	if err != nil || !strings.Contains(p, "\nauth-user-pass\n") || !strings.Contains(p, "<cert>") {
		t.Fatalf("auth-user-pass profile: %v\n%s", err, p)
	}
	p, err = d.Profile("nocert", "vpn", 1194, "tcp", ProfileOptions{NoCert: true})
	if err != nil || !strings.Contains(p, "\nauth-user-pass\n") || strings.Contains(p, "<cert>") || strings.Contains(p, "<key>") {
		t.Fatalf("cert-less profile: %v\n%s", err, p)
	}
	if p, _ := d.Profile("alice", "vpn", 1194, "udp"); strings.Contains(p, "auth-user-pass") {
		t.Fatal("plain profile asks for a password")
	}
}
