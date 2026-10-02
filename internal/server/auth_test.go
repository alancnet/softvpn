package server

import (
	"crypto/tls"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/pki"
	"github.com/softvpn/softvpn/internal/users"
)

func testPKI(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	if err := (pki.Dir{Path: dir}).Init("server", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	return dir
}

func load(dir, extra string) (*Config, error) {
	c, err := config.ParseString("ca " + dir + "/ca.crt\ncert " + dir + "/server.crt\nkey " + dir + "/server.key\n" + extra)
	if err != nil {
		return nil, err
	}
	return Load(c)
}

func TestAuthDirectives(t *testing.T) {
	dir := testPKI(t)
	usersFile := filepath.Join(dir, "users")
	if err := users.Add(usersFile, "alice", "pw"); err != nil {
		t.Fatal(err)
	}

	cfg, err := load(dir, "auth-user-pass-file "+usersFile+"\nverify-client-cert none\nusername-as-common-name\nauth-gen-token 3600\ncrl-verify "+dir+"/crl.pem\n")
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Auth
	if a.Users == nil || a.CRL == nil || !a.UsernameAsCommonName || !a.AuthGenToken || a.TokenLifetime != time.Hour {
		t.Fatalf("auth config: %+v", a)
	}
	if cfg.TLS.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v", cfg.TLS.ClientAuth)
	}
	cfg, err = load(dir, "auth-user-pass-file "+usersFile+"\nverify-client-cert optional\n")
	if err != nil || cfg.TLS.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("optional: %v", err)
	}
	cfg, err = load(dir, "")
	if err != nil || cfg.TLS.ClientAuth != tls.RequireAndVerifyClientCert || cfg.Auth.Users != nil {
		t.Fatalf("default: %v", err)
	}

	for extra, want := range map[string]string{
		"plugin /usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so login": "auth-user-pass-file",
		"auth-user-pass-verify /etc/openvpn/check.sh via-file":             "auth-user-pass-file",
		"client-connect /bin/true":                                         "no shell",
		"verify-client-cert none":                                          "add auth-user-pass-file",
		"username-as-common-name":                                          "needs auth-user-pass-file",
		"auth-user-pass-file " + dir + "/missing":                          "softvpn user add",
		"crl-verify " + dir + "/missing":                                   "crl-verify",
		"crl-verify " + dir + " dir":                                       "dir",
	} {
		if _, err := load(dir, extra); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want it to mention %q", extra, err, want)
		}
	}
}

func TestAuthToken(t *testing.T) {
	dir := testPKI(t)
	usersFile := filepath.Join(dir, "users")
	users.Add(usersFile, "alice", "pw")
	cfg, err := load(dir, "auth-user-pass-file "+usersFile+"\nauth-gen-token 60\n")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	issued := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	tok, ok := s.makeToken("alice", issued)
	if !ok || !strings.HasPrefix(tok, tokenPrefix) {
		t.Fatalf("token %q", tok)
	}
	if got, err := s.verifyToken("alice", tok); err != nil || !got.Equal(issued) {
		t.Fatalf("verify: %v, %v (issued %v)", got, err, issued)
	}
	if _, err := s.verifyToken("bob", tok); err == nil {
		t.Fatal("token accepted for another user")
	}
	b := []byte(tok)
	i := len(tokenPrefix) + 20
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := s.verifyToken("alice", string(b)); err == nil {
		t.Fatal("tampered token accepted")
	}
	old, _ := s.makeToken("alice", time.Now().Add(-2*time.Minute))
	if _, err := s.verifyToken("alice", old); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token: %v", err)
	}
	// Changing the password invalidates outstanding tokens.
	time.Sleep(10 * time.Millisecond)
	users.SetPassword(usersFile, "alice", "pw2")
	if _, err := s.verifyToken("alice", tok); err == nil {
		t.Fatal("token survived a password change")
	}
}
