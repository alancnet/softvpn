package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/ovpn"
	"github.com/softvpn/softvpn/internal/pki"
	"github.com/softvpn/softvpn/internal/users"
)

// Authentication directives.
var authDirectives = []string{
	"auth-user-pass-file", "verify-client-cert", "username-as-common-name",
	"auth-user-pass-optional", "auth-gen-token", "auth-gen-token-secret", "crl-verify",
}

// AuthConfig is client authentication beyond the CA check: the built-in
// user database, auth tokens and the CRL.
type AuthConfig struct {
	Users                *users.DB // auth-user-pass-file; nil: certificates only
	VerifyClientCert     string    // "require" (default), "optional" or "none"
	UsernameAsCommonName bool
	AuthUserPassOptional bool          // clients with a certificate may skip the password
	AuthGenToken         bool          // push an auth-token that replaces the password
	TokenLifetime        time.Duration // 0: valid until the server restarts
	TokenSecret          []byte
	CRL                  *pki.CRL // crl-verify
}

// loadAuth parses the authentication directives. tlsConf is adjusted for
// verify-client-cert.
func loadAuth(c *config.Config, caPEM []byte, tlsConf *tls.Config) (AuthConfig, error) {
	a := AuthConfig{VerifyClientCert: "require"}
	if d, ok := c.Last("auth-user-pass-file"); ok {
		if len(d.Args) != 1 {
			return a, d.Errorf("expects one file name")
		}
		db, err := users.Open(d.Path(0))
		if err != nil {
			return a, d.Errorf("%v (create it with: softvpn user add -file %s NAME)", err, d.Arg(0))
		}
		a.Users = db
	}
	if d, ok := c.Last("verify-client-cert"); ok {
		a.VerifyClientCert = strings.ToLower(d.Arg(0))
		switch a.VerifyClientCert {
		case "require":
		case "optional":
			tlsConf.ClientAuth = tls.VerifyClientCertIfGiven
		case "none":
			tlsConf.ClientAuth = tls.NoClientCert
		default:
			return a, d.Errorf("expects none, optional or require")
		}
		if a.VerifyClientCert != "require" && a.Users == nil {
			return a, d.Errorf("clients without a certificate need a password: add auth-user-pass-file")
		}
	}
	a.UsernameAsCommonName = c.Has("username-as-common-name")
	a.AuthUserPassOptional = c.Has("auth-user-pass-optional")
	for _, name := range []string{"username-as-common-name", "auth-user-pass-optional", "auth-gen-token"} {
		if d, ok := c.Last(name); ok && a.Users == nil {
			return a, d.Errorf("needs auth-user-pass-file")
		}
	}
	if d, ok := c.Last("auth-gen-token"); ok {
		a.AuthGenToken = true
		if len(d.Args) > 0 {
			var err error
			if a.TokenLifetime, err = config.Seconds(d.Arg(0)); err != nil {
				return a, d.Errorf("%v", err)
			}
		}
		if d.Arg(2) == "external-auth" {
			return a, d.Errorf("external-auth is not supported")
		}
		a.TokenSecret = randomSecret()
	}
	if d, ok := c.Last("auth-gen-token-secret"); ok {
		b, err := os.ReadFile(d.Path(0))
		if err != nil {
			return a, d.Errorf("%v", err)
		}
		// OpenVPN's format is PEM ("openvpn --genkey auth-token"); any file
		// with enough random bytes will do.
		if p, _ := pem.Decode(b); p != nil {
			b = p.Bytes
		}
		if len(b) < 32 {
			return a, d.Errorf("secret is too short (need at least 32 bytes)")
		}
		a.TokenSecret = b
	}
	if d, ok := c.Last("crl-verify"); ok {
		if len(d.Args) != 1 {
			return a, d.Errorf("expects one file (the \"dir\" form is not supported)")
		}
		crl, err := pki.OpenCRL(d.Path(0), caPEM)
		if err != nil {
			return a, d.Errorf("%v", err)
		}
		a.CRL = crl
	}
	return a, nil
}

// rejectScripts explains why script and plugin hooks can't work and what to
// use instead.
func rejectScripts(c *config.Config) error {
	if d, ok := c.Last("plugin"); ok {
		return d.Errorf("plugins are not supported: softvpn is a static binary with nothing to load them into. " +
			"For username/password authentication use the built-in user database: " +
			"\"auth-user-pass-file FILE\" (manage it with \"softvpn user add -file FILE NAME\")")
	}
	if d, ok := c.Last("auth-user-pass-verify"); ok {
		return d.Errorf("scripts are not supported: the softvpn image has no shell. " +
			"Use the built-in user database instead: \"auth-user-pass-file FILE\" " +
			"(manage it with \"softvpn user add -file FILE NAME\")")
	}
	for _, name := range []string{"client-connect", "client-disconnect", "learn-address", "tls-verify", "up", "down"} {
		if d, ok := c.Last(name); ok {
			return d.Errorf("scripts are not supported: the softvpn image has no shell")
		}
	}
	return nil
}

func randomSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Authenticate implements ovpn.Authenticator. The CA (and CRL) checks have
// already happened in the TLS handshake; this checks the username and
// password, or the auth token that replaces the password after the first
// login.
func (s *Server) Authenticate(ss *ovpn.Session, c *ovpn.Credentials) (string, error) {
	a := &s.cfg.Auth
	cn := ""
	if c.Certificate != nil {
		cn = c.Certificate.Subject.CommonName
	}
	if a.Users == nil {
		if c.Certificate == nil {
			return "", errors.New("client certificate required")
		}
		return cn, nil
	}
	if c.Username == "" && c.Password == "" {
		if a.AuthUserPassOptional && c.Certificate != nil {
			return cn, nil
		}
		return "", errors.New("username and password required (add auth-user-pass to the client profile)")
	}
	if c.Renegotiation && ss.Username() != c.Username {
		return "", errors.New("username changed during renegotiation")
	}

	method, issued := "password", time.Now()
	if a.AuthGenToken && strings.HasPrefix(c.Password, tokenPrefix) {
		var err error
		if issued, err = s.verifyToken(c.Username, c.Password); err != nil {
			s.log.Warn("auth-token rejected", "user", c.Username, "remote", ss.Remote(), "err", err)
			return "", fmt.Errorf("auth-token for %q is invalid or expired", c.Username)
		}
		method = "token"
	} else if err := a.Users.Verify(c.Username, c.Password); err != nil {
		if !errors.Is(err, users.ErrBadCredentials) {
			s.log.Error("auth-user-pass-file", "err", err)
		}
		return "", fmt.Errorf("authentication failed for user %q", c.Username)
	}

	if a.UsernameAsCommonName {
		cn = c.Username
	} else if cn == "" {
		cn = "UNDEF" // what OpenVPN calls a client without a certificate
	}
	if c.Renegotiation {
		s.log.Debug("user re-authenticated", "user", c.Username, "method", method)
		return cn, nil
	}
	s.log.Info("user authenticated", "user", c.Username, "method", method, "remote", ss.Remote())
	if a.AuthGenToken {
		if tok, ok := s.makeToken(c.Username, issued); ok {
			s.mu.Lock()
			s.tokens[ss] = tok
			s.mu.Unlock()
		}
	}
	return cn, nil
}

// takeToken returns (and forgets) the auth-token to push to a session.
func (s *Server) takeToken(ss *ovpn.Session) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tokens[ss]
	delete(s.tokens, ss)
	return t
}

// Auth tokens (auth-gen-token) let a client renegotiate and reconnect without
// the server seeing its password again; OpenVPN clients keep sending the
// token in place of the password. A token is
//
//	SESS_ID_AT_ base64url( issued[8] | HMAC-SHA256(secret, username, password hash, issued) )
//
// so it is bound to the user's current password (changing it, or deleting
// the user, invalidates the token), and carries the time of the original
// password login for the lifetime check. The prefix is OpenVPN's.
const tokenPrefix = "SESS_ID_AT_"

func (s *Server) tokenMAC(user string, stamp []byte, issued []byte) []byte {
	m := hmac.New(sha256.New, s.cfg.Auth.TokenSecret)
	m.Write([]byte("softvpn auth-token\x00" + user + "\x00"))
	m.Write(stamp)
	m.Write([]byte{0})
	m.Write(issued)
	return m.Sum(nil)
}

func (s *Server) makeToken(user string, issued time.Time) (string, bool) {
	stamp, ok := s.cfg.Auth.Users.Stamp(user)
	if !ok {
		return "", false
	}
	ts := binary.BigEndian.AppendUint64(nil, uint64(issued.Unix()))
	raw := append(ts, s.tokenMAC(user, stamp, ts)...)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(raw), true
}

func (s *Server) verifyToken(user, token string) (time.Time, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, tokenPrefix))
	if err != nil || len(raw) != 8+sha256.Size {
		return time.Time{}, errors.New("malformed token")
	}
	stamp, ok := s.cfg.Auth.Users.Stamp(user)
	if !ok {
		return time.Time{}, errors.New("no such user")
	}
	if !hmac.Equal(raw[8:], s.tokenMAC(user, stamp, raw[:8])) {
		return time.Time{}, errors.New("bad signature (password changed or server restarted?)")
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw)), 0)
	if l := s.cfg.Auth.TokenLifetime; l > 0 && time.Since(issued) > l {
		return time.Time{}, errors.New("token expired")
	}
	return issued, nil
}

// verifyConnection is the TLS hook that checks client certificates against
// the CRL, on every handshake including renegotiations.
func (s *Server) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	cert := cs.PeerCertificates[0]
	if err := s.cfg.Auth.CRL.Check(cert); err != nil {
		if errors.Is(err, pki.ErrRevoked) {
			s.log.Warn("client certificate revoked, refusing", "client", cert.Subject.CommonName, "serial", fmt.Sprintf("%X", cert.SerialNumber))
		} else {
			s.log.Error("refusing client: CRL unavailable", "client", cert.Subject.CommonName, "err", err)
		}
		return err
	}
	return nil
}

// authWatch re-reads the CRL and users file when they change and
// disconnects sessions that are no longer allowed: revoked certificates and
// deleted users. (Changed passwords take effect at the next renegotiation.)
func (s *Server) authWatch(ctx context.Context) {
	a := &s.cfg.Auth
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		crlChanged, usersChanged := false, false
		if a.CRL != nil {
			changed, err := a.CRL.Reload()
			if err != nil {
				if changed {
					s.log.Error("CRL unusable, refusing all client certificates", "err", err)
				}
			} else if changed {
				s.log.Info("CRL reloaded", "file", a.CRL.Path(), "revoked", a.CRL.Len())
				crlChanged = true
			}
		}
		if a.Users != nil {
			changed, err := a.Users.Reload()
			if err != nil && changed {
				s.log.Warn("problem in users file", "err", err)
			} else if changed {
				s.log.Info("users file reloaded", "file", a.Users.Path())
			}
			usersChanged = changed
		}
		if !crlChanged && !usersChanged {
			continue
		}
		s.mu.RLock()
		var all []*ovpn.Session
		for ss := range s.sessions {
			all = append(all, ss)
		}
		s.mu.RUnlock()
		for _, ss := range all {
			if cert := ss.Certificate(); crlChanged && cert != nil && errors.Is(a.CRL.Check(cert), pki.ErrRevoked) {
				s.log.Warn("disconnecting client: certificate revoked", "client", ss.CommonName(), "serial", fmt.Sprintf("%X", cert.SerialNumber))
				go ss.Kick("AUTH_FAILED,certificate revoked", "certificate revoked")
				continue
			}
			if u := ss.Username(); usersChanged && u != "" {
				if ok, err := a.Users.Exists(u); err == nil && !ok {
					s.log.Warn("disconnecting client: user removed", "client", ss.CommonName(), "user", u)
					go ss.Kick("AUTH_FAILED,user removed", "user removed")
				}
			}
		}
	}
}
