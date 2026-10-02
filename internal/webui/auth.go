package webui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/softvpn/softvpn/internal/fsutil"
	"github.com/softvpn/softvpn/internal/users"
)

// The administrators' accounts: an htpasswd-style bcrypt file (web-ui-users,
// managed like the VPN's own users file), plus the account that
// SOFTVPN_WEB_PASSWORD sets up.

const (
	// PasswordEnv sets (or creates) the "admin" account's password.
	PasswordEnv  = "SOFTVPN_WEB_PASSWORD"
	defaultAdmin = "admin"
)

type admins struct {
	file string    // "" if there is none
	db   *users.DB // nil without a file
	// memHash is the bcrypt hash of SOFTVPN_WEB_PASSWORD for "admin" when
	// it could not be written to the file.
	memHash []byte
}

// setupAdmins opens the administrators file, creating it (or the admin
// account in it) when needed:
//   - with SOFTVPN_WEB_PASSWORD set, "admin" gets that password, in the file
//     if it is writable, otherwise in memory;
//   - without it, a missing file is created with "admin" and a random
//     password, which is logged once.
func setupAdmins(file string, log *slog.Logger) (*admins, error) {
	a := &admins{file: file}
	pw := os.Getenv(PasswordEnv)
	exists := false
	if file != "" {
		_, err := os.Stat(file)
		exists = err == nil
	}
	switch {
	case pw != "" && file != "" && fsutil.Writable(file) == "":
		ok := false
		if exists {
			if db, err := users.Open(file); err == nil && db.Verify(defaultAdmin, pw) == nil {
				ok = true
			}
		}
		if !ok {
			if err := users.Set(file, defaultAdmin, pw); err != nil {
				return nil, fmt.Errorf("web-ui-users: %w", err)
			}
			log.Info("web UI: administrator password set from "+PasswordEnv, "user", defaultAdmin, "file", file)
		}
	case pw != "":
		h, err := bcrypt.GenerateFromPassword([]byte(pw), users.Cost)
		if err != nil {
			return nil, err
		}
		a.memHash = h
		if file != "" {
			log.Warn("web UI: cannot write the administrators file; the "+PasswordEnv+" account lives in memory only", "file", file, "reason", fsutil.Writable(file))
		}
	case file == "":
		return nil, errors.New("web UI: no administrators: set web-ui-users FILE or " + PasswordEnv)
	case !exists:
		if why := fsutil.Writable(file); why != "" {
			return nil, fmt.Errorf("web UI: no administrators file, and cannot create one: %s (create it with \"softvpn user add -file %s admin\", or set %s)", why, file, PasswordEnv)
		}
		pw := randomPassword()
		if err := users.Add(file, defaultAdmin, pw); err != nil {
			return nil, fmt.Errorf("web-ui-users: %w", err)
		}
		// The only time a secret is logged: nobody else knows it yet.
		log.Warn("web UI: created an administrator account; log in and keep this password safe, it is not shown again",
			"user", defaultAdmin, "password", pw, "file", file)
	}
	if file != "" {
		if _, err := os.Stat(file); err == nil {
			db, err := users.Open(file)
			if err != nil {
				return nil, fmt.Errorf("web-ui-users: %w", err)
			}
			a.db = db
		}
	}
	return a, nil
}

func randomPassword() string {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	// URL-safe base64 without look-alikes is overkill; 20 characters of
	// base64 is easy enough to paste.
	return base64.RawURLEncoding.EncodeToString(b)
}

// verify checks an administrator's password (ErrBadCredentials if wrong).
func (a *admins) verify(name, password string) error {
	if a.memHash != nil && name == defaultAdmin {
		if bcrypt.CompareHashAndPassword(a.memHash, []byte(password)) == nil {
			return nil
		}
		if a.db == nil {
			return users.ErrBadCredentials
		}
	}
	if a.db == nil {
		users.HashPassword(password) // same cost as a real check
		return users.ErrBadCredentials
	}
	return a.db.Verify(name, password)
}

// exists reports whether name is still an administrator.
func (a *admins) exists(name string) bool {
	if a.memHash != nil && name == defaultAdmin {
		return true
	}
	if a.db == nil {
		return false
	}
	ok, err := a.db.Exists(name)
	return err == nil && ok
}

// Sessions: a random token in an HttpOnly cookie, and a second random token
// the page sends in a header on every change (CSRF).

const (
	cookieName  = "softvpn_session"
	csrfHeader  = "X-CSRF-Token"
	sessionIdle = 8 * time.Hour
	sessionMax  = 24 * time.Hour
)

type session struct {
	user    string
	csrf    string
	created time.Time
	seen    time.Time
}

type sessions struct {
	mu sync.Mutex
	m  map[string]*session // by SHA-256 of the cookie value
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenKey(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// create starts a session and returns its cookie value.
func (s *sessions) create(user string) (string, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m { // prune
		if now.Sub(v.seen) > sessionIdle || now.Sub(v.created) > sessionMax {
			delete(s.m, k)
		}
	}
	t := newToken()
	ss := &session{user: user, csrf: newToken(), created: now, seen: now}
	s.m[tokenKey(t)] = ss
	return t, ss
}

func (s *sessions) get(token string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tokenKey(token)
	ss := s.m[k]
	if ss == nil {
		return nil
	}
	now := time.Now()
	if now.Sub(ss.seen) > sessionIdle || now.Sub(ss.created) > sessionMax {
		delete(s.m, k)
		return nil
	}
	ss.seen = now
	c := *ss
	return &c
}

func (s *sessions) remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tokenKey(token))
}

// removeUser ends every session of user except keep (a cookie value).
func (s *sessions) removeUser(user, keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.user == user && k != tokenKey(keep) {
			delete(s.m, k)
		}
	}
}

// limiter slows down password guessing: an address may fail to log in
// limitPerAddr times per window, and all addresses together limitTotal
// times.
type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
	all   []time.Time
}

const (
	limitWindow  = 15 * time.Minute
	limitPerAddr = 5
	limitTotal   = 50
)

func prune(ts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) > limitWindow {
		i++
	}
	return ts[i:]
}

// allow returns 0 if addr may try to log in, or how long it must wait.
func (l *limiter) allow(addr string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.all = prune(l.all, now)
	f := prune(l.fails[addr], now)
	if len(f) == 0 {
		delete(l.fails, addr)
	} else {
		l.fails[addr] = f
	}
	switch {
	case len(f) >= limitPerAddr:
		return limitWindow - now.Sub(f[0])
	case len(l.all) >= limitTotal:
		return limitWindow - now.Sub(l.all[0])
	}
	return 0
}

func (l *limiter) fail(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.fails[addr] = append(l.fails[addr], now)
	l.all = append(l.all, now)
}

func (l *limiter) reset(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, addr)
}

func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sameOrigin rejects requests that a page from another site could have
// made: browsers send Origin (and Sec-Fetch-Site) with every POST, PUT and
// DELETE. Requests without either come from non-browser clients (curl),
// which cannot be tricked into sending the session cookie.
func sameOrigin(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return fmt.Errorf("cross-site request refused (Sec-Fetch-Site: %s)", site)
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return fmt.Errorf("cross-origin request refused (Origin: %s)", o)
		}
	}
	return nil
}

func csrfOK(r *http.Request, ss *session) bool {
	got := r.Header.Get(csrfHeader)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(ss.csrf)) == 1
}
