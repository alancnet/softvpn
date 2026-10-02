// Package webui is softvpn's optional web interface: a dashboard of the
// running server, an editor for server.conf that validates and applies
// changes (restarting the VPN engine in-process), and management of client
// certificates, profiles, client-config-dir files and password users.
//
// It is enabled with "web-ui ADDR" and is meant for a container whose
// configuration volume is mounted read-write; with a read-only one it still
// shows the server's state. Every page needs an administrator login.
package webui

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/softvpn/softvpn/internal/logbuf"
	"github.com/softvpn/softvpn/internal/pki"
	"github.com/softvpn/softvpn/internal/server"
)

//go:embed static
var static embed.FS

// UI is the web interface.
type UI struct {
	opt     Options
	sup     *server.Supervisor
	log     *slog.Logger
	ring    *logbuf.Ring
	version string
	started time.Time

	admins   *admins
	sessions sessions
	limiter  limiter
	cert     *tls.Certificate // nil for plain HTTP

	editMu sync.Mutex // serializes changes to files
	mux    *http.ServeMux
}

// New sets up the web UI: the administrators file (see setupAdmins) and,
// unless web-ui-http is set, the TLS certificate.
func New(opt Options, sup *server.Supervisor, ring *logbuf.Ring, log *slog.Logger, version string) (*UI, error) {
	u := &UI{opt: opt, sup: sup, ring: ring, log: log, version: version, started: time.Now()}
	u.sessions.m = map[string]*session{}
	u.limiter.fails = map[string][]time.Time{}
	var err error
	if u.admins, err = setupAdmins(opt.UsersFile, log); err != nil {
		return nil, err
	}
	if !opt.HTTP {
		c, err := certificate(&opt, log)
		if err != nil {
			return nil, err
		}
		u.cert = &c
	}
	u.routes()
	return u, nil
}

// Handler serves the UI and its API.
func (u *UI) Handler() http.Handler { return u.mux }

// Serve listens on the configured address until ctx is cancelled.
func (u *UI) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", u.opt.Addr)
	if err != nil {
		return err
	}
	return u.ServeListener(ctx, ln)
}

// ServeListener is Serve on an existing listener.
func (u *UI) ServeListener(ctx context.Context, ln net.Listener) error {
	hs := &http.Server{
		Handler:           u.mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(u.log.Handler(), slog.LevelDebug),
	}
	scheme := "https"
	if u.cert != nil {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*u.cert}}
		ln = tls.NewListener(ln, hs.TLSConfig)
	} else {
		scheme = "http"
		u.log.Warn("web UI: serving plain HTTP (web-ui-http); put it behind a TLS reverse proxy, passwords and session cookies travel in the clear otherwise")
	}
	u.log.Info("web UI listening", "url", scheme+"://"+ln.Addr().String()+"/")
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// headers sets the security headers every response gets.
func (u *UI) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "+
			"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (u *UI) routes() {
	m := http.NewServeMux()
	staticFS, _ := fs.Sub(static, "static")
	files := http.FileServer(http.FS(staticFS))
	m.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.Contains(r.URL.Path, ".") {
			r.URL.Path = "/" // the app's own routes are in the URL fragment
		}
		w.Header().Set("Cache-Control", "no-cache") // revalidate: the binary may have been upgraded
		files.ServeHTTP(w, r)
	}))

	m.HandleFunc("POST /api/login", u.login)
	m.Handle("POST /api/logout", u.auth(u.logout))
	m.HandleFunc("GET /api/session", u.getSession)
	m.Handle("POST /api/session/password", u.auth(u.changeAdminPassword))

	m.Handle("GET /api/status", u.auth(u.status))
	m.Handle("GET /api/sessions", u.auth(u.listSessions))
	m.Handle("POST /api/sessions/{id}/disconnect", u.auth(u.disconnect))
	m.Handle("GET /api/events", u.auth(u.events))
	m.Handle("GET /api/logs", u.auth(u.logs))

	m.Handle("GET /api/config", u.auth(u.getConfig))
	m.Handle("POST /api/config/check", u.auth(u.checkConfig))
	m.Handle("POST /api/config/render", u.auth(u.renderConfig))
	m.Handle("PUT /api/config", u.auth(u.putConfig))
	m.Handle("POST /api/keys/{mode}", u.auth(u.genKey))

	m.Handle("GET /api/clients", u.auth(u.listClients))
	m.Handle("POST /api/clients", u.auth(u.createClient))
	m.Handle("GET /api/clients/{name}/profile", u.auth(u.clientProfile))
	m.Handle("POST /api/clients/{name}/revoke", u.auth(u.revokeClient))
	m.Handle("GET /api/ccd/{name}", u.auth(u.getCCD))
	m.Handle("PUT /api/ccd/{name}", u.auth(u.putCCD))
	m.Handle("DELETE /api/ccd/{name}", u.auth(u.deleteCCD))

	m.Handle("GET /api/users", u.auth(u.listUsers))
	m.Handle("POST /api/users", u.auth(u.addUser))
	m.Handle("PUT /api/users/{name}", u.auth(u.setUserPassword))
	m.Handle("DELETE /api/users/{name}", u.auth(u.deleteUser))
	m.Handle("GET /api/users/{name}/profile", u.auth(u.userProfile))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "no such API endpoint")
	})
	u.mux = http.NewServeMux()
	u.mux.Handle("/", u.headers(m))
}

type ctxKey struct{}

// sessionOf is the logged-in session of an authenticated request.
func sessionOf(r *http.Request) *session { s, _ := r.Context().Value(ctxKey{}).(*session); return s }

// auth requires a logged-in administrator, and for changes (anything but
// GET) also the session's CSRF token and a same-origin request.
func (u *UI) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var ss *session
		if err == nil {
			ss = u.sessions.get(c.Value)
		}
		if ss == nil || !u.admins.exists(ss.user) {
			apiError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := sameOrigin(r); err != nil {
				apiError(w, http.StatusForbidden, err.Error())
				return
			}
			if !csrfOK(r, ss) {
				apiError(w, http.StatusForbidden, "missing or wrong "+csrfHeader+" header")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, ss)))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON request: " + err.Error())
	}
	return nil
}

// pkiDir is the PKI directory for client certificates, or why there is none.
func (u *UI) pkiDir() (pki.Dir, string) {
	if u.opt.PKIDir == "" {
		return pki.Dir{}, "no PKI directory with a CA key: set web-ui-pki DIR (the directory \"softvpn pki init\" made)"
	}
	d := pki.Dir{Path: u.opt.PKIDir}
	if !d.Exists("ca.key") {
		return pki.Dir{}, u.opt.PKIDir + " has no ca.key: client certificates cannot be issued here"
	}
	return d, ""
}
