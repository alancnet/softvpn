package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/fsutil"
	"github.com/softvpn/softvpn/internal/logbuf"
	"github.com/softvpn/softvpn/internal/ovpn"
	"github.com/softvpn/softvpn/internal/pki"
	"github.com/softvpn/softvpn/internal/server"
	"github.com/softvpn/softvpn/internal/users"
)

// ---- login ----

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	if err := sameOrigin(r); err != nil {
		apiError(w, http.StatusForbidden, err.Error())
		return
	}
	// A header that a cross-site form cannot send: logging in from another
	// site's page is refused too.
	if r.Header.Get("X-Requested-With") != "softvpn" {
		apiError(w, http.StatusForbidden, "missing X-Requested-With: softvpn header")
		return
	}
	addr := clientAddr(r)
	if wait := u.limiter.allow(addr); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		apiError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed logins; try again in %d minutes", int(wait.Minutes())+1))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := u.admins.verify(req.Username, req.Password); err != nil {
		u.limiter.fail(addr)
		if !errors.Is(err, users.ErrBadCredentials) {
			u.log.Error("web UI: administrators file", "err", err)
		}
		u.log.Warn("web UI: failed login", "user", req.Username, "remote", addr)
		apiError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	u.limiter.reset(addr)
	token, ss := u.sessions.create(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", MaxAge: int(sessionMax.Seconds()),
		HttpOnly: true, Secure: !u.opt.HTTP, SameSite: http.SameSiteStrictMode,
	})
	u.log.Info("web UI: administrator logged in", "user", req.Username, "remote", addr)
	writeJSON(w, http.StatusOK, map[string]any{"user": ss.user, "csrf": ss.csrf})
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		u.sessions.remove(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !u.opt.HTTP, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// getSession tells the page whether it is logged in (without an error
// status when it is not: that is the normal first visit).
func (u *UI) getSession(w http.ResponseWriter, r *http.Request) {
	var ss *session
	if c, err := r.Cookie(cookieName); err == nil {
		ss = u.sessions.get(c.Value)
	}
	if ss == nil || !u.admins.exists(ss.user) {
		writeJSON(w, http.StatusOK, map[string]any{"loggedIn": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loggedIn": true, "user": ss.user, "csrf": ss.csrf,
		"canChangePassword": u.admins.db != nil && fsutil.Writable(u.admins.file) == ""})
}

func (u *UI) changeAdminPassword(w http.ResponseWriter, r *http.Request) {
	ss := sessionOf(r)
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if u.admins.db == nil || fsutil.Writable(u.admins.file) != "" {
		apiError(w, http.StatusConflict, "the administrators file cannot be changed here")
		return
	}
	if len(req.New) < 8 {
		apiError(w, http.StatusBadRequest, "the new password must have at least 8 characters")
		return
	}
	if u.admins.verify(ss.user, req.Current) != nil {
		apiError(w, http.StatusForbidden, "the current password is wrong")
		return
	}
	u.editMu.Lock()
	err := users.SetPassword(u.admins.file, ss.user, req.New)
	u.editMu.Unlock()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c, _ := r.Cookie(cookieName)
	u.sessions.removeUser(ss.user, c.Value)
	u.log.Info("web UI: administrator changed their password", "user", ss.user)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- status ----

type listenerJSON struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
}

type statusJSON struct {
	Version        string         `json:"version"`
	ProcessStarted time.Time      `json:"processStarted"`
	Now            time.Time      `json:"now"`
	Running        bool           `json:"running"`
	EngineStarted  time.Time      `json:"engineStarted"`
	LastApplied    *time.Time     `json:"lastApplied"`
	Listeners      []listenerJSON `json:"listeners"`
	Mode           string         `json:"mode"`
	Subnet         string         `json:"subnet"`
	Gateway        string         `json:"gateway"`
	Subnet6        string         `json:"subnet6"`
	Gateway6       string         `json:"gateway6"`
	Routes         []string       `json:"routes"`
	Clients        int            `json:"clients"`
	MaxClients     int            `json:"maxClients"`
	ClientToClient bool           `json:"clientToClient"`
	Ciphers        []string       `json:"ciphers"`
	Wrap           string         `json:"wrap"`
	Compress       string         `json:"compress"`
	Push           []string       `json:"push"`
	CCDDir         string         `json:"ccdDir"`
	Auth           struct {
		VerifyClientCert     string `json:"verifyClientCert"`
		UsersFile            string `json:"usersFile"`
		CRLFile              string `json:"crlFile"`
		UsernameAsCommonName bool   `json:"usernameAsCommonName"`
		AuthUserPassOptional bool   `json:"authUserPassOptional"`
		AuthGenToken         bool   `json:"authGenToken"`
	} `json:"auth"`
	Config struct {
		File     string   `json:"file"`
		Writable bool     `json:"writable"`
		Reason   string   `json:"reason"`
		Args     []string `json:"args"`
	} `json:"config"`
	PKI struct {
		Dir       string `json:"dir"`
		Available bool   `json:"available"`
		Writable  bool   `json:"writable"`
		Reason    string `json:"reason"`
	} `json:"pki"`
	WebUI struct {
		HTTP      bool   `json:"http"`
		UsersFile string `json:"usersFile"`
	} `json:"webui"`
}

// configState is the configuration file and, if it cannot be edited, why.
func (u *UI) configState() (file, reason string) {
	file = u.sup.ConfigFile()
	if file == "" {
		return "", "softvpn was started without --config FILE, so there is no configuration file to edit"
	}
	if why := fsutil.Writable(file); why != "" {
		return file, "the configuration is read-only: " + why + ". Mount its volume read-write to edit it here"
	}
	return file, ""
}

func (u *UI) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, u.statusInfo())
}

func (u *UI) statusInfo() *statusJSON {
	s := &statusJSON{Version: u.version, ProcessStarted: u.started, Now: time.Now(),
		Routes: []string{}, Ciphers: []string{}, Push: []string{}, Listeners: []listenerJSON{}}
	if t := u.sup.LastApplied(); !t.IsZero() {
		s.LastApplied = &t
	}
	if srv := u.sup.Server(); srv != nil {
		cfg := srv.Config()
		s.Running, s.EngineStarted = true, srv.Started()
		for _, l := range srv.Listening() {
			s.Listeners = append(s.Listeners, listenerJSON{l.Proto, l.Addr})
		}
		s.Mode = "tun"
		if cfg.TAP {
			s.Mode = "tap"
		}
		s.Subnet, s.Gateway = cfg.Subnet.String(), cfg.Gateway.String()
		if cfg.Subnet6.IsValid() {
			s.Subnet6, s.Gateway6 = cfg.Subnet6.String(), cfg.Gateway6.String()
		}
		for _, p := range cfg.Routes {
			s.Routes = append(s.Routes, p.String())
		}
		s.Clients = len(srv.Sessions())
		s.MaxClients, s.ClientToClient = cfg.MaxClients, cfg.ClientToClient
		s.Ciphers = append(s.Ciphers, cfg.Ciphers...)
		if cfg.Wrap != nil {
			s.Wrap = cfg.Wrap.Mode.String()
		}
		if o := cfg.Compress.PushOption(); o != "" {
			s.Compress = o
		}
		s.Push = append(s.Push, cfg.Push...)
		s.CCDDir = cfg.CCDDir
		a := cfg.Auth
		s.Auth.VerifyClientCert = a.VerifyClientCert
		if a.Users != nil {
			s.Auth.UsersFile = a.Users.Path()
		}
		if a.CRL != nil {
			s.Auth.CRLFile = a.CRL.Path()
		}
		s.Auth.UsernameAsCommonName, s.Auth.AuthUserPassOptional, s.Auth.AuthGenToken = a.UsernameAsCommonName, a.AuthUserPassOptional, a.AuthGenToken
	}
	file, reason := u.configState()
	s.Config.File, s.Config.Writable, s.Config.Reason = file, reason == "", reason
	s.Config.Args = otherArgs(u.sup.Args)
	d, why := u.pkiDir()
	s.PKI.Dir, s.PKI.Available, s.PKI.Reason = u.opt.PKIDir, why == "", why
	if why == "" {
		if w := fsutil.DirWritable(d.Path); w != "" {
			s.PKI.Reason = "the PKI directory is read-only: " + w
		} else {
			s.PKI.Writable = true
		}
	}
	s.WebUI.HTTP, s.WebUI.UsersFile = u.opt.HTTP, u.admins.file
	return s
}

// otherArgs is the command line without "--config FILE": directives that
// override the file.
func otherArgs(args []string) []string {
	out := []string{}
	for i := 0; i < len(args); i++ {
		if strings.EqualFold(args[i], "--config") && i+1 < len(args) {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// ---- sessions ----

type sessionJSON struct {
	ID         uint32    `json:"id"`
	CommonName string    `json:"commonName"`
	Username   string    `json:"username"`
	Remote     string    `json:"remote"`
	IP         string    `json:"ip"`
	IP6        string    `json:"ip6"`
	IRoutes    []string  `json:"iroutes"`
	Cipher     string    `json:"cipher"`
	Version    string    `json:"version"`
	Platform   string    `json:"platform"`
	GUI        string    `json:"gui"`
	Compress   string    `json:"compress"`
	RxBytes    uint64    `json:"rxBytes"`
	TxBytes    uint64    `json:"txBytes"`
	Since      time.Time `json:"since"`
}

func (u *UI) sessionList() []sessionJSON {
	out := []sessionJSON{}
	srv := u.sup.Server()
	if srv == nil {
		return out
	}
	for _, s := range srv.Sessions() {
		j := sessionJSON{ID: s.PeerID, CommonName: s.CommonName, Username: s.Username, Remote: s.Remote,
			IP: s.IP.String(), Cipher: s.Cipher, Version: s.Version, Platform: s.Platform, GUI: s.GUI,
			Compress: s.Compress, RxBytes: s.RxBytes, TxBytes: s.TxBytes, Since: s.Since, IRoutes: []string{}}
		if s.IP6.IsValid() {
			j.IP6 = s.IP6.String()
		}
		for _, p := range s.IRoutes {
			j.IRoutes = append(j.IRoutes, p.String())
		}
		out = append(out, j)
	}
	return out
}

func (u *UI) listSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"sessions": u.sessionList()})
}

func (u *UI) disconnect(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	var req struct {
		Reconnect bool `json:"reconnect"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	srv := u.sup.Server()
	if srv == nil || !srv.DisconnectPeer(uint32(id), req.Reconnect) {
		apiError(w, http.StatusNotFound, "no such session (it may have disconnected already)")
		return
	}
	u.log.Info("web UI: session disconnected", "user", sessionOf(r).user, "peer_id", id, "reconnect", req.Reconnect)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// events streams Server-Sent Events: "sessions" (with a status summary)
// every two seconds, and "log" with new log entries as they arrive.
func (u *UI) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		apiError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	wantLogs := r.URL.Query().Get("logs") != ""
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(event string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	summary := func() map[string]any {
		s := u.statusInfo()
		return map[string]any{"sessions": u.sessionList(), "running": s.Running, "engineStarted": s.EngineStarted,
			"clients": s.Clients, "lastApplied": s.LastApplied, "now": s.Now}
	}
	if !send("sessions", summary()) {
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		var notify <-chan struct{}
		if wantLogs {
			var entries []any
			list, n := u.ring.Since(since)
			for _, e := range list {
				entries = append(entries, e)
				since = e.Seq
			}
			if len(entries) > 0 && !send("log", entries) {
				return
			}
			notify = n
		}
		select {
		case <-r.Context().Done():
			return
		case <-notify:
			time.Sleep(150 * time.Millisecond) // batch bursts
		case <-tick.C:
			if !send("sessions", summary()) {
				return
			}
		}
	}
}

func (u *UI) logs(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	list, _ := u.ring.Since(since)
	if list == nil {
		list = []logbuf.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": list})
}

// ---- configuration ----

func textHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type issue struct {
	Line    int    `json:"line"` // 0: not tied to a line of the file
	Message string `json:"message"`
}

// issues turns a loader error into messages, with line numbers when it
// names a line of file.
func issues(err error, file string) []issue {
	msg := err.Error()
	if file != "" && strings.HasPrefix(msg, file+":") {
		rest := msg[len(file)+1:]
		if i := strings.Index(rest, ":"); i > 0 {
			if n, err := strconv.Atoi(rest[:i]); err == nil {
				return []issue{{Line: n, Message: strings.TrimSpace(rest[i+1:])}}
			}
		}
	}
	return []issue{{Message: msg}}
}

// validate checks a candidate server.conf exactly as the server would load
// it at startup (with the same command line), plus the web UI's own
// directives.
func (u *UI) validate(text string) (*server.Config, []issue) {
	file := u.sup.ConfigFile()
	c, cfg, err := u.sup.Load(&text)
	if err != nil {
		return nil, issues(err, file)
	}
	if _, err := ParseOptions(c, file); err != nil {
		return nil, issues(err, file)
	}
	return cfg, nil
}

// prepare creates what a candidate configuration refers to but does not
// exist yet and the UI can make: an empty client-config-dir and an empty
// users file. It returns a function that removes them again.
func (u *UI) prepare(text string) (undo func()) {
	var made []string
	undo = func() {
		for i := len(made) - 1; i >= 0; i-- {
			os.Remove(made[i])
		}
	}
	file := u.sup.ConfigFile()
	c, err := config.ParseText(file, text)
	if err != nil {
		return undo
	}
	if d, ok := c.Last("client-config-dir"); ok && d.Arg(0) != "" {
		if _, err := os.Stat(d.Path(0)); errors.Is(err, os.ErrNotExist) && fsutil.DirWritable(filepath.Dir(d.Path(0))) == "" {
			if os.Mkdir(d.Path(0), 0o755) == nil {
				made = append(made, d.Path(0))
			}
		}
	}
	if d, ok := c.Last("auth-user-pass-file"); ok && d.Arg(0) != "" {
		if _, err := os.Stat(d.Path(0)); errors.Is(err, os.ErrNotExist) && fsutil.DirWritable(filepath.Dir(d.Path(0))) == "" {
			if f, err := os.OpenFile(d.Path(0), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
				f.Close()
				made = append(made, d.Path(0))
			}
		}
	}
	return undo
}

func (u *UI) getConfig(w http.ResponseWriter, r *http.Request) {
	file, reason := u.configState()
	resp := map[string]any{"file": file, "writable": reason == "", "reason": reason, "args": otherArgs(u.sup.Args),
		"text": "", "hash": "", "settings": extractSettings("")}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp["text"], resp["hash"], resp["settings"] = string(b), textHash(b), extractSettings(string(b))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (u *UI) checkConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if u.sup.ConfigFile() == "" {
		apiError(w, http.StatusConflict, "there is no configuration file")
		return
	}
	u.editMu.Lock()
	undo := u.prepare(req.Text)
	_, errs := u.validate(req.Text)
	undo()
	u.editMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": len(errs) == 0, "errors": nonNil(errs)})
}

func nonNil(v []issue) []issue {
	if v == nil {
		return []issue{}
	}
	return v
}

// renderConfig applies structured settings to the current file and
// returns the resulting text, for review before it is saved.
func (u *UI) renderConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Settings Settings `json:"settings"`
		Hash     string   `json:"hash"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	file := u.sup.ConfigFile()
	if file == "" {
		apiError(w, http.StatusConflict, "there is no configuration file")
		return
	}
	cur, err := os.ReadFile(file)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Hash != "" && req.Hash != textHash(cur) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the configuration file changed since it was loaded; reload it first", "hash": textHash(cur)})
		return
	}
	text, err := applySettings(string(cur), req.Settings)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"text": text, "changed": text != string(cur)})
}

// putConfig validates, writes and applies a new server.conf. Nothing is
// written if it is invalid; if the server cannot start with it, the old
// file is put back and the old configuration keeps running.
func (u *UI) putConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
		Hash string `json:"hash"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	u.editMu.Lock()
	defer u.editMu.Unlock()
	file, reason := u.configState()
	if reason != "" {
		apiError(w, http.StatusConflict, reason)
		return
	}
	cur, err := os.ReadFile(file)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Hash != "" && req.Hash != textHash(cur) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the configuration file changed since it was loaded; reload it first", "hash": textHash(cur)})
		return
	}
	if !strings.HasSuffix(req.Text, "\n") && req.Text != "" {
		req.Text += "\n"
	}
	if req.Text == string(cur) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": true, "hash": textHash(cur)})
		return
	}
	undo := u.prepare(req.Text)
	cfg, errs := u.validate(req.Text)
	if errs != nil {
		undo()
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "the configuration is invalid; nothing was saved", "errors": errs})
		return
	}
	if err := fsutil.WriteFile(file, []byte(req.Text), 0o644); err != nil {
		undo()
		apiError(w, http.StatusInternalServerError, "writing "+file+": "+err.Error())
		return
	}
	user := sessionOf(r).user
	u.log.Info("web UI: configuration saved, restarting the server", "user", user, "file", file)
	if err := u.sup.Apply(cfg); err != nil {
		restoreErr := fsutil.WriteFile(file, cur, 0o644)
		undo()
		var ae *server.ApplyError
		rolledBack := errors.As(err, &ae) && ae.RolledBack
		resp := map[string]any{"error": err.Error(), "rolledBack": rolledBack, "restored": restoreErr == nil, "hash": textHash(cur)}
		if restoreErr != nil {
			resp["error"] = err.Error() + "; restoring the previous file failed too: " + restoreErr.Error()
		}
		u.log.Warn("web UI: configuration not applied; previous file restored", "user", user, "err", err, "restored", restoreErr == nil)
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hash": textHash([]byte(req.Text)), "applied": u.sup.LastApplied()})
}

// genKey creates a control-channel key in the PKI directory (if there is
// none yet) and returns its path, for the tls-auth/tls-crypt settings.
func (u *UI) genKey(w http.ResponseWriter, r *http.Request) {
	wrap, err := pki.ParseWrap(r.PathValue("mode"))
	if err != nil || wrap == pki.WrapNone {
		apiError(w, http.StatusBadRequest, "unknown key type")
		return
	}
	d, why := u.pkiDir()
	if why == "" {
		why = fsutil.DirWritable(d.Path)
	}
	if why != "" {
		apiError(w, http.StatusConflict, why)
		return
	}
	u.editMu.Lock()
	made, err := d.GenKey(wrap)
	u.editMu.Unlock()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	file := filepath.Join(d.Path, wrap.KeyFile())
	if made {
		u.log.Info("web UI: created a control-channel key", "user", sessionOf(r).user, "file", file)
	}
	writeJSON(w, http.StatusOK, map[string]any{"file": file, "created": made})
}

// ---- clients ----

var clientName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

func checkName(name string) error {
	if !clientName.MatchString(name) {
		return fmt.Errorf("invalid name %q: use up to 64 letters, digits, '.', '_', '@' and '-', starting with a letter or digit", name)
	}
	return nil
}

type clientJSON struct {
	Name      string     `json:"name"`
	Serial    string     `json:"serial"`
	NotAfter  time.Time  `json:"notAfter"`
	Expired   bool       `json:"expired"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revokedAt"`
	Online    int        `json:"online"`
	CCD       bool       `json:"ccd"`
	Disabled  bool       `json:"disabled"`
	User      bool       `json:"user"` // a password user of the same name exists
}

func (u *UI) online() (byCN, byUser map[string]int) {
	byCN, byUser = map[string]int{}, map[string]int{}
	if srv := u.sup.Server(); srv != nil {
		for _, s := range srv.Sessions() {
			byCN[s.CommonName]++
			if s.Username != "" {
				byUser[s.Username]++
			}
		}
	}
	return byCN, byUser
}

func (u *UI) currentConfig() *server.Config {
	if srv := u.sup.Server(); srv != nil {
		return srv.Config()
	}
	return nil
}

func (u *UI) listClients(w http.ResponseWriter, r *http.Request) {
	cfg := u.currentConfig()
	st := u.statusInfo()
	resp := map[string]any{"pki": st.PKI, "clients": []clientJSON{}}
	crl := map[string]any{"configured": false}
	ccd := map[string]any{"configured": false}
	var userSet map[string]bool
	if cfg != nil {
		if cfg.Auth.CRL != nil {
			crl["configured"], crl["file"] = true, cfg.Auth.CRL.Path()
		}
		if cfg.CCDDir != "" {
			ccd["configured"], ccd["dir"] = true, cfg.CCDDir
			if why := fsutil.DirWritable(cfg.CCDDir); why != "" {
				ccd["reason"] = why
			} else {
				ccd["writable"] = true
			}
		}
		if cfg.Auth.Users != nil {
			if names, err := users.List(cfg.Auth.Users.Path()); err == nil {
				userSet = map[string]bool{}
				for _, n := range names {
					userSet[n] = true
				}
			}
		}
		resp["defaults"] = u.profileDefaults(r, cfg)
	}
	d, why := u.pkiDir()
	if why == "" {
		crl["pkiFile"] = filepath.Join(d.Path, pki.CRLFile)
		if f, ok := crl["file"].(string); ok {
			crl["matches"] = sameFile(f, filepath.Join(d.Path, pki.CRLFile))
		}
		certs, err := d.List()
		if err != nil {
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		byCN, _ := u.online()
		var list []clientJSON
		for _, c := range certs {
			if !c.Client {
				continue
			}
			j := clientJSON{Name: c.Name, Serial: fmt.Sprintf("%X", c.Serial), NotAfter: c.NotAfter,
				Expired: time.Now().After(c.NotAfter), Revoked: c.Revoked, User: userSet[c.Name]}
			if c.Revoked {
				t := c.RevokedAt
				j.RevokedAt = &t
			} else {
				j.Online = byCN[c.Name]
			}
			if cfg != nil && cfg.CCDDir != "" {
				if b, err := os.ReadFile(filepath.Join(cfg.CCDDir, c.Name)); err == nil {
					j.CCD, j.Disabled = true, extractCCD(string(b)).Disabled
				}
			}
			list = append(list, j)
		}
		if list != nil {
			resp["clients"] = list
		}
	}
	resp["crl"], resp["ccd"] = crl, ccd
	writeJSON(w, http.StatusOK, resp)
}

func sameFile(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

func (u *UI) createClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Days     int    `json:"days"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := checkName(req.Name); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Days <= 0 {
		req.Days = 3650
	}
	if req.Days > 36500 {
		apiError(w, http.StatusBadRequest, "validity is too long")
		return
	}
	d, why := u.pkiDir()
	if why == "" {
		why = fsutil.DirWritable(d.Path)
	}
	if why != "" {
		apiError(w, http.StatusConflict, why)
		return
	}
	cfg := u.currentConfig()
	var usersFile string
	if req.Password != "" {
		if cfg == nil || cfg.Auth.Users == nil {
			apiError(w, http.StatusConflict, "the server has no auth-user-pass-file, so there are no password users")
			return
		}
		usersFile = cfg.Auth.Users.Path()
	}
	u.editMu.Lock()
	defer u.editMu.Unlock()
	if d.Exists(req.Name + ".crt") {
		apiError(w, http.StatusConflict, fmt.Sprintf("a certificate named %q exists already", req.Name))
		return
	}
	if usersFile != "" {
		if names, err := users.List(usersFile); err == nil && contains(names, req.Name) {
			apiError(w, http.StatusConflict, fmt.Sprintf("a password user named %q exists already", req.Name))
			return
		}
	}
	if err := d.Issue(req.Name, pki.RoleClient, nil, time.Duration(req.Days)*24*time.Hour); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user := sessionOf(r).user
	u.log.Info("web UI: client certificate issued", "user", user, "client", req.Name, "days", req.Days)
	if usersFile != "" {
		if err := users.Add(usersFile, req.Name, req.Password); err != nil {
			apiError(w, http.StatusInternalServerError, "the certificate was issued, but adding the password user failed: "+err.Error())
			return
		}
		u.log.Info("web UI: password user added", "user", user, "name", req.Name)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "name": req.Name})
}

func (u *UI) revokeClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := checkName(name); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, why := u.pkiDir()
	if why == "" {
		why = fsutil.DirWritable(d.Path)
	}
	if why != "" {
		apiError(w, http.StatusConflict, why)
		return
	}
	u.editMu.Lock()
	err := d.Revoke(name, 3650*24*time.Hour)
	u.editMu.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		apiError(w, http.StatusNotFound, fmt.Sprintf("no certificate named %q", name))
		return
	} else if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u.log.Warn("web UI: client certificate revoked", "user", sessionOf(r).user, "client", name)
	resp := map[string]any{"ok": true, "crlVerify": false}
	byCN, _ := u.online()
	resp["online"] = byCN[name]
	crlFile := filepath.Join(d.Path, pki.CRLFile)
	if cfg := u.currentConfig(); cfg != nil && cfg.Auth.CRL != nil && sameFile(cfg.Auth.CRL.Path(), crlFile) {
		resp["crlVerify"] = true
	} else {
		resp["warning"] = "The server does not check " + crlFile + " (no matching crl-verify), so the revoked certificate can still connect. " +
			"Add \"crl-verify " + crlFile + "\" to the configuration."
		resp["crlFile"] = crlFile
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- profiles ----

type profileDefaultsJSON struct {
	Remote       string   `json:"remote"`
	Port         int      `json:"port"`
	Proto        string   `json:"proto"`
	Protos       []string `json:"protos"`
	AuthUserPass bool     `json:"authUserPass"`
	NoCert       bool     `json:"noCert"`
	PasswordOnly bool     `json:"passwordOnly"` // password users can have profiles without a certificate
	TAP          bool     `json:"tap"`
	Wrap         string   `json:"wrap"`
}

func (u *UI) profileDefaults(r *http.Request, cfg *server.Config) profileDefaultsJSON {
	p := profileDefaultsJSON{TAP: cfg.TAP, Protos: []string{}}
	p.Remote, p.Port, p.Proto, _ = u.endpoint(r, cfg)
	for _, l := range cfg.Listeners {
		if !contains(p.Protos, l.Proto) {
			p.Protos = append(p.Protos, l.Proto)
		}
	}
	a := cfg.Auth
	p.NoCert = a.VerifyClientCert == "none"
	p.AuthUserPass = a.Users != nil && (p.NoCert || !a.AuthUserPassOptional)
	p.PasswordOnly = a.Users != nil && a.VerifyClientCert != "require"
	if cfg.Wrap != nil {
		p.Wrap = cfg.Wrap.Mode.String()
	}
	return p
}

// endpoint is what a profile connects to: the query's remote/port/proto,
// else web-ui-remote, else the host the browser used and the server's
// first listener.
func (u *UI) endpoint(r *http.Request, cfg *server.Config) (remote string, port int, proto string, err error) {
	q := r.URL.Query()
	remote = u.opt.RemoteHost
	if remote == "" {
		remote = r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			remote = h
		}
		remote = strings.Trim(remote, "[]")
	}
	if v := strings.TrimSpace(q.Get("remote")); v != "" {
		remote = v
	}
	if remote == "" || strings.ContainsAny(remote, " \t\r\n\"#;") {
		return "", 0, "", fmt.Errorf("invalid remote host %q", remote)
	}
	proto = u.opt.RemoteProto
	if v := q.Get("proto"); v != "" {
		proto = v
	}
	if proto == "" && len(cfg.Listeners) > 0 {
		proto = cfg.Listeners[0].Proto
	}
	if proto != "udp" && proto != "tcp" {
		return "", 0, "", fmt.Errorf("proto must be udp or tcp")
	}
	port = u.opt.RemotePort
	if port == 0 {
		port = u.listenPort(proto)
	}
	if v := q.Get("port"); v != "" {
		if port, err = strconv.Atoi(v); err != nil || port < 1 || port > 65535 {
			return "", 0, "", fmt.Errorf("invalid port %q", v)
		}
	}
	if port == 0 {
		port = 1194
	}
	return remote, port, proto, nil
}

// listenPort is the port the running server listens on for proto ("udp"
// or "tcp"), or 0.
func (u *UI) listenPort(proto string) int {
	srv := u.sup.Server()
	if srv == nil {
		return 0
	}
	for _, l := range srv.Listening() {
		if strings.HasPrefix(l.Proto, proto) {
			if _, p, err := net.SplitHostPort(l.Addr); err == nil {
				n, _ := strconv.Atoi(p)
				return n
			}
		}
	}
	return 0
}

// profile renders a .ovpn profile that matches the running server: its
// transport, control-channel protection (with the client's own tls-crypt-v2
// key, made if needed), password prompt, TAP mode, auth digest and
// compression.
func (u *UI) profile(r *http.Request, name string, passwordOnly bool) (string, int, error) {
	cfg := u.currentConfig()
	if cfg == nil {
		return "", http.StatusServiceUnavailable, errors.New("the server is restarting; try again in a moment")
	}
	d, why := u.pkiDir()
	if why != "" {
		return "", http.StatusConflict, errors.New(why)
	}
	remote, port, proto, err := u.endpoint(r, cfg)
	if err != nil {
		return "", http.StatusBadRequest, err
	}
	def := u.profileDefaults(r, cfg)
	po := pki.ProfileOptions{TAP: cfg.TAP, NoCert: def.NoCert || passwordOnly}
	po.AuthUserPass = cfg.Auth.Users != nil && (po.NoCert || !cfg.Auth.AuthUserPassOptional)
	if !po.NoCert && !d.Exists(name+".crt") {
		return "", http.StatusNotFound, fmt.Errorf("no certificate named %q (revoked certificates have no profile)", name)
	}
	if w := cfg.Wrap; w != nil {
		switch w.Mode {
		case ovpn.WrapTLSAuth:
			po.Wrap, po.WrapKey = pki.WrapTLSAuth, w.Key.Marshal()
			switch w.Direction {
			case ovpn.KeyDirNormal: // the client's is the profile's default, "1"
			case ovpn.KeyDirInverse:
				po.KeyDirection = "0"
			default:
				po.KeyDirection = "none"
			}
		case ovpn.WrapTLSCrypt:
			po.Wrap, po.WrapKey = pki.WrapTLSCrypt, w.Key.Marshal()
		case ovpn.WrapTLSCryptV2:
			po.Wrap = pki.WrapTLSCryptV2
			u.editMu.Lock()
			made, err := d.GenTLSCryptV2ClientKeyFrom(name, w.V2Key.Marshal(), nil)
			u.editMu.Unlock()
			if err != nil {
				return "", http.StatusInternalServerError, fmt.Errorf("making the client's tls-crypt-v2 key: %w", err)
			}
			if made {
				u.log.Info("web UI: created a tls-crypt-v2 client key", "client", name)
			}
		}
	}
	if cfg.Digest != "" && cfg.Digest != "SHA1" {
		po.Extra = append(po.Extra, "auth "+cfg.Digest)
	}
	if o := cfg.Compress.PushOption(); o != "" {
		po.Extra = append(po.Extra, o)
		if !cfg.Compress.Stub() {
			po.Extra = append(po.Extra, "allow-compression asym")
		}
	}
	// Stock clients offer AES-256-GCM, AES-128-GCM and CHACHA20-POLY1305;
	// name the server's ciphers if it allows none of them.
	common := false
	for _, c := range cfg.Ciphers {
		common = common || c == "AES-256-GCM" || c == "AES-128-GCM" || c == "CHACHA20-POLY1305"
	}
	if !common && len(cfg.Ciphers) > 0 {
		po.Extra = append(po.Extra, "data-ciphers "+strings.Join(cfg.Ciphers, ":"))
	}
	p, err := d.Profile(name, remote, port, proto, po)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	return p, http.StatusOK, nil
}

func (u *UI) sendProfile(w http.ResponseWriter, r *http.Request, name string, passwordOnly bool) {
	p, code, err := u.profile(r, name, passwordOnly)
	if err != nil {
		apiError(w, code, err.Error())
		return
	}
	u.log.Info("web UI: profile downloaded", "user", sessionOf(r).user, "client", name, "password_only", passwordOnly)
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.ovpn"`)
	w.Write([]byte(p))
}

func (u *UI) clientProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := checkName(name); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	u.sendProfile(w, r, name, false)
}

func (u *UI) userProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := checkName(name); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := u.currentConfig()
	if cfg != nil && cfg.Auth.VerifyClientCert == "require" {
		apiError(w, http.StatusConflict, "the server requires a certificate from every client (verify-client-cert require): "+
			"issue a client certificate named "+name+" and download that profile instead")
		return
	}
	u.sendProfile(w, r, name, true)
}

// ---- client-config-dir ----

func (u *UI) ccdPath(w http.ResponseWriter, r *http.Request) (*server.Config, string, string, bool) {
	name := r.PathValue("name")
	if err := checkName(name); err != nil || !server.ValidCCDName(name) {
		apiError(w, http.StatusBadRequest, fmt.Sprintf("invalid client name %q", name))
		return nil, "", "", false
	}
	cfg := u.currentConfig()
	if cfg == nil {
		apiError(w, http.StatusServiceUnavailable, "the server is restarting; try again in a moment")
		return nil, "", "", false
	}
	if cfg.CCDDir == "" {
		apiError(w, http.StatusConflict, "client-config-dir is not configured: set it in the configuration first")
		return nil, "", "", false
	}
	return cfg, name, filepath.Join(cfg.CCDDir, name), true
}

func (u *UI) getCCD(w http.ResponseWriter, r *http.Request) {
	cfg, name, path, ok := u.ccdPath(w, r)
	if !ok {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reason := fsutil.Writable(path)
	if reason == "" && err != nil {
		reason = fsutil.DirWritable(cfg.CCDDir)
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "path": path, "exists": err == nil, "text": string(b),
		"settings": extractCCD(string(b)), "writable": reason == "", "reason": reason,
		"subnet": cfg.Subnet.String(), "subnet6": prefixString(cfg.Subnet6)})
}

func prefixString(p interface {
	IsValid() bool
	String() string
}) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

func (u *UI) putCCD(w http.ResponseWriter, r *http.Request) {
	cfg, name, path, ok := u.ccdPath(w, r)
	if !ok {
		return
	}
	var req struct {
		Text     *string      `json:"text"`
		Settings *CCDSettings `json:"settings"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	u.editMu.Lock()
	defer u.editMu.Unlock()
	cur, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var text string
	switch {
	case req.Text != nil:
		text = *req.Text
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
	case req.Settings != nil:
		text = applyCCD(string(cur), *req.Settings, cfg.Subnet)
	default:
		apiError(w, http.StatusBadRequest, "expected text or settings")
		return
	}
	if err := cfg.CheckCCD(name, text); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid client-config-dir file; nothing was saved", "errors": issues(err, path)})
		return
	}
	if err := fsutil.WriteFile(path, []byte(text), 0o644); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u.log.Info("web UI: client-config-dir file saved", "user", sessionOf(r).user, "client", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "text": text, "settings": extractCCD(text)})
}

func (u *UI) deleteCCD(w http.ResponseWriter, r *http.Request) {
	_, name, path, ok := u.ccdPath(w, r)
	if !ok {
		return
	}
	u.editMu.Lock()
	err := os.Remove(path)
	u.editMu.Unlock()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u.log.Info("web UI: client-config-dir file deleted", "user", sessionOf(r).user, "client", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- password users (auth-user-pass-file) ----

// usersFile is the server's users file, or why there is none.
func (u *UI) usersFile() (string, string) {
	cfg := u.currentConfig()
	if cfg == nil {
		return "", "the server is restarting; try again in a moment"
	}
	if cfg.Auth.Users == nil {
		return "", "the server has no auth-user-pass-file: password users are off"
	}
	return cfg.Auth.Users.Path(), ""
}

func (u *UI) listUsers(w http.ResponseWriter, r *http.Request) {
	file, why := u.usersFile()
	resp := map[string]any{"configured": why == "", "reason": why, "file": file, "users": []any{}}
	if why == "" {
		names, err := users.List(file)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_, byUser := u.online()
		var list []any
		for _, n := range names {
			list = append(list, map[string]any{"name": n, "online": byUser[n]})
		}
		if list != nil {
			resp["users"] = list
		}
		if w := fsutil.Writable(file); w != "" {
			resp["readOnly"] = w
		}
		if cfg := u.currentConfig(); cfg != nil {
			resp["defaults"] = u.profileDefaults(r, cfg)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (u *UI) addUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := checkName(req.Name); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Password == "" {
		apiError(w, http.StatusBadRequest, "the password is empty")
		return
	}
	file, why := u.usersFile()
	if why != "" {
		apiError(w, http.StatusConflict, why)
		return
	}
	u.editMu.Lock()
	err := users.Add(file, req.Name, req.Password)
	u.editMu.Unlock()
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already exists") {
			code = http.StatusConflict
		}
		apiError(w, code, err.Error())
		return
	}
	u.log.Info("web UI: password user added", "user", sessionOf(r).user, "name", req.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "name": req.Name})
}

func (u *UI) setUserPassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Password == "" {
		apiError(w, http.StatusBadRequest, "the password is empty")
		return
	}
	file, why := u.usersFile()
	if why != "" {
		apiError(w, http.StatusConflict, why)
		return
	}
	u.editMu.Lock()
	err := users.SetPassword(file, name, req.Password)
	u.editMu.Unlock()
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "no user") {
			code = http.StatusNotFound
		}
		apiError(w, code, err.Error())
		return
	}
	u.log.Info("web UI: password changed", "user", sessionOf(r).user, "name", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (u *UI) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	file, why := u.usersFile()
	if why != "" {
		apiError(w, http.StatusConflict, why)
		return
	}
	u.editMu.Lock()
	err := users.Delete(file, name)
	u.editMu.Unlock()
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "no user") {
			code = http.StatusNotFound
		}
		apiError(w, code, err.Error())
		return
	}
	u.log.Warn("web UI: password user deleted", "user", sessionOf(r).user, "name", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
