package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/logbuf"
	"github.com/softvpn/softvpn/internal/pki"
	"github.com/softvpn/softvpn/internal/server"
	"github.com/softvpn/softvpn/internal/users"
)

const adminPassword = "correct horse battery"

func init() { users.Cost = bcrypt.MinCost }

// env is a running softvpn (real engine, on loopback with ephemeral ports)
// with its web UI behind an httptest server.
type env struct {
	t    *testing.T
	dir  string // server.conf's directory; the PKI is dir/pki
	conf string
	sup  *server.Supervisor
	ui   *UI
	ts   *httptest.Server
	log  *bytes.Buffer
}

const baseConf = `# softvpn test configuration
local 127.0.0.1
port 0
proto udp
proto tcp   # both
dev tun
server 10.77.0.0 255.255.255.0
ca   pki/ca.crt
cert pki/server.crt
key  pki/server.key
crl-verify pki/crl.pem
keepalive 10 60
push "dhcp-option DNS 10.77.0.1"
client-config-dir ccd
auth-user-pass-file users
verify-client-cert optional
auth-user-pass-optional
web-ui 127.0.0.1:0
web-ui-http
`

func newEnv(t *testing.T, conf string) *env {
	t.Helper()
	dir := t.TempDir()
	if err := (pki.Dir{Path: filepath.Join(dir, "pki")}).Init("server", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	return newEnvIn(t, dir, conf)
}

// newEnvIn starts the server with conf as dir/server.conf; dir holds the
// files conf names.
func newEnvIn(t *testing.T, dir, conf string) *env {
	t.Helper()
	os.Mkdir(filepath.Join(dir, "ccd"), 0o755)
	if err := users.Add(filepath.Join(dir, "users"), "bob", "bobpw"); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, conf: filepath.Join(dir, "server.conf"), log: &bytes.Buffer{}}
	if err := os.WriteFile(e.conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PasswordEnv, adminPassword)
	ring := logbuf.New(100)
	var level slog.LevelVar
	log := slog.New(ring.Handler(slog.NewTextHandler(&lockedWriter{w: e.log}, &slog.HandlerOptions{Level: &level}), &level))
	e.sup = &server.Supervisor{Args: []string{"--config", e.conf}, Log: log}
	c, cfg, err := e.sup.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := ParseOptions(c, e.conf)
	if err != nil || opts == nil {
		t.Fatalf("options: %v %v", opts, err)
	}
	if e.ui, err = New(*opts, e.sup, ring, log, "test"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.sup.Run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	for i := 0; e.sup.Server() == nil; i++ {
		if i > 200 {
			t.Fatal("server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.ts = httptest.NewServer(e.ui.Handler())
	t.Cleanup(e.ts.Close)
	return e
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// client is a browser-like API client: cookies and the CSRF header.
type client struct {
	e    *env
	http *http.Client
	csrf string
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar}}
}

type resp struct {
	code int
	body map[string]any
	raw  []byte
	hdr  http.Header
}

func (c *client) do(method, path string, body any, hdr ...string) resp {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.ts.URL+path, rd)
	if c.csrf != "" {
		req.Header.Set(csrfHeader, c.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	r := resp{code: res.StatusCode, raw: raw, hdr: res.Header}
	json.Unmarshal(raw, &r.body)
	return r
}

func (c *client) login() {
	c.e.t.Helper()
	r := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": adminPassword}, "X-Requested-With", "softvpn")
	if r.code != 200 {
		c.e.t.Fatalf("login: %d %s", r.code, r.raw)
	}
	c.csrf = r.body["csrf"].(string)
}

func (e *env) file() string {
	b, err := os.ReadFile(e.conf)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func TestAuth(t *testing.T) {
	e := newEnv(t, baseConf)
	c := e.client()
	if r := c.do("GET", "/api/status", nil); r.code != 401 {
		t.Fatalf("status without login: %d", r.code)
	}
	if r := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": adminPassword}); r.code != 403 {
		t.Errorf("login without X-Requested-With: %d", r.code)
	}
	if r := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": adminPassword},
		"X-Requested-With", "softvpn", "Origin", "https://evil.example"); r.code != 403 {
		t.Errorf("cross-origin login: %d", r.code)
	}
	if r := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}, "X-Requested-With", "softvpn"); r.code != 401 {
		t.Errorf("wrong password: %d", r.code)
	}
	if strings.Contains(e.log.String(), adminPassword) || strings.Contains(e.log.String(), "wrong") && strings.Contains(e.log.String(), "password=wrong") {
		t.Error("a password was logged")
	}
	c.login()
	r := c.do("GET", "/api/status", nil)
	if r.code != 200 || r.body["running"] != true || r.body["version"] != "test" {
		t.Fatalf("status: %d %s", r.code, r.raw)
	}
	if got := r.hdr.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Errorf("CSP %q", got)
	}

	// CSRF: changes need the session's token and a same-origin request.
	tok := c.csrf
	c.csrf = ""
	if r := c.do("POST", "/api/users", map[string]string{"name": "x", "password": "y"}); r.code != 403 {
		t.Errorf("change without CSRF token: %d", r.code)
	}
	c.csrf = "not-the-token"
	if r := c.do("POST", "/api/users", map[string]string{"name": "x", "password": "y"}); r.code != 403 {
		t.Errorf("change with a wrong CSRF token: %d", r.code)
	}
	c.csrf = tok
	if r := c.do("POST", "/api/users", map[string]string{"name": "x", "password": "y"}, "Origin", "https://evil.example"); r.code != 403 {
		t.Errorf("cross-origin change: %d", r.code)
	}
	if r := c.do("POST", "/api/users", map[string]string{"name": "x", "password": "y"}, "Sec-Fetch-Site", "cross-site"); r.code != 403 {
		t.Errorf("cross-site change: %d", r.code)
	}
	if r := c.do("POST", "/api/users", map[string]string{"name": "x", "password": "y"}, "Origin", e.ts.URL, "Sec-Fetch-Site", "same-origin"); r.code != 201 {
		t.Errorf("same-origin change: %d %s", r.code, r.raw)
	}

	// Logging out ends the session.
	if r := c.do("POST", "/api/logout", map[string]string{}); r.code != 200 {
		t.Fatalf("logout: %d", r.code)
	}
	if r := c.do("GET", "/api/status", nil); r.code != 401 {
		t.Errorf("status after logout: %d", r.code)
	}

	// Failed logins are rate-limited per address.
	b := e.client()
	for i := 0; i < limitPerAddr; i++ {
		b.do("POST", "/api/login", map[string]string{"username": "admin", "password": "guess" + strconv.Itoa(i)}, "X-Requested-With", "softvpn")
	}
	r = b.do("POST", "/api/login", map[string]string{"username": "admin", "password": adminPassword}, "X-Requested-With", "softvpn")
	if r.code != 429 || r.hdr.Get("Retry-After") == "" {
		t.Errorf("after %d failures: %d (Retry-After %q)", limitPerAddr, r.code, r.hdr.Get("Retry-After"))
	}
}

func TestSessionCookie(t *testing.T) {
	e := newEnv(t, strings.Replace(baseConf, "web-ui-http\n", "", 1))
	if e.ui.cert == nil {
		t.Fatal("expected a TLS certificate")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "web-ui.crt")); err != nil {
		t.Errorf("self-signed certificate not kept: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"`+adminPassword+`"}`))
	req.Header.Set("X-Requested-With", "softvpn")
	e.ui.Handler().ServeHTTP(rec, req)
	c := rec.Header().Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Strict", cookieName + "="} {
		if !strings.Contains(c, want) {
			t.Errorf("cookie %q lacks %s", c, want)
		}
	}
}

func TestBootstrapAdmin(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(&out, nil))
	t.Setenv(PasswordEnv, "")
	file := filepath.Join(dir, "web-ui.users")
	a, err := setupAdmins(file, log)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(out.String(), "password=")
	if i < 0 {
		t.Fatalf("generated password not logged: %s", out.String())
	}
	pw := strings.Fields(out.String()[i+len("password="):])[0]
	if a.verify("admin", pw) != nil {
		t.Fatal("generated password does not work")
	}
	// Next start: the file exists, nothing is logged.
	out.Reset()
	if _, err := setupAdmins(file, log); err != nil || strings.Contains(out.String(), "password=") {
		t.Fatalf("second start: %v %s", err, out.String())
	}
	// SOFTVPN_WEB_PASSWORD sets the password in the file.
	t.Setenv(PasswordEnv, "from-env-123")
	a, err = setupAdmins(file, log)
	if err != nil || a.verify("admin", "from-env-123") != nil || a.verify("admin", pw) == nil {
		t.Fatalf("env password: %v", err)
	}
	if strings.Contains(out.String(), "from-env-123") {
		t.Error("env password logged")
	}
	// Without a writable place for the file it lives in memory only.
	a, err = setupAdmins("", log)
	if err != nil || a.verify("admin", "from-env-123") != nil {
		t.Fatalf("in-memory admin: %v", err)
	}
	t.Setenv(PasswordEnv, "")
	if _, err := setupAdmins("", log); err == nil {
		t.Error("no administrators at all accepted")
	}
}

func TestConfigValidationDoesNotWrite(t *testing.T) {
	e := newEnv(t, baseConf)
	c := e.client()
	c.login()
	before := e.file()
	started := e.sup.Server().Started()
	g := c.do("GET", "/api/config", nil)
	if g.code != 200 || g.body["writable"] != true || g.body["text"] != before {
		t.Fatalf("get config: %d %s", g.code, g.raw)
	}
	bad := strings.Replace(before, "keepalive 10 60", "keepalive 60 10", 1) // timeout must exceed interval
	r := c.do("PUT", "/api/config", map[string]string{"text": bad, "hash": g.body["hash"].(string)})
	if r.code != 422 {
		t.Fatalf("invalid config: %d %s", r.code, r.raw)
	}
	errs := r.body["errors"].([]any)
	if line := errs[0].(map[string]any)["line"].(float64); line != 12 {
		t.Errorf("error line %v, want 12: %s", line, r.raw)
	}
	r = c.do("PUT", "/api/config", map[string]string{"text": before + "no-such-directive yes\n"})
	if r.code != 422 || !strings.Contains(string(r.raw), "unknown directive") {
		t.Errorf("unknown directive: %d %s", r.code, r.raw)
	}
	r = c.do("POST", "/api/config/check", map[string]string{"text": before + "web-ui-remote\n"})
	if r.code != 200 || r.body["ok"] != false {
		t.Errorf("bad web-ui directive passed the check: %s", r.raw)
	}
	if e.file() != before {
		t.Fatal("an invalid configuration was written")
	}
	if !e.sup.Server().Started().Equal(started) {
		t.Fatal("the server restarted for an invalid configuration")
	}
	// A stale hash (someone else changed the file) is refused.
	r = c.do("PUT", "/api/config", map[string]string{"text": before + "verb 4\n", "hash": "0000"})
	if r.code != 409 {
		t.Errorf("stale hash: %d", r.code)
	}
}

func TestApplyAndRollback(t *testing.T) {
	e := newEnv(t, baseConf)
	c := e.client()
	c.login()
	before := e.file()
	srv := e.sup.Server()
	newText := strings.Replace(before, "keepalive 10 60", "keepalive 5 30", 1)
	r := c.do("PUT", "/api/config", map[string]string{"text": newText})
	if r.code != 200 || r.body["ok"] != true {
		t.Fatalf("apply: %d %s", r.code, r.raw)
	}
	if e.file() != newText {
		t.Fatal("file not written")
	}
	now := e.sup.Server()
	if now == srv || now.Config().PingInterval != 5*time.Second {
		t.Fatal("server not restarted with the new configuration")
	}

	// A port that is taken: the new configuration cannot start, so the old
	// file comes back and the old configuration runs again.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	busy := strings.Replace(newText, "port 0", "port "+port, 1)
	r = c.do("PUT", "/api/config", map[string]string{"text": busy})
	if r.code != 500 || r.body["rolledBack"] != true || r.body["restored"] != true {
		t.Fatalf("apply with a busy port: %d %s", r.code, r.raw)
	}
	if e.file() != newText {
		t.Fatalf("file not restored:\n%s", e.file())
	}
	back := e.sup.Server()
	if back == nil || back.Config().PingInterval != 5*time.Second {
		t.Fatal("previous configuration not running again")
	}
	for _, l := range back.Listening() {
		if strings.HasSuffix(l.Addr, ":"+port) {
			t.Fatalf("rolled back server listens on the busy port: %v", back.Listening())
		}
	}
	// It still applies changes afterwards.
	if r := c.do("PUT", "/api/config", map[string]string{"text": before}); r.code != 200 {
		t.Fatalf("apply after rollback: %d %s", r.code, r.raw)
	}
}

func TestStructuredSettings(t *testing.T) {
	e := newEnv(t, baseConf)
	c := e.client()
	c.login()
	g := c.do("GET", "/api/config", nil)
	s := g.body["settings"].(map[string]any)
	if s["keepaliveInterval"] != "10" || s["server"] != "10.77.0.0/24" || s["crlVerify"] != "pki/crl.pem" {
		t.Fatalf("settings %v", s)
	}
	s["keepaliveInterval"], s["keepaliveTimeout"] = "20", "120"
	s["push"] = append(s["push"].([]any), "redirect-gateway def1")
	s["clientToClient"] = true
	r := c.do("POST", "/api/config/render", map[string]any{"settings": s, "hash": g.body["hash"]})
	if r.code != 200 || r.body["changed"] != true {
		t.Fatalf("render: %d %s", r.code, r.raw)
	}
	text := r.body["text"].(string)
	for _, want := range []string{"# softvpn test configuration\n", "proto tcp   # both\n", "keepalive 20 120\n",
		"push \"dhcp-option DNS 10.77.0.1\"\npush \"redirect-gateway def1\"\n", "client-to-client\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered text lacks %q:\n%s", want, text)
		}
	}
	if e.file() == text {
		t.Fatal("render wrote the file")
	}
	if r := c.do("PUT", "/api/config", map[string]string{"text": text}); r.code != 200 {
		t.Fatalf("apply: %d %s", r.code, r.raw)
	}
	cfg := e.sup.Server().Config()
	if !cfg.ClientToClient || cfg.PingInterval != 20*time.Second || len(cfg.Push) != 2 {
		t.Fatalf("applied config: %+v", cfg)
	}
}

func TestReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write read-only files")
	}
	e := newEnv(t, baseConf)
	os.Chmod(e.conf, 0o444)
	os.Chmod(e.dir, 0o555)
	t.Cleanup(func() { os.Chmod(e.dir, 0o755) })
	c := e.client()
	c.login()
	g := c.do("GET", "/api/config", nil)
	if g.code != 200 || g.body["writable"] != false || !strings.Contains(g.body["reason"].(string), "read-only") {
		t.Fatalf("read-only config: %d %s", g.code, g.raw)
	}
	if st := c.do("GET", "/api/status", nil); st.code != 200 || st.body["config"].(map[string]any)["writable"] != false {
		t.Fatalf("status in read-only mode: %s", st.raw)
	}
	r := c.do("PUT", "/api/config", map[string]string{"text": e.file() + "verb 4\n"})
	if r.code != 409 {
		t.Fatalf("write in read-only mode: %d %s", r.code, r.raw)
	}
}

func TestClientsAndProfiles(t *testing.T) {
	e := newEnv(t, baseConf)
	c := e.client()
	c.login()
	if r := c.do("POST", "/api/clients", map[string]any{"name": "../evil"}); r.code != 400 {
		t.Errorf("bad name: %d", r.code)
	}
	if r := c.do("POST", "/api/clients", map[string]any{"name": "laptop", "password": "lpw"}); r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	if r := c.do("POST", "/api/clients", map[string]any{"name": "laptop"}); r.code != 409 {
		t.Errorf("duplicate: %d", r.code)
	}
	l := c.do("GET", "/api/clients", nil)
	cl := l.body["clients"].([]any)
	if len(cl) != 1 || cl[0].(map[string]any)["name"] != "laptop" || cl[0].(map[string]any)["user"] != true {
		t.Fatalf("clients: %s", l.raw)
	}
	if ok, _ := users.List(filepath.Join(e.dir, "users")); !contains(ok, "laptop") {
		t.Error("password user not created")
	}

	r := c.do("GET", "/api/clients/laptop/profile?proto=tcp", nil)
	if r.code != 200 || !strings.Contains(r.hdr.Get("Content-Disposition"), `filename="laptop.ovpn"`) {
		t.Fatalf("profile: %d %s", r.code, r.raw)
	}
	p, err := config.ParseString(string(r.raw))
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(e.sup.Server().Listening()[1].Addr)
	rem := p.All("remote")
	if len(rem) != 1 || rem[0].Arg(0) != "127.0.0.1" || rem[0].Arg(1) != port || p.String("proto", "") != "tcp-client" {
		t.Errorf("remote/proto: %v %q (server port %s)", rem, p.String("proto", ""), port)
	}
	for _, block := range []string{"ca", "cert", "key"} {
		if _, ok := p.Inline[block]; !ok {
			t.Errorf("profile lacks <%s>", block)
		}
	}
	if p.Has("auth-user-pass") {
		t.Error("certificate clients need no password here (auth-user-pass-optional)")
	}
	// A password-only profile for a user.
	r = c.do("GET", "/api/users/bob/profile", nil)
	if r.code != 200 || !strings.Contains(string(r.raw), "auth-user-pass\n") || strings.Contains(string(r.raw), "<cert>") {
		t.Errorf("user profile: %d %s", r.code, r.raw)
	}

	// Revocation: the CRL the server checks gets the certificate.
	r = c.do("POST", "/api/clients/laptop/revoke", map[string]any{})
	if r.code != 200 || r.body["crlVerify"] != true {
		t.Fatalf("revoke: %d %s", r.code, r.raw)
	}
	revoked, _ := (pki.Dir{Path: filepath.Join(e.dir, "pki")}).Revoked()
	if len(revoked) != 1 {
		t.Errorf("CRL has %d entries", len(revoked))
	}
	if r := c.do("GET", "/api/clients/laptop/profile", nil); r.code != 404 {
		t.Errorf("profile of a revoked client: %d", r.code)
	}
}

func TestProfileMatchesServer(t *testing.T) {
	dir := t.TempDir()
	d := pki.Dir{Path: filepath.Join(dir, "keys")}
	if err := d.Init("server", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GenKey(pki.WrapTLSCryptV2); err != nil {
		t.Fatal(err)
	}
	conf := strings.NewReplacer("pki/", "keys/", "crl-verify keys/crl.pem\n", "",
		"dev tun\n", "dev tun\ntls-crypt-v2 keys/tls-crypt-v2.key\nauth SHA256\ncompress lz4-v2\n").Replace(baseConf)
	e := newEnvIn(t, dir, conf)
	c := e.client()
	c.login()
	if r := c.do("POST", "/api/clients", map[string]any{"name": "phone"}); r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	r := c.do("GET", "/api/clients/phone/profile?remote=vpn.example.com", nil)
	if r.code != 200 {
		t.Fatalf("profile: %d %s", r.code, r.raw)
	}
	p, _ := config.ParseString(string(r.raw))
	if _, ok := p.Inline["tls-crypt-v2"]; !ok || !d.Exists(pki.TLSCryptV2ClientKeyFile("phone")) {
		t.Error("tls-crypt-v2 client key missing")
	}
	if p.String("auth", "") != "SHA256" || p.String("compress", "") != "lz4-v2" || p.All("remote")[0].Arg(0) != "vpn.example.com" {
		t.Errorf("profile options:\n%s", r.raw)
	}
}

func TestCCDAndUsers(t *testing.T) {
	e := newEnv(t, baseConf)
	c := e.client()
	c.login()
	ccd := filepath.Join(e.dir, "ccd", "laptop")
	r := c.do("PUT", "/api/ccd/laptop", map[string]any{"settings": map[string]any{"ip": "10.99.0.5"}})
	if r.code != 422 {
		t.Fatalf("address outside the subnet: %d %s", r.code, r.raw)
	}
	if _, err := os.Stat(ccd); err == nil {
		t.Fatal("invalid client-config-dir file written")
	}
	r = c.do("PUT", "/api/ccd/laptop", map[string]any{"settings": map[string]any{"ip": "10.77.0.50", "iroutes": []string{"192.168.5.0/24"}, "push": []string{"route 192.168.6.0 255.255.255.0"}}})
	if r.code != 200 {
		t.Fatalf("ccd: %d %s", r.code, r.raw)
	}
	b, _ := os.ReadFile(ccd)
	if string(b) != "ifconfig-push 10.77.0.50 255.255.255.0\niroute 192.168.5.0 255.255.255.0\npush \"route 192.168.6.0 255.255.255.0\"\n" {
		t.Errorf("ccd file:\n%s", b)
	}
	g := c.do("GET", "/api/ccd/laptop", nil)
	if g.body["settings"].(map[string]any)["ip"] != "10.77.0.50" {
		t.Errorf("ccd settings: %s", g.raw)
	}
	if r := c.do("GET", "/api/ccd/.hidden", nil); r.code != 400 {
		t.Errorf("ccd path traversal: %d", r.code)
	}
	if r := c.do("DELETE", "/api/ccd/laptop", nil); r.code != 200 {
		t.Errorf("delete ccd: %d", r.code)
	}

	file := filepath.Join(e.dir, "users")
	if r := c.do("POST", "/api/users", map[string]string{"name": "carol", "password": "c1"}); r.code != 201 {
		t.Fatalf("add user: %d %s", r.code, r.raw)
	}
	if r := c.do("PUT", "/api/users/carol", map[string]string{"password": "c2"}); r.code != 200 {
		t.Fatalf("set password: %d", r.code)
	}
	db, _ := users.Open(file)
	if db.Verify("carol", "c2") != nil {
		t.Error("new password does not work")
	}
	if r := c.do("DELETE", "/api/users/carol", nil); r.code != 200 {
		t.Fatalf("delete user: %d", r.code)
	}
	if r := c.do("DELETE", "/api/users/carol", nil); r.code != 404 {
		t.Errorf("delete missing user: %d", r.code)
	}
	l := c.do("GET", "/api/users", nil)
	if l.body["configured"] != true || len(l.body["users"].([]any)) != 1 {
		t.Errorf("users: %s", l.raw)
	}
}

func TestLogsAndStatic(t *testing.T) {
	e := newEnv(t, baseConf)
	c := e.client()
	c.login()
	r := c.do("GET", "/api/logs", nil)
	if r.code != 200 || !strings.Contains(string(r.raw), "virtual network up") {
		t.Errorf("logs: %d %s", r.code, r.raw)
	}
	for _, p := range []string{"/", "/js/app.js", "/css/app.css", "/favicon.svg"} {
		res, err := http.Get(e.ts.URL + p)
		if err != nil || res.StatusCode != 200 {
			t.Errorf("GET %s: %v %v", p, err, res.Status)
		}
		res.Body.Close()
	}
	if r := c.do("GET", "/api/nope", nil); r.code != 404 {
		t.Errorf("unknown endpoint: %d", r.code)
	}
}
