package webui

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/softvpn/softvpn/internal/config"
)

// Options configure the web UI. They come from the web-ui* directives in
// server.conf or on the command line:
//
//	web-ui ADDR                 listen address, e.g. 0.0.0.0:8443 (enables the UI)
//	web-ui-cert FILE            TLS certificate (default: self-signed, kept as web-ui.crt next to server.conf)
//	web-ui-key FILE             its key (web-ui.key)
//	web-ui-http                 plain HTTP, for use behind a TLS-terminating reverse proxy
//	web-ui-users FILE           administrators, htpasswd/bcrypt (default: web-ui.users next to server.conf)
//	web-ui-pki DIR              PKI directory for client certificates (default: the ca file's directory)
//	web-ui-remote HOST [PORT [PROTO]]  what generated profiles connect to
type Options struct {
	Addr        string
	CertFile    string // "" with KeyFile "": self-signed
	KeyFile     string
	HTTP        bool
	UsersFile   string // "": administrators only from SOFTVPN_WEB_PASSWORD
	PKIDir      string // "": no client management
	RemoteHost  string // "": the host name the browser used
	RemotePort  int    // 0: the server's port
	RemoteProto string // "": the server's first proto

	// ConfigDir is where the default files live (server.conf's directory).
	ConfigDir string
}

// ParseOptions reads the web UI directives. It returns nil if the UI is not
// enabled (no web-ui directive). configFile is the server's configuration
// file, if it has one; the defaults live next to it.
func ParseOptions(c *config.Config, configFile string) (*Options, error) {
	d, ok := c.Last("web-ui")
	if !ok {
		return nil, nil
	}
	if len(d.Args) != 1 {
		return nil, d.Errorf("expects one listen address, e.g. 0.0.0.0:8443")
	}
	if _, port, err := net.SplitHostPort(d.Arg(0)); err != nil || port == "" {
		return nil, d.Errorf("expects HOST:PORT (e.g. 0.0.0.0:8443 or :8443), not %q", d.Arg(0))
	}
	o := &Options{Addr: d.Arg(0), HTTP: c.Has("web-ui-http")}
	if configFile != "" {
		o.ConfigDir = filepath.Dir(configFile)
	}
	path := func(name string) (string, error) {
		d, ok := c.Last(name)
		if !ok {
			return "", nil
		}
		if len(d.Args) != 1 {
			return "", d.Errorf("expects one file name")
		}
		return d.Path(0), nil
	}
	var err error
	if o.CertFile, err = path("web-ui-cert"); err != nil {
		return nil, err
	}
	if o.KeyFile, err = path("web-ui-key"); err != nil {
		return nil, err
	}
	if (o.CertFile == "") != (o.KeyFile == "") {
		return nil, fmt.Errorf("web-ui-cert and web-ui-key go together")
	}
	if o.UsersFile, err = path("web-ui-users"); err != nil {
		return nil, err
	}
	if o.UsersFile == "" && o.ConfigDir != "" {
		o.UsersFile = filepath.Join(o.ConfigDir, "web-ui.users")
	}
	if o.PKIDir, err = path("web-ui-pki"); err != nil {
		return nil, err
	}
	if o.PKIDir == "" {
		// The CA's directory, if the CA key is there too (softvpn pki init).
		if ca, ok := c.Last("ca"); ok && ca.Arg(0) != "" && ca.Arg(0) != "[inline]" {
			dir := filepath.Dir(ca.Path(0))
			if _, err := os.Stat(filepath.Join(dir, "ca.key")); err == nil {
				o.PKIDir = dir
			}
		}
	}
	if d, ok := c.Last("web-ui-remote"); ok {
		if len(d.Args) < 1 || len(d.Args) > 3 {
			return nil, d.Errorf("expects HOST [PORT [PROTO]]")
		}
		o.RemoteHost = d.Arg(0)
		if p := d.Arg(1); p != "" {
			if o.RemotePort, err = strconv.Atoi(p); err != nil || o.RemotePort < 1 || o.RemotePort > 65535 {
				return nil, d.Errorf("invalid port %q", p)
			}
		}
		if p := strings.ToLower(d.Arg(2)); p != "" {
			if p != "udp" && p != "tcp" {
				return nil, d.Errorf("proto must be udp or tcp")
			}
			o.RemoteProto = p
		}
	}
	return o, nil
}
