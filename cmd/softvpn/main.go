// Command softvpn is an OpenVPN-compatible VPN server that runs entirely in
// userspace: no TUN device, no iptables, no capabilities. Stock OpenVPN
// clients connect to it; their traffic is routed and NATed by an in-process
// TCP/IP stack.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/pki"
	"github.com/softvpn/softvpn/internal/server"
)

var version = "dev"

const usage = `softvpn - userspace OpenVPN-compatible server

Usage:
  softvpn server --config server.conf [--directive args ...]
  softvpn pki init    [-dir pki] [-name server] [-san host,ip,...] [-days N] [-wrap MODE]
                      [-clients a,b,... [-remote HOST [-port 1194] [-proto udp|tcp]]]
  softvpn pki client  [-dir pki] [-days N] [-wrap MODE] NAME
  softvpn pki profile [-dir pki] [-wrap MODE] -remote HOST [-port 1194] [-proto udp|tcp] NAME
  softvpn pki genkey  [-dir pki] [-out FILE|-] tls-auth|tls-crypt|tls-crypt-v2
  softvpn pki genkey  [-dir pki] [-out FILE|-] [-metadata TEXT] tls-crypt-v2-client NAME
  softvpn version

The server reads OpenVPN server.conf directives; any directive can also be
given on the command line as --name args. "pki profile" prints a ready-to-use
.ovpn file with the certificates inlined, for the stock openvpn client;
"pki init -clients ... -remote ..." writes them as DIR/NAME.ovpn.

-wrap tls-auth|tls-crypt|tls-crypt-v2 protects the control channel: it
creates the key (DIR/ta.key, DIR/tc.key or DIR/tls-crypt-v2.key, plus
DIR/NAME-tls-crypt-v2.key per client) if missing and embeds the client's
key in profiles. "pki genkey" makes the same keys in openvpn's formats.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "pki":
		err = runPKI(os.Args[2:])
	case "version":
		fmt.Println("softvpn", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		if strings.HasPrefix(os.Args[1], "--") { // "softvpn --config x", like openvpn
			err = runServer(os.Args[1:])
		} else {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "softvpn:", err)
		os.Exit(1)
	}
}

func runServer(args []string) error {
	c, err := config.ParseArgs(args)
	if err != nil {
		return err
	}
	cfg, err := server.Load(c)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	switch {
	case cfg.Verb >= 4:
		level = slog.LevelDebug
	case cfg.Verb == 0:
		level = slog.LevelWarn
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	srv, err := server.New(cfg, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("softvpn starting", "version", version, "uid", os.Getuid())
	return srv.Run(ctx)
}

func runPKI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("pki: expected init, client, profile or genkey")
	}
	fs := flag.NewFlagSet("pki "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", "pki", "PKI directory")
	days := fs.Int("days", 3650, "certificate validity in days")
	shared := fs.Bool("shared", false, "make keys and profiles world-readable (demo volumes shared between users only)")
	remote := fs.String("remote", "", "server host name or IP that clients connect to (for profiles)")
	port := fs.Int("port", 1194, "server port (for profiles)")
	proto := fs.String("proto", "udp", "udp or tcp (for profiles)")
	wrapName := fs.String("wrap", "", "control-channel protection: tls-auth, tls-crypt or tls-crypt-v2")
	var wrap pki.Wrap
	validity := func() time.Duration { return time.Duration(*days) * 24 * time.Hour }
	d := func() pki.Dir { return pki.Dir{Path: *dir, Shared: *shared, Wrap: wrap} }
	parse := func() error {
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var err error
		wrap, err = pki.ParseWrap(*wrapName)
		return err
	}
	// wrapKeys creates missing control-channel keys for these clients.
	wrapKeys := func(server bool, clients ...string) error {
		if server {
			if made, err := d().GenKey(wrap); err != nil {
				return err
			} else if made {
				fmt.Fprintf(os.Stderr, "created %s key %s\n", wrap, filepath.Join(*dir, wrap.KeyFile()))
			}
		}
		if wrap != pki.WrapTLSCryptV2 {
			return nil
		}
		for _, c := range clients {
			if made, err := d().GenTLSCryptV2ClientKey(c, nil); err != nil {
				return err
			} else if made {
				fmt.Fprintf(os.Stderr, "created %s\n", filepath.Join(*dir, pki.TLSCryptV2ClientKeyFile(c)))
			}
		}
		return nil
	}

	switch args[0] {
	case "init":
		name := fs.String("name", "server", "server certificate common name")
		san := fs.String("san", "", "extra comma-separated DNS names / IPs for the server certificate")
		clients := fs.String("clients", "", "comma-separated client certificates to issue (with -remote, also writes NAME.ovpn)")
		if err := parse(); err != nil {
			return err
		}
		// Idempotent, so it can run on every container start.
		if d().Exists("ca.crt") {
			fmt.Fprintf(os.Stderr, "CA already exists in %s, keeping it\n", *dir)
		} else {
			if err := d().Init(*name, splitList(*san), validity()); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "created CA and server certificate %q in %s\n", *name, *dir)
		}
		if err := wrapKeys(true, splitList(*clients)...); err != nil {
			return err
		}
		for _, c := range splitList(*clients) {
			if !d().Exists(c + ".crt") {
				if err := d().Issue(c, pki.RoleClient, nil, validity()); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "created client certificate %q\n", c)
			}
			if *remote != "" {
				if err := d().WriteProfile(c, *remote, *port, *proto); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "wrote %s\n", filepath.Join(*dir, c+".ovpn"))
			}
		}
	case "client":
		if err := parse(); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("pki client: expected NAME")
		}
		if err := d().Issue(fs.Arg(0), pki.RoleClient, nil, validity()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "created client certificate %q in %s\n", fs.Arg(0), *dir)
		if err := wrapKeys(false, fs.Arg(0)); err != nil {
			return err
		}
	case "profile":
		if err := parse(); err != nil {
			return err
		}
		if fs.NArg() != 1 || *remote == "" {
			return fmt.Errorf("pki profile: expected -remote HOST and NAME")
		}
		if err := wrapKeys(false, fs.Arg(0)); err != nil {
			return err
		}
		p, err := d().Profile(fs.Arg(0), *remote, *port, *proto)
		if err != nil {
			return err
		}
		fmt.Print(p)
	case "genkey":
		out := fs.String("out", "", "write the key to FILE (- for stdout) instead of into -dir")
		metadata := fs.String("metadata", "", "tls-crypt-v2-client: user data for the server (default: creation time)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return genKey(d(), *out, *metadata, fs.Args())
	default:
		return fmt.Errorf("pki: unknown command %q", args[0])
	}
	return nil
}

// genKey implements "pki genkey": by default keys go into the PKI directory
// under their standard names and existing ones are kept.
func genKey(d pki.Dir, out, metadata string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("pki genkey: expected tls-auth, tls-crypt, tls-crypt-v2 or tls-crypt-v2-client NAME")
	}
	var md []byte
	if metadata != "" {
		md = []byte(metadata)
	}
	var key []byte
	var err error
	switch args[0] {
	case "tls-auth", "tls-crypt", "tls-crypt-v2", "tls-crypt-v2-server":
		if len(args) != 1 {
			return fmt.Errorf("pki genkey %s: unexpected arguments", args[0])
		}
		w := pki.Wrap(strings.TrimSuffix(args[0], "-server"))
		if out == "" {
			made, err := d.GenKey(w)
			if err == nil {
				reportKey(d, w.KeyFile(), made)
			}
			return err
		}
		key, err = pki.NewKey(w)
	case "tls-crypt-v2-client":
		if len(args) != 2 {
			return fmt.Errorf("pki genkey tls-crypt-v2-client: expected NAME")
		}
		if out == "" {
			made, err := d.GenTLSCryptV2ClientKey(args[1], md)
			if err == nil {
				reportKey(d, pki.TLSCryptV2ClientKeyFile(args[1]), made)
			}
			return err
		}
		var srv []byte
		if srv, err = d.Read(pki.TLSCryptV2ServerKeyFile); err == nil {
			key, err = pki.NewTLSCryptV2ClientKey(srv, md)
		}
	default:
		return fmt.Errorf("pki genkey: unknown key type %q", args[0])
	}
	if err != nil {
		return err
	}
	if out == "-" {
		_, err = os.Stdout.Write(key)
		return err
	}
	return os.WriteFile(out, key, 0o600)
}

func reportKey(d pki.Dir, file string, made bool) {
	if made {
		fmt.Fprintf(os.Stderr, "created %s\n", filepath.Join(d.Path, file))
	} else {
		fmt.Fprintf(os.Stderr, "%s already exists, keeping it\n", filepath.Join(d.Path, file))
	}
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
