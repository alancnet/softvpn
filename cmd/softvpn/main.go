// Command softvpn is an OpenVPN-compatible VPN server that runs entirely in
// userspace: no TUN device, no iptables, no capabilities. Stock OpenVPN
// clients connect to it; their traffic is routed and NATed by an in-process
// TCP/IP stack.
package main

import (
	"bufio"
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
	"github.com/softvpn/softvpn/internal/users"
)

var version = "dev"

const usage = `softvpn - userspace OpenVPN-compatible server

Usage:
  softvpn server --config server.conf [--directive args ...]
  softvpn pki init    [-dir pki] [-name server] [-san host,ip,...] [-days N]
                      [-clients a,b,... [-remote HOST [-port 1194] [-proto udp|tcp]
                       [-auth-user-pass] [-no-cert]]]
  softvpn pki client  [-dir pki] [-days N] NAME
  softvpn pki profile [-dir pki] -remote HOST [-port 1194] [-proto udp|tcp]
                      [-auth-user-pass] [-no-cert] NAME
  softvpn pki revoke  [-dir pki] [-days N] NAME
  softvpn pki crl     [-dir pki] [-days N]
  softvpn pki list    [-dir pki]
  softvpn user add|passwd|del -file FILE [-password PASSWORD] NAME
  softvpn user list -file FILE
  softvpn version

The server reads OpenVPN server.conf directives; any directive can also be
given on the command line as --name args. "pki profile" prints a ready-to-use
.ovpn file with the certificates inlined, for the stock openvpn client;
"pki init -clients ... -remote ..." writes them as DIR/NAME.ovpn.
-auth-user-pass makes the client ask for a username and password; -no-cert
leaves out the client certificate (for "verify-client-cert none").

"pki revoke" adds a client certificate to DIR/crl.pem (for crl-verify) and
moves its files to DIR/revoked/; "pki crl" re-signs the CRL. "user" manages
the users file of auth-user-pass-file; without -password, the password is
read from the first line of standard input.
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
	case "user":
		err = runUser(os.Args[2:])
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
		return fmt.Errorf("pki: expected init, client or profile")
	}
	fs := flag.NewFlagSet("pki "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", "pki", "PKI directory")
	days := fs.Int("days", 3650, "certificate validity in days")
	shared := fs.Bool("shared", false, "make keys and profiles world-readable (demo volumes shared between users only)")
	remote := fs.String("remote", "", "server host name or IP that clients connect to (for profiles)")
	port := fs.Int("port", 1194, "server port (for profiles)")
	proto := fs.String("proto", "udp", "udp or tcp (for profiles)")
	authUserPass := fs.Bool("auth-user-pass", false, "profiles ask for a username and password (for profiles)")
	noCert := fs.Bool("no-cert", false, "profiles without a client certificate, for verify-client-cert none (for profiles)")
	validity := func() time.Duration { return time.Duration(*days) * 24 * time.Hour }
	d := func() pki.Dir { return pki.Dir{Path: *dir, Shared: *shared} }
	popts := func() pki.ProfileOptions { return pki.ProfileOptions{AuthUserPass: *authUserPass, NoCert: *noCert} }

	switch args[0] {
	case "init":
		name := fs.String("name", "server", "server certificate common name")
		san := fs.String("san", "", "extra comma-separated DNS names / IPs for the server certificate")
		clients := fs.String("clients", "", "comma-separated client certificates to issue (with -remote, also writes NAME.ovpn)")
		if err := fs.Parse(args[1:]); err != nil {
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
		if !d().Exists(pki.CRLFile) { // PKI directories from before CRL support
			if err := d().WriteCRL(validity()); err != nil {
				return err
			}
		}
		for _, c := range splitList(*clients) {
			if !*noCert && !d().Exists(c+".crt") {
				if err := d().Issue(c, pki.RoleClient, nil, validity()); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "created client certificate %q\n", c)
			}
			if *remote != "" {
				if err := d().WriteProfile(c, *remote, *port, *proto, popts()); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "wrote %s\n", filepath.Join(*dir, c+".ovpn"))
			}
		}
	case "client":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("pki client: expected NAME")
		}
		if err := d().Issue(fs.Arg(0), pki.RoleClient, nil, validity()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "created client certificate %q in %s\n", fs.Arg(0), *dir)
	case "profile":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 || *remote == "" {
			return fmt.Errorf("pki profile: expected -remote HOST and NAME")
		}
		p, err := d().Profile(fs.Arg(0), *remote, *port, *proto, popts())
		if err != nil {
			return err
		}
		fmt.Print(p)
	case "revoke":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("pki revoke: expected NAME")
		}
		if err := d().Revoke(fs.Arg(0), validity()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "revoked %q; wrote %s\n", fs.Arg(0), filepath.Join(*dir, pki.CRLFile))
	case "crl":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := d().WriteCRL(validity()); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", filepath.Join(*dir, pki.CRLFile))
	case "list":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		certs, err := d().List()
		if err != nil {
			return err
		}
		fmt.Printf("%-24s %-7s %-10s %-20s %s\n", "NAME", "ROLE", "EXPIRES", "STATUS", "SERIAL")
		for _, c := range certs {
			role, status := "server", "valid"
			if c.Client {
				role = "client"
			}
			if c.Revoked {
				status = "revoked " + c.RevokedAt.Format("2006-01-02")
			} else if time.Now().After(c.NotAfter) {
				status = "expired"
			}
			fmt.Printf("%-24s %-7s %-10s %-20s %X\n", c.Name, role, c.NotAfter.Format("2006-01-02"), status, c.Serial)
		}
	default:
		return fmt.Errorf("pki: unknown command %q", args[0])
	}
	return nil
}

func runUser(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("user: expected add, passwd, del or list")
	}
	fs := flag.NewFlagSet("user "+args[0], flag.ContinueOnError)
	file := fs.String("file", "", "users file (the server's auth-user-pass-file)")
	password := fs.String("password", "", "the password (default: read a line from standard input)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("user %s: -file is required", args[0])
	}
	if args[0] == "list" {
		names, err := users.List(*file)
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("user %s: expected NAME", args[0])
	}
	name := fs.Arg(0)
	readPassword := func() (string, error) {
		if *password != "" {
			return *password, nil
		}
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintf(os.Stderr, "password for %s (will echo): ", name)
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	switch args[0] {
	case "add", "passwd":
		pw, err := readPassword()
		if err != nil {
			return err
		}
		if args[0] == "add" {
			err = users.Add(*file, name, pw)
		} else {
			err = users.SetPassword(*file, name, pw)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: user %q saved\n", *file, name)
	case "del":
		if err := users.Delete(*file, name); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: user %q deleted\n", *file, name)
	default:
		return fmt.Errorf("user: unknown command %q", args[0])
	}
	return nil
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
