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
  softvpn pki init    [-dir pki] [-name server] [-san host,ip,...] [-days N]
                      [-clients a,b,... [-remote HOST [-port 1194] [-proto udp|tcp]]]
  softvpn pki client  [-dir pki] [-days N] NAME
  softvpn pki profile [-dir pki] -remote HOST [-port 1194] [-proto udp|tcp] NAME
  softvpn version

The server reads OpenVPN server.conf directives; any directive can also be
given on the command line as --name args. "pki profile" prints a ready-to-use
.ovpn file with the certificates inlined, for the stock openvpn client;
"pki init -clients ... -remote ..." writes them as DIR/NAME.ovpn.
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
		return fmt.Errorf("pki: expected init, client or profile")
	}
	fs := flag.NewFlagSet("pki "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", "pki", "PKI directory")
	days := fs.Int("days", 3650, "certificate validity in days")
	shared := fs.Bool("shared", false, "make keys and profiles world-readable (demo volumes shared between users only)")
	remote := fs.String("remote", "", "server host name or IP that clients connect to (for profiles)")
	port := fs.Int("port", 1194, "server port (for profiles)")
	proto := fs.String("proto", "udp", "udp or tcp (for profiles)")
	validity := func() time.Duration { return time.Duration(*days) * 24 * time.Hour }
	d := func() pki.Dir { return pki.Dir{Path: *dir, Shared: *shared} }

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
		p, err := d().Profile(fs.Arg(0), *remote, *port, *proto)
		if err != nil {
			return err
		}
		fmt.Print(p)
	default:
		return fmt.Errorf("pki: unknown command %q", args[0])
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
