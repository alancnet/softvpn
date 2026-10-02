# softvpn

**An OpenVPN server that needs no privileges.** No TUN device, no
iptables, no `NET_ADMIN`, no root: it runs in a fully locked-down container
(`--cap-drop ALL`, non-root, read-only filesystem) and stock OpenVPN clients
connect to it unmodified.

[![docker](https://github.com/alancnet/softvpn/actions/workflows/docker.yml/badge.svg)](https://github.com/alancnet/softvpn/actions/workflows/docker.yml)
[![Docker Hub](https://img.shields.io/docker/pulls/alancnet/softvpn?label=docker%20hub)](https://hub.docker.com/r/alancnet/softvpn)

Routing and NAT happen inside the process. Each connection a client makes is
terminated by an in-process TCP/IP stack and re-opened as an ordinary socket,
so client traffic leaves through the host's default route without any host
network configuration. That makes it a fit for places where a regular
OpenVPN server can't run: unprivileged containers, PaaS platforms,
Kubernetes pods without `NET_ADMIN`, or anywhere you'd rather not hand a VPN
daemon root.

## Features

- Speaks the OpenVPN protocol: UDP and TCP, TLS with client certificates,
  AES-GCM and ChaCha20-Poly1305 (plus CBC ciphers for old clients),
  tls-auth / tls-crypt / tls-crypt-v2, compression framing, renegotiation.
- Reads OpenVPN `server.conf` files; kernel-only directives are accepted and
  ignored.
- Routed (`dev tun`) and bridged (`dev tap`) modes, IPv6 inside the tunnel,
  client-to-client traffic, networks behind clients (`iroute`).
- Certificate, username/password, or both, with live revocation.
- A built-in CA that creates certificates, keys and ready-to-use `.ovpn`
  profiles — no easy-rsa, no `openvpn` binary.
- An optional web UI for status, configuration and client profiles.
- A single static binary; the image is `FROM scratch`, for amd64 and arm64.

Tested with stock OpenVPN clients 2.3 through 2.6.
See [compatibility](docs/compatibility.md) for what isn't supported.

## Quick start

```sh
docker volume create softvpn

# A CA, a server certificate, and a profile for one client
docker run --rm -v softvpn:/pki alancnet/softvpn \
  pki init -dir /pki -clients laptop -remote vpn.example.com

# A server.conf next to them (the image has no shell, so use any small image to write it)
docker run --rm -i -v softvpn:/pki alpine \
  sh -c 'cat > /pki/server.conf && chown 65534:65534 /pki/server.conf' <<'EOF'
port 1194
proto udp
dev tun
server 10.8.0.0 255.255.255.0
ca   /pki/ca.crt
cert /pki/server.crt
key  /pki/server.key
crl-verify /pki/crl.pem
keepalive 10 60
push "redirect-gateway def1"
push "dhcp-option DNS 10.8.0.1"
EOF

# Run it, locked down
docker run -d --name softvpn --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 1194:1194/udp -v softvpn:/pki \
  alancnet/softvpn server --config /pki/server.conf

# Fetch the client profile, then on the client: openvpn --config laptop.ovpn
docker run --rm -v softvpn:/pki alpine cat /pki/laptop.ovpn > laptop.ovpn
```

Replace `vpn.example.com` with the address clients will use to reach the
server. More clients: `docker run --rm -v softvpn:/pki alancnet/softvpn pki
init -dir /pki -clients phone -remote vpn.example.com` (existing files are
kept). See [clients and certificates](docs/clients.md).

### Web UI

Add `--web-ui 0.0.0.0:8443` and `-p 8443:8443`, then open
`https://your-server:8443/`. The admin password is printed once, on first
start:

```sh
docker logs softvpn 2>&1 | grep 'administrator account'
```

The UI shows connected clients, edits and applies the configuration, and
creates, downloads and revokes client profiles. It needs the volume mounted
read-write, as above. See [web UI](docs/web-ui.md).

## How it works

```
openvpn client ──UDP/TCP──▶ softvpn ──▶ virtual router
                                          ├─ another client's address ─▶ that client
                                          ├─ the gateway (10.8.0.1)    ─▶ ping, DNS relay
                                          └─ anything else ─▶ userspace TCP/IP stack ─▶ host sockets ─▶ internet
```

The OpenVPN protocol is implemented in Go. Decrypted packets go to a virtual
router; packets bound for the outside world go into a
[gVisor](https://gvisor.dev) network stack, which accepts every TCP
connection and UDP flow and relays it over a normal socket, much like
masquerading NAT. Ping uses unprivileged ICMP sockets. More in
[how it works](docs/how-it-works.md).

The trade-off is performance: every connection is relayed in userspace.
Expect hundreds of Mbit/s rather than line rate.

## Documentation

- [Configuration reference](docs/configuration.md): supported directives and
  softvpn's extensions
- [Clients and certificates](docs/clients.md): profiles, revocation,
  passwords, control-channel keys
- [Web UI](docs/web-ui.md)
- [How it works](docs/how-it-works.md): architecture and security model
- [Compatibility](docs/compatibility.md): client versions and known gaps
- [Development](docs/development.md): building, the test suite, releases

## Building

```sh
go build ./cmd/softvpn          # Go 1.22+
docker build -t softvpn .
test/run.sh                     # end-to-end tests with real OpenVPN clients (Docker)
```
