# softvpn

An OpenVPN-compatible VPN server that runs entirely in userspace. It needs no
TUN device, no iptables, no `NET_ADMIN`, and no root, so it runs in a fully
locked-down Docker container (`cap_drop: [ALL]`, non-root, read-only root
filesystem). Stock OpenVPN clients (2.5 and 2.6) connect to it unmodified.

Routing and NAT happen inside the process:

```
 openvpn client ──TLS/UDP or TCP──▶ softvpn ──▶ virtual router
                                                 ├─ 10.8.0.x (other client) ─▶ that client's tunnel
                                                 ├─ 10.8.0.1 (gateway)      ─▶ ping replies, DNS relay
                                                 └─ anything else           ─▶ userspace TCP/IP stack (gVisor)
                                                                                 └─ ordinary sockets ─▶ host's default route
```

Every TCP connection and UDP flow a client opens is terminated by an
in-process TCP/IP stack ([gVisor netstack](https://gvisor.dev)) and re-opened
as a normal socket on the host. Traffic therefore leaves through the server's
default gateway with the server's address, like masquerading NAT, and no
network configuration is needed on the host. ICMP echo (`ping`) is NATed
through unprivileged ICMP sockets, which Docker allows by default.

## Quick start

Images for amd64 and arm64 are published to Docker Hub as
[`alancnet/softvpn`](https://hub.docker.com/r/alancnet/softvpn). Every push to
`main` and every `v*` tag publishes, once the tests pass (see
[.github/workflows/docker.yml](.github/workflows/docker.yml)). To build it
yourself, run `docker build -t alancnet/softvpn .`.

```sh
# CA, server certificate, and a ready-to-use client profile
docker volume create softvpn-pki
docker run --rm -v softvpn-pki:/pki alancnet/softvpn \
  pki init -dir /pki -clients laptop -remote vpn.example.com

# Run it: no capabilities, no devices, not root
docker run -d --name softvpn --read-only --cap-drop ALL \
  --security-opt no-new-privileges -p 1194:1194/udp \
  -v softvpn-pki:/pki:ro -v $PWD/server.conf:/etc/softvpn/server.conf:ro \
  alancnet/softvpn

# Hand /pki/laptop.ovpn to the client and run: openvpn --config laptop.ovpn
```

A minimal `server.conf` uses the same syntax as OpenVPN:

```
port 1194
proto udp
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ca   /pki/ca.crt
cert /pki/server.crt
key  /pki/server.key
keepalive 10 60
push "redirect-gateway def1"
push "dhcp-option DNS 10.8.0.1"
```

Any directive can also go on the command line, as with OpenVPN:
`softvpn server --config server.conf --verb 4`.

## Authentication

By default every client needs a certificate from the CA. Two optional
additions, both plain files that the server re-reads when they change:

**Revocation.** `pki init` writes an empty `crl.pem`, and
`softvpn pki revoke NAME` adds a client's certificate to it (and moves its
files to `revoked/`, so the name can be issued again). With
`crl-verify /pki/crl.pem` the server refuses revoked certificates in every TLS
handshake, renegotiations included, and disconnects already-connected clients
within seconds of the CRL changing. Any PEM or DER CRL signed by the CA works.

**Usernames and passwords.** The image has no shell and cannot load plugins,
so instead of `auth-user-pass-verify` scripts softvpn has a built-in user
database: an htpasswd-style file of bcrypt hashes (`htpasswd -B` files work
too).

```sh
docker run --rm -i -v softvpn-pki:/pki alancnet/softvpn user add -file /pki/users alice   # password on stdin
docker run --rm -v softvpn-pki:/pki alancnet/softvpn user list -file /pki/users
#   user passwd|del -file FILE [-password PW] NAME
docker run --rm -v softvpn-pki:/pki alancnet/softvpn \
  pki profile -dir /pki -remote vpn.example.com -auth-user-pass -no-cert alice > alice.ovpn
```

```
auth-user-pass-file /pki/users
verify-client-cert none         # or optional (certificate if given), require (default)
username-as-common-name         # the session (and its client-config-dir file) is named after the user
auth-gen-token                  # renegotiate and reconnect with a token instead of the password
```

Credentials are checked on every key exchange, so a changed password or a
deleted user takes effect at the client's next renegotiation; deleting a user
also disconnects their sessions immediately. `auth-user-pass-optional` lets
clients with a valid certificate skip the password. `auth-gen-token [LIFETIME]`
tokens are signed with a random per-start secret (or `auth-gen-token-secret
FILE`) and bound to the user's current password hash; stock clients fall
back to their cached password when a token is refused, for example after a
server restart. Without `username-as-common-name`, password-only clients
share OpenVPN's common name `UNDEF` (add `duplicate-cn` in that case).
`plugin`, `auth-user-pass-verify` and other script hooks are rejected at
startup with a pointer to these directives.

## End-to-end test

```sh
test/run.sh            # builds, runs 55 checks, tears down
KEEP=1 test/run.sh     # leave it running afterwards
```

[test/docker-compose.yml](test/docker-compose.yml) sets up:

| container | network | notes |
|---|---|---|
| `server` | `wan` + `edge` | softvpn; uid 65534, all capabilities dropped, read-only, no devices |
| `web` | `wan` only | stands in for the internet: HTTP, bulk download, UDP echo |
| `client1` | `edge` only | stock OpenVPN 2.6 over UDP; rekeys every 15 s |
| `client2` | `edge` only | stock OpenVPN 2.6 over TCP; static IP from `client-config-dir` |
| `client3` | `edge` only | stock OpenVPN 2.5 with ChaCha20-Poly1305 and legacy key derivation |
| `client4` | `edge` only | stock OpenVPN 2.6, no certificate: username/password (`auth-user-pass`), rekeys every 15 s with an auth token |
| `client5` | `edge` only | same profile, wrong password |
| `client6` | `edge` only | a revoked client certificate |
| `probe` | `edge` only | no VPN; proves `edge` can't reach anything by itself |
| `tapserver` | `wan` + `tapedge` | softvpn with `dev tap` and `server-bridge` ([server-tap.conf](test/server-tap.conf)); locked down like `server` |
| `tapclient1` | `tapedge` only | stock OpenVPN 2.6 with `dev tap` over UDP |
| `tapclient2` | `tapedge` only | stock OpenVPN 2.5 with `dev tap` over TCP |
| `dhcpserver` | `wan` + `dhcpedge` | softvpn with `dev tap` and `server-bridge` without arguments: DHCP only ([server-dhcp.conf](test/server-dhcp.conf)) |
| `tapclient3` | `dhcpedge` only | stock OpenVPN 2.6 with `dev tap`, configured by `udhcpc` (which also needs `NET_RAW`) |

`edge` is a Docker `internal` network, so anything a client reaches on `wan`
or the internet has gone through the tunnel and the server's software NAT.
The checks cover: container privileges (the server process has an empty
effective capability set), address assignment, `redirect-gateway`, TCP, UDP,
and ICMP NAT (the web server sees the server's address), DNS through the VPN
gateway, client-to-client routing, a 50 MB transfer with throughput, real
HTTPS to example.com through the server's default gateway, and traffic
continuing across key renegotiations, password login and AUTH_FAILED for a
wrong password, re-authentication with an auth token on renegotiation,
refusal of a revoked certificate, and live changes: revoking a connected
client's certificate (`pki revoke`) and deleting a connected user
(`user del`) disconnect them within seconds, without a server restart. The
one-shot `pki`, `pki-revoke`, `pki-alice` and `users` containers set up the
PKI, CRL and user database with the server image itself (it has no shell).
In TAP mode they cover the same
lockdown, `server-bridge` pool addresses, ARP resolution of the gateway's
MAC, ping, `redirect-gateway`, TCP/UDP/ICMP NAT and DNS, client-to-client
over the Ethernet segment (the peer's MAC in the ARP cache), a 50 MB
transfer, dropping a source address the server did not assign, and a DHCP
lease from the built-in DHCP server with OpenVPN's `route-gateway dhcp`.

No container is privileged. The OpenVPN *clients* get `/dev/net/tun` and the
single capability `NET_ADMIN`, because the stock client always creates a
kernel TUN interface. That requirement belongs to the client. The server needs
neither.

## Supported

- Transports: UDP and TCP. Several `proto` lines listen on each (a softvpn
  extension; OpenVPN takes only one).
- TLS 1.2/1.3 control channel with mutual certificate authentication, plus
  OpenVPN's control-channel reliability layer.
- Certificate revocation: `crl-verify FILE` (PEM or DER), re-read when it
  changes; `softvpn pki revoke` maintains it.
- Username/password authentication from a built-in user database instead of
  scripts or plugins: `auth-user-pass-file` (softvpn extension),
  `verify-client-cert none|optional|require`, `username-as-common-name`,
  `auth-user-pass-optional`, `auth-gen-token [LIFETIME]`,
  `auth-gen-token-secret`. See [Authentication](#authentication).
- Data channel: AES-256-GCM, AES-128-GCM, and CHACHA20-POLY1305, negotiated
  via `data-ciphers`; P_DATA_V2 with peer-id and client floating; 64-packet
  replay window.
- Key derivation: `tls-ekm` (RFC 5705, OpenVPN 2.6) and the legacy OpenVPN
  PRF (2.5).
- Client-initiated renegotiation (`reneg-sec`), with a 60 s overlap during
  which the old key still works.
- TAP (bridged) mode, `dev tap`: the server is a virtual Ethernet switch.
  It learns each client's MAC address, switches unicast frames between
  clients, and floods broadcast, multicast and unknown unicast, all only
  with `client-to-client` (without it, clients reach only the server). The
  server is a port on that switch with its own MAC: it answers ARP for the
  gateway address and routes and NATs exactly like tun mode, including as
  the default gateway for `redirect-gateway`. Each client may send only from
  the first MAC it uses and, for IPv4 and ARP, only from the address the
  server assigned; anything else, IPv6 and VLAN-tagged frames included, is
  dropped. Addresses:
  - `server-bridge GATEWAY NETMASK POOL_START POOL_END`: the gateway address
    and a pool, as in OpenVPN.
  - `server NETWORK NETMASK` works with `dev tap` too (gateway `.1`).
  - `server-bridge` without arguments (or `server-bridge nogw`, which omits
    the gateway): clients get no `ifconfig`, but `route-gateway dhcp`, and
    configure themselves by DHCP. softvpn answers DHCP itself, always with the
    address assigned to the session, and in this mode takes the range from
    `server` (default 10.8.0.0/24). The DHCP server also answers in the other
    modes, so a DHCP client on the tap interface gets its pushed address.
    It passes on pushed `dhcp-option DNS` and `DOMAIN`.
  - `lladdr MAC` sets the gateway's MAC address. The default,
    `02:00` followed by the gateway's IPv4 address, is stable across restarts.
  - `dev-type tap` with any `dev` name works too.
- `push`, `client-to-client`, `duplicate-cn`, `max-clients`, `keepalive`,
  `client-config-dir` (`ifconfig-push`, `push`, `push-reset`, `disable`),
  `status`, `verb`, `tun-mtu`, explicit-exit-notify, and push continuation
  for long option lists.
- softvpn extensions:
  - `upstream-dns IP[:PORT]`: where DNS sent to the gateway is relayed.
    Defaults to the host's `/etc/resolv.conf`, so in Docker clients resolve
    the same names the server can.
  - `nat-allow CIDR...` / `nat-deny CIDR...`: firewall for the soft NAT.
    Loopback, the VPN subnet, multicast, and link-local (cloud metadata) are
    always refused.

Directives that only matter to kernel OpenVPN (`dh`, `persist-tun`, `user`,
and similar) are accepted and ignored, so existing configs load. Directives
softvpn doesn't implement are rejected at startup.

## Not supported (yet)

- `tls-auth`, `tls-crypt`, and `tls-crypt-v2`: remove them from client profiles.
- Compression (`compress`, `comp-lzo`): clients must not enable it.
- Plugins and scripts (`plugin`, `auth-user-pass-verify`, `client-connect`,
  ...): use the built-in user database instead. Deferred authentication,
  `crl-verify DIR dir`, and `auth-gen-token`'s renewal window and
  `external-auth` aren't supported.
- IPv6 inside the tunnel, `iroute` (routing to networks behind a client),
  and CBC ciphers for pre-2.4 clients.
- In TAP mode: a client bridging a LAN behind it (more than one MAC per
  client), IPv6, and VLAN tags.

## Layout

| path | what |
|---|---|
| [cmd/softvpn](cmd/softvpn/main.go) | CLI: `server`, `pki init/client/profile/revoke/crl/list`, `user add/passwd/del/list` |
| [internal/ovpn](internal/ovpn) | OpenVPN protocol: packets, reliability layer, TLS-over-control-channel, key exchange, data-channel crypto, UDP/TCP transports |
| [internal/server](internal/server) | config, address pool, virtual router, soft-NAT policy, ICMP NAT; TAP mode's virtual switch and DHCP server |
| [internal/vnet](internal/vnet) | gVisor stack in promiscuous/spoofing mode, TCP/UDP forwarders (the NAT) |
| [internal/pki](internal/pki) | minimal CA (easy-rsa replacement), CRL, and `.ovpn` profile generation |
| [internal/users](internal/users) | user database for `auth-user-pass-file` (htpasswd-style bcrypt file) |
| [internal/config](internal/config) | OpenVPN config syntax: directives, quoting, inline `<ca>` blocks, argv |
