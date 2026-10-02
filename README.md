# softvpn

An OpenVPN-compatible VPN server that runs entirely in userspace. It needs no
TUN device, no iptables, no `NET_ADMIN`, and no root, so it runs in a fully
locked-down Docker container (`cap_drop: [ALL]`, non-root, read-only root
filesystem). Stock OpenVPN clients (2.5 and 2.6) connect to it unmodified.

Routing and NAT happen inside the process:

```
 openvpn client ──TLS/UDP or TCP──▶ softvpn ──▶ virtual router (IPv4 and IPv6, longest-prefix match)
                                                 ├─ 10.8.0.x, fd00:8::x (other client) ─▶ that client's tunnel
                                                 ├─ iroute network (behind a client)   ─▶ that client's tunnel
                                                 ├─ 10.8.0.1, fd00:8::1 (gateway)      ─▶ ping replies, DNS relay
                                                 └─ anything else                      ─▶ userspace TCP/IP stack (gVisor)
                                                                                           └─ ordinary sockets ─▶ host's default route
```

Every TCP connection and UDP flow a client opens is terminated by an
in-process TCP/IP stack ([gVisor netstack](https://gvisor.dev)) and re-opened
as a normal socket on the host. Traffic therefore leaves through the server's
default gateway with the server's address, like masquerading NAT, and no
network configuration is needed on the host. ICMP echo (`ping`) is NATed
through unprivileged ICMP sockets, which Docker allows by default. IPv6 works
the same way (like NAT66): clients get IPv6 addresses inside the tunnel, and
their IPv6 traffic leaves through the host's own IPv6 connectivity, if it has
any.

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

### IPv6

```
server-ipv6 fd00:8::/64
push "redirect-gateway def1 ipv6"     # or push "route-ipv6 2000::/3"
```

The gateway is `fd00:8::1`; it answers ping and relays DNS like `10.8.0.1`.
Each client's IPv6 address follows its IPv4 one, numbered like OpenVPN's pool
(`10.8.0.2` gets `fd00:8::1000`, `10.8.0.3` gets `fd00:8::1001`, ...), or is
set per client with `ifconfig-ipv6-push fd00:8::20/64` in its
`client-config-dir` file. Clients reach each other over IPv6 with
`client-to-client`, and everything else is NATed out through the host's IPv6
(TCP, UDP, and ICMPv6 echo through unprivileged ping sockets). Docker
containers only have IPv6 on networks created with `enable_ipv6`.

The server listens on IPv4 and IPv6 for `proto udp`/`tcp` (and, as in
OpenVPN, `udp6`/`tcp6`); `udp4`/`tcp4` listen on IPv4 only.

### Networks behind a client (site-to-site)

A client can be the gateway to a LAN, as with OpenVPN's `iroute`. In
`server.conf`:

```
route 192.168.10.0 255.255.255.0          # the LAN is inside the VPN
route-ipv6 fd00:10::/64
push "route 192.168.10.0 255.255.255.0"   # other clients reach it via the VPN
push "route-ipv6 fd00:10::/64"
client-to-client
```

and in the gateway client's `client-config-dir` file:

```
iroute 192.168.10.0 255.255.255.0
iroute-ipv6 fd00:10::/64
```

The server routes packets for those networks to that client (longest prefix
wins; like all traffic between clients this needs `client-to-client`) and
accepts packets from it whose source is in them. Routes to a
client's own iroutes are left out of what it is pushed. `route` doesn't touch
any kernel routing table here; it marks the network as part of the VPN, so
while its client is offline it is unreachable instead of NATed out. The
gateway client forwards between the tunnel and its LAN (`ip_forward`), and
the LAN needs a route back to the VPN subnet through it, as with OpenVPN.

## End-to-end test

```sh
test/run.sh            # builds, runs 44 checks, tears down
KEEP=1 test/run.sh     # leave it running afterwards
```

[test/docker-compose.yml](test/docker-compose.yml) sets up:

| container | network | notes |
|---|---|---|
| `server` | `wan` + `edge` | softvpn; uid 65534, all capabilities dropped, read-only, no devices |
| `web` | `wan` only | stands in for the internet: HTTP, bulk download, UDP echo (IPv4 and IPv6) |
| `client1` | `edge` only | stock OpenVPN 2.6 over UDP; rekeys every 15 s |
| `client2` | `edge` only | stock OpenVPN 2.6 over TCP; static IPv4 and IPv6 from `client-config-dir` |
| `client3` | `edge` only | stock OpenVPN 2.5 over IPv6 (`udp6`) with ChaCha20-Poly1305 and legacy key derivation |
| `client4` | `edge` + `lan` | stock OpenVPN 2.6; site gateway for `lan` (`iroute`, `iroute-ipv6`), forwarding enabled |
| `lansvc` | `lan` only | a host on client4's LAN, with a route back to the VPN via client4 |
| `probe` | `edge` only | no VPN; proves `edge` can't reach anything by itself |

All three networks are dual-stack. `edge` and `lan` are Docker `internal`
networks, so anything a client reaches on `wan` or the internet has gone
through the tunnel and the server's software NAT.
The checks cover: container privileges (the server process has an empty
effective capability set), address assignment, `redirect-gateway`, TCP, UDP,
and ICMP NAT (the web server sees the server's address), DNS through the VPN
gateway, client-to-client routing, a 50 MB transfer with throughput, real
HTTPS to example.com through the server's default gateway, and traffic
continuing across key renegotiations. For IPv6: pool and static addresses,
ping to the IPv6 gateway, `redirect-gateway ipv6`, TCP, UDP and ICMPv6 NAT to
the web server's IPv6 address, DNS over IPv6, client-to-client over IPv6, and
an OpenVPN 2.5 client connecting to the server over IPv6. For `iroute`: other
clients reach `lansvc` behind client4 over IPv4 and IPv6 without NAT, and
client4 isn't pushed routes to its own LAN. Real IPv6 internet access is
checked too, but only warns if the host has none.

No container is privileged. The OpenVPN *clients* get `/dev/net/tun` and the
single capability `NET_ADMIN`, because the stock client always creates a
kernel TUN interface. That requirement belongs to the client. The server needs
neither.

## Supported

- Transports: UDP and TCP. Several `proto` lines listen on each (a softvpn
  extension; OpenVPN takes only one).
- TLS 1.2/1.3 control channel with mutual certificate authentication, plus
  OpenVPN's control-channel reliability layer.
- Data channel: AES-256-GCM, AES-128-GCM, and CHACHA20-POLY1305, negotiated
  via `data-ciphers`; P_DATA_V2 with peer-id and client floating; 64-packet
  replay window.
- Key derivation: `tls-ekm` (RFC 5705, OpenVPN 2.6) and the legacy OpenVPN
  PRF (2.5).
- Client-initiated renegotiation (`reneg-sec`), with a 60 s overlap during
  which the old key still works.
- IPv6 inside the tunnel: `server-ipv6`, `ifconfig-ipv6` pushed to clients,
  IPv6 client-to-client routing, and NAT of IPv6 TCP, UDP and ICMPv6 echo
  through the host's IPv6. Listening on IPv6: `proto udp`/`tcp` are
  dual-stack, as are `udp6`/`tcp6`; `udp4`/`tcp4` are IPv4 only.
- Networks behind clients: `route`, `route-ipv6`, and in `client-config-dir`
  `iroute` and `iroute-ipv6`, with longest-prefix-match routing and source
  address validation against each client's addresses and iroutes.
- `push`, `client-to-client`, `duplicate-cn`, `max-clients`, `keepalive`,
  `client-config-dir` (`ifconfig-push`, `ifconfig-ipv6-push`, `iroute`,
  `iroute-ipv6`, `push`, `push-reset`, `disable`), `status`, `verb`,
  `tun-mtu`, explicit-exit-notify, and push continuation for long option
  lists.
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
- `auth-user-pass` and plugins: authentication is by client certificate only.
- TAP/bridged mode and CBC ciphers for pre-2.4 clients.
- IPv6-only clients (every client gets an IPv4 address) and NAT64.
- Certificate revocation lists. To lock a client out, use `disable` in its
  `client-config-dir` file.

## Layout

| path | what |
|---|---|
| [cmd/softvpn](cmd/softvpn/main.go) | CLI: `server`, `pki init/client/profile` |
| [internal/ovpn](internal/ovpn) | OpenVPN protocol: packets, reliability layer, TLS-over-control-channel, key exchange, data-channel crypto, UDP/TCP transports |
| [internal/server](internal/server) | config, address pool, virtual router, soft-NAT policy, ICMP NAT |
| [internal/vnet](internal/vnet) | gVisor stack in promiscuous/spoofing mode, TCP/UDP forwarders (the NAT) |
| [internal/pki](internal/pki) | minimal CA (easy-rsa replacement) and `.ovpn` profile generation |
| [internal/config](internal/config) | OpenVPN config syntax: directives, quoting, inline `<ca>` blocks, argv |
