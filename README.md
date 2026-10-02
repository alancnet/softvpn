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

### Control-channel keys

`-wrap tls-auth|tls-crypt|tls-crypt-v2` on `pki init`, `pki client` and
`pki profile` creates the keys that are missing and embeds the client's key in
its profiles. Add the matching line to `server.conf`:

| `-wrap` | key files in the PKI directory | `server.conf` | profile gets |
|---|---|---|---|
| `tls-auth` | `ta.key` | `tls-auth /pki/ta.key 0` | `<tls-auth>` and `key-direction 1` |
| `tls-crypt` | `tc.key` | `tls-crypt /pki/tc.key` | `<tls-crypt>` |
| `tls-crypt-v2` | `tls-crypt-v2.key`, plus `NAME-tls-crypt-v2.key` per client | `tls-crypt-v2 /pki/tls-crypt-v2.key` | `<tls-crypt-v2>` with that client's key |

```sh
softvpn pki init -dir /pki -wrap tls-crypt-v2 -clients laptop -remote vpn.example.com
```

`softvpn pki genkey` makes single keys, like `openvpn --genkey`:
`genkey tls-auth`, `genkey tls-crypt`, `genkey tls-crypt-v2` (server key),
and `genkey [-metadata TEXT] tls-crypt-v2-client NAME`. Keys go into `-dir`
under the names above, and existing ones are kept; `-out FILE` (or `-` for
stdout) writes elsewhere. If the server sets `auth`, put the same `auth` line
in tls-auth client profiles.

## End-to-end test

```sh
test/run.sh            # builds, runs 39 checks, tears down
KEEP=1 test/run.sh     # leave it running afterwards
```

[test/docker-compose.yml](test/docker-compose.yml) sets up:

| container | network | notes |
|---|---|---|
| `server` | `wan` + `edge` | softvpn; uid 65534, all capabilities dropped, read-only, no devices |
| `server-tls-auth`, `server-tls-crypt`, `server-tls-crypt-v2` | `wan` + `edge` | the same, each with one kind of control-channel protection |
| `web` | `wan` only | stands in for the internet: HTTP, bulk download, UDP echo |
| `client1` | `edge` only | stock OpenVPN 2.6 over UDP; rekeys every 15 s |
| `client2` | `edge` only | stock OpenVPN 2.6 over TCP; static IP from `client-config-dir` |
| `client3` | `edge` only | stock OpenVPN 2.5 with ChaCha20-Poly1305 and legacy key derivation |
| `client4` | `edge` only | OpenVPN 2.6, `tls-auth` with `key-direction 1` and `auth SHA256` |
| `client5` | `edge` only | OpenVPN 2.6, `tls-crypt` over TCP; rekeys every 15 s |
| `client6`, `client7` | `edge` only | `tls-crypt-v2` with OpenVPN 2.6 and 2.5 |
| `probe` | `edge` only | no VPN; proves `edge` can't reach anything by itself |

`edge` is a Docker `internal` network, so anything a client reaches on `wan`
or the internet has gone through the tunnel and the server's software NAT.
The checks cover: container privileges (the server process has an empty
effective capability set), address assignment, `redirect-gateway`, TCP, UDP,
and ICMP NAT (the web server sees the server's address), DNS through the VPN
gateway, client-to-client routing, a 50 MB transfer with throughput, real
HTTPS to example.com through the server's default gateway, and traffic
continuing across key renegotiations. For control-channel protection they
check that each wrapped client connects and is NATed by its server, that
clients with the wrong HMAC digest, no key, or a tls-crypt-v2 key from another
server are refused, and that a tls-crypt-v2 client key made by the stock
`openvpn --genkey` from softvpn's server key is accepted. All keys and
profiles in the test come from softvpn's own generator (the `pki-*` services).

No container is privileged. The OpenVPN *clients* get `/dev/net/tun` and the
single capability `NET_ADMIN`, because the stock client always creates a
kernel TUN interface. That requirement belongs to the client. The server needs
neither.

## Supported

- Transports: UDP and TCP. Several `proto` lines listen on each (a softvpn
  extension; OpenVPN takes only one).
- TLS 1.2/1.3 control channel with mutual certificate authentication, plus
  OpenVPN's control-channel reliability layer.
- Control-channel protection, one per server:
  - `tls-auth FILE [0|1]` (or an inline `<tls-auth>` block with
    `key-direction`): HMAC on every control packet, with the digest from
    `auth` (SHA1 by default; SHA224/256/384/512).
  - `tls-crypt FILE`: control packets encrypted and authenticated with
    AES-256-CTR and HMAC-SHA256.
  - `tls-crypt-v2 FILE` (the server key): like tls-crypt, but every client has
    its own key, which it sends wrapped by the server key in its first packet
    (`P_CONTROL_HARD_RESET_CLIENT_V3`, and `P_CONTROL_WKC_V1` if sent).

  Packets that fail the check, or repeat a packet id, are dropped before any
  state is created for them. Key files are OpenVPN's formats, so keys from
  `openvpn --genkey` work, and `softvpn pki` makes the same keys without an
  openvpn binary.
- Data channel: AES-256-GCM, AES-128-GCM, and CHACHA20-POLY1305, negotiated
  via `data-ciphers`; P_DATA_V2 with peer-id and client floating; 64-packet
  replay window.
- Key derivation: `tls-ekm` (RFC 5705, OpenVPN 2.6) and the legacy OpenVPN
  PRF (2.5).
- Client-initiated renegotiation (`reneg-sec`), with a 60 s overlap during
  which the old key still works.
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

- `tls-crypt-v2-verify` and `tls-crypt-v2-max-age`: client key metadata is
  not checked.
- Compression (`compress`, `comp-lzo`): clients must not enable it.
- `auth-user-pass` and plugins: authentication is by client certificate only.
- IPv6 inside the tunnel, TAP/bridged mode, `iroute` (routing to networks
  behind a client), and CBC ciphers for pre-2.4 clients.
- Certificate revocation lists. To lock a client out, use `disable` in its
  `client-config-dir` file.

## Layout

| path | what |
|---|---|
| [cmd/softvpn](cmd/softvpn/main.go) | CLI: `server`, `pki init/client/profile/genkey` |
| [internal/ovpn](internal/ovpn) | OpenVPN protocol: packets, reliability layer, tls-auth/tls-crypt/tls-crypt-v2 and their key formats, TLS-over-control-channel, key exchange, data-channel crypto, UDP/TCP transports |
| [internal/server](internal/server) | config, address pool, virtual router, soft-NAT policy, ICMP NAT |
| [internal/vnet](internal/vnet) | gVisor stack in promiscuous/spoofing mode, TCP/UDP forwarders (the NAT) |
| [internal/pki](internal/pki) | minimal CA (easy-rsa replacement), control-channel key generation, and `.ovpn` profile generation |
| [internal/config](internal/config) | OpenVPN config syntax: directives, quoting, inline `<ca>` blocks, argv |
