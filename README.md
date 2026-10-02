# softvpn

An OpenVPN-compatible VPN server that runs entirely in userspace. It needs no
TUN device, no iptables, no `NET_ADMIN`, and no root, so it runs in a fully
locked-down Docker container (`cap_drop: [ALL]`, non-root, read-only root
filesystem). Stock OpenVPN clients (2.5 and 2.6, and older ones over CBC
ciphers) connect to it unmodified.

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

## End-to-end test

```sh
test/run.sh            # builds, runs 39 checks, tears down
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
| `cbc-lz4-client` | `edge` only | OpenVPN 2.6 over TCP offering only AES-256-CBC (HMAC-SHA256); `compress lz4` |
| `fallback-lzo-client` | `edge` only | OpenVPN 2.5 with `--ncp-disable`: gets `data-ciphers-fallback` AES-128-CBC; `comp-lzo yes` |
| `lz4v2-client` | `edge` only | OpenVPN 2.6 with `compress lz4-v2` |
| `stubv2-client` | `edge` only | OpenVPN 2.6 with `compress stub-v2`, which the server doesn't configure (migrated) |
| `openvpn23-client` | `edge` only | OpenVPN 2.3.18: no cipher negotiation, AES-256-CBC, `comp-lzo` |
| `probe` | `edge` only | no VPN; proves `edge` can't reach anything by itself |

`edge` is a Docker `internal` network, so anything a client reaches on `wan`
or the internet has gone through the tunnel and the server's software NAT.
The checks cover: container privileges (the server process has an empty
effective capability set), address assignment, `redirect-gateway`, TCP, UDP,
and ICMP NAT (the web server sees the server's address), DNS through the VPN
gateway, client-to-client routing, a 50 MB transfer with throughput, real
HTTPS to example.com through the server's default gateway, traffic
continuing across key renegotiations, CBC ciphers negotiated, taken from an
old client's options, or used as the fallback, and compression: uploads of
compressible data that the clients compress with LZ4, LZ4-v2, and LZO must
reach the web server byte for byte (it checks a SHA-256), and with
`allow-compression yes` the server's LZ4-compressed downloads must decompress
in the clients. The clients' own OpenVPN statistics confirm that compression
happened.

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
- CBC ciphers for older clients: AES-256-CBC, AES-192-CBC, AES-128-CBC, and
  BF-CBC, authenticated with HMAC using the `auth` digest (SHA1, the default,
  SHA224, SHA256, SHA384, SHA512). They are never offered by default. A
  client gets one when it is in `data-ciphers` and the client lists it, when
  a client that can't negotiate (OpenVPN 2.3, or `--ncp-disable`) has it as
  its `cipher` and it is in `data-ciphers`, or from `data-ciphers-fallback`
  for clients that can't negotiate. As in OpenVPN 2.6, `cipher` on the server
  acts as the fallback when it isn't in `data-ciphers`. `auth` isn't
  negotiated: it must match the clients'.
- Compression: `compress` (`stub`, `stub-v2`, `lz4`, `lz4-v2`, `lzo`,
  `migrate`) and `comp-lzo` (`yes`, `no`, `adaptive`) in `server.conf` or in a
  client's `client-config-dir` file, with OpenVPN's framing for each. The
  setting is pushed to the client (the comp-lzo spelling for OpenVPN 2.3),
  unless you already `push` a `compress`/`comp-lzo` option, in which case
  that option sets the framing instead. A client that has compression enabled
  while the server configures none is migrated to framing without
  compression (`compress stub-v2`, or `comp-lzo no` for 2.3), like OpenVPN's
  `compress migrate`. `allow-compression` follows OpenVPN 2.6: `asym` (the
  default) decompresses LZ4 and LZO from clients but never compresses what it
  sends; `yes` also compresses outgoing packets with LZ4 (LZO framing is
  always sent uncompressed); `no` allows only the stub framings and drops
  compressed packets. Compressing outgoing traffic makes VORACLE-style
  attacks possible, so leave it at `asym` unless you need it.
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

- `tls-auth`, `tls-crypt`, and `tls-crypt-v2`: remove them from client profiles.
- `auth-user-pass` and plugins: authentication is by client certificate only.
- IPv6 inside the tunnel, TAP/bridged mode, and `iroute` (routing to networks
  behind a client).
- OpenVPN 2.3 clients with `remote-cert-tls server` reject the ECDSA server
  certificates `softvpn pki` issues (2.3 expects RSA key usage); add
  `remote-cert-ku 80` to their profile or use an RSA certificate. Snappy
  compression isn't implemented.
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
