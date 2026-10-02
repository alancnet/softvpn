# softvpn

An OpenVPN-compatible VPN server that runs entirely in userspace. It needs no
TUN device, no iptables, no `NET_ADMIN`, and no root, so it runs in a fully
locked-down Docker container (`cap_drop: [ALL]`, non-root, read-only root
filesystem). Stock OpenVPN clients (2.5 and 2.6, and older ones over CBC
ciphers) connect to it unmodified.

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

Optionally, manage it from a browser: keep `server.conf` in the PKI volume
(read-write), add `web-ui 0.0.0.0:8443`, and publish the port. See
[Web UI](#web-ui).

```sh
# copy server.conf into the volume (the image itself has no shell)
docker run --rm -i -v softvpn-pki:/pki alpine sh -c \
  'cat > /pki/server.conf && chown 65534:65534 /pki/server.conf' < server.conf
docker run -d --name softvpn --read-only --cap-drop ALL \
  --security-opt no-new-privileges -p 1194:1194/udp -p 8443:8443 \
  -v softvpn-pki:/pki alancnet/softvpn server --config /pki/server.conf --web-ui 0.0.0.0:8443
docker logs softvpn 2>&1 | grep 'administrator account'   # the first admin password
# then open https://your-server:8443/
```

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

IPv6, `route` and `iroute` are tun-mode features: with `dev tap` the server
rejects them at startup.

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

## Web UI

An optional web interface manages the running server: a live dashboard,
the configuration, client certificates and profiles, per-client settings,
password users, and the log. It is built into the binary (no external
resources, works offline) and needs no shell or capability, so the image
stays the same locked-down scratch container.

**Enabling it.** Add `web-ui ADDR` to `server.conf` (or `--web-ui ADDR` on
the command line), mount the configuration's directory read-write, and
publish the port:

```sh
# server.conf (with "web-ui 0.0.0.0:8443") lives in the PKI volume next to ca.crt
docker run -d --name softvpn --read-only --cap-drop ALL \
  --security-opt no-new-privileges -p 1194:1194/udp -p 8443:8443 \
  -v softvpn-pki:/pki alancnet/softvpn server --config /pki/server.conf
```

The directory must be writable by the server's uid 65534: a named volume
mounted at `/pki` is (the image's `/pki` belongs to that uid); for a bind
mount, `chown -R 65534:65534` the host directory.

Saving in the UI overwrites `server.conf` and applies it. **Backups are your
responsibility**: the UI keeps no history. Mount a directory rather than a
single file when you can; a bind-mounted single file works too (it is
rewritten in place, since it cannot be replaced atomically), but the
default administrator and certificate files need a writable directory next
to it. With a read-only mount the UI still shows everything, and says why
editing is off.

**Logging in.** Every page needs an administrator login. On first start, if
the administrators file (`web-ui.users` next to `server.conf`) does not
exist, softvpn creates it with the user `admin` and a random password, and
logs that password once:

```
level=WARN msg="web UI: created an administrator account; ..." user=admin password=... file=/etc/softvpn/web-ui.users
```

Alternatively set `SOFTVPN_WEB_PASSWORD`: it becomes `admin`'s password (in
the file if it is writable, else in memory). The file is an htpasswd-style
bcrypt file like `auth-user-pass-file`, so `softvpn user add -file
/etc/softvpn/web-ui.users NAME` adds administrators, and logged-in
administrators can change their password in the UI.

**What it does.**

- Dashboard: version, uptime, listeners, subnets, mode, and the connected
  clients (name or user, real and virtual addresses, cipher, client version
  and platform, traffic, connected time), updated live, with *Reconnect*
  and *Disconnect* (the client is told to exit) per session.
- Configuration: a form for the common settings (port and protocols,
  subnets, routes, pushed options such as redirect-gateway and DNS,
  client-to-client, keepalive, ciphers, compression, authentication, CRL,
  client-config-dir, tls-auth/tls-crypt/tls-crypt-v2 with key generation,
  NAT lists, verb), and the raw file with line numbers and live
  validation. The form rewrites only the directives it changed and keeps
  everything else, comments, order and inline `<ca>`/`<tls-*>` blocks
  included. Every save is first validated exactly as the server loads its
  configuration at startup; an invalid file is never written, and errors
  point at their line. A valid one is written and the VPN engine restarts
  in-process with it (the UI keeps running): connected clients are told to
  reconnect (`RESTART`) and come back within seconds. If the new
  configuration cannot start (its port is taken, say), the previous file is
  put back and the previous configuration restarted, and the UI says so.
  Directives given on the command line still apply on top of the file.
- Clients: certificates issued from the PKI directory (`web-ui-pki`, by
  default the `ca` file's directory if it holds `ca.key`), online status,
  revoked ones. *New client* issues a certificate (optionally with a
  password user of the same name); *Profile* downloads a `.ovpn` that
  matches the running server: proto and port, its tls-auth/tls-crypt key or
  a new per-client tls-crypt-v2 key, `auth-user-pass` when passwords are
  required, no certificate with `verify-client-cert none`, `dev tap`,
  `auth` and compression. *Revoke* updates `crl.pem`; with `crl-verify` the
  server disconnects the client within seconds (the UI offers to add
  `crl-verify` when it is missing). *Settings* edits the client's
  `client-config-dir` file: static IPv4/IPv6 address, iroutes, extra pushed
  options, push-reset, disable.
- Password users (with `auth-user-pass-file`): add, change password,
  delete, download a password-only profile. These files, the CRL and the
  client-config-dir files take effect without a restart.
- Logs: the most recent 2000 log lines, live, filterable and downloadable.

**Security.** The UI serves HTTPS with a self-signed certificate made on
first start (`web-ui.crt`/`web-ui.key` next to `server.conf`; its SHA-256
fingerprint is logged), or your own with `web-ui-cert`/`web-ui-key`. Behind
a TLS-terminating reverse proxy, `web-ui-http` serves plain HTTP (and logs
a warning). Passwords are checked with bcrypt, and failed logins are
limited (5 per address and 50 in total per 15 minutes). The session cookie
is `HttpOnly`, `Secure` (unless `web-ui-http`) and `SameSite=Strict`; every
change also needs the session's CSRF token in a header and a same-origin
request, and responses carry a strict Content-Security-Policy. Secrets are
never logged, except the one generated admin password. Anyone with an
administrator login controls the VPN: expose the port only where you need
it.

| directive | |
|---|---|
| `web-ui ADDR` | listen address, e.g. `0.0.0.0:8443`; enables the UI (off by default) |
| `web-ui-cert FILE`, `web-ui-key FILE` | TLS certificate and key (default: self-signed, kept next to `server.conf`) |
| `web-ui-http` | plain HTTP, for use behind a TLS reverse proxy |
| `web-ui-users FILE` | administrators (default: `web-ui.users` next to `server.conf`) |
| `web-ui-pki DIR` | PKI directory for client certificates (default: the `ca` file's directory, if it has `ca.key`) |
| `web-ui-remote HOST [PORT [PROTO]]` | what generated profiles connect to (default: the host name the browser used, and the server's port and first proto) |

The `web-ui*` directives are read at process start; changing them in the UI
takes effect at the next container start. The JSON API the UI uses is under
`/api/` (see [internal/webui](internal/webui)).

## End-to-end test

```sh
test/run.sh            # builds, runs 123 checks, tears down
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
| `client4` | `edge` only | stock OpenVPN 2.6, no certificate: username/password (`auth-user-pass`), rekeys every 15 s with an auth token |
| `client5` | `edge` only | same profile, wrong password |
| `client6` | `edge` only | a revoked client certificate |
| `tlsauth-server`, `tlscrypt-server`, `tlscryptv2-server` | `wan` + `edge` | softvpn locked down like `server`, each with one kind of control-channel protection |
| `tlsauth-client` | `edge` only | stock OpenVPN 2.6, `tls-auth` with `key-direction 1` and `auth SHA256` |
| `tlscrypt-client` | `edge` only | stock OpenVPN 2.6, `tls-crypt` over TCP; rekeys every 15 s |
| `tlscryptv2-client`, `tlscryptv2-client25` | `edge` only | `tls-crypt-v2` with OpenVPN 2.6 and 2.5 |
| `siteclient` | `edge` + `lan` | stock OpenVPN 2.6; site gateway for `lan` (`iroute`, `iroute-ipv6`), forwarding enabled |
| `lansvc` | `lan` only | a host on siteclient's LAN, with a route back to the VPN via siteclient |
| `cbc-lz4-client` | `edge` only | OpenVPN 2.6 over TCP offering only AES-256-CBC (HMAC-SHA256); `compress lz4` |
| `fallback-lzo-client` | `edge` only | OpenVPN 2.5 with `--ncp-disable`: gets `data-ciphers-fallback` AES-128-CBC; `comp-lzo yes` |
| `lz4v2-client` | `edge` only | OpenVPN 2.6 with `compress lz4-v2` |
| `stubv2-client` | `edge` only | OpenVPN 2.6 with `compress stub-v2`, which the server doesn't configure (migrated) |
| `openvpn23-client` | `edge` only | OpenVPN 2.3.18: no cipher negotiation, AES-256-CBC, `comp-lzo` |
| `probe` | `edge` only | no VPN; proves `edge` can't reach anything by itself |
| `tapserver` | `wan` + `tapedge` | softvpn with `dev tap` and `server-bridge` ([server-tap.conf](test/server-tap.conf)); locked down like `server` |
| `tapclient1` | `tapedge` only | stock OpenVPN 2.6 with `dev tap` over UDP |
| `tapclient2` | `tapedge` only | stock OpenVPN 2.5 with `dev tap` over TCP |
| `dhcpserver` | `wan` + `dhcpedge` | softvpn with `dev tap` and `server-bridge` without arguments: DHCP only ([server-dhcp.conf](test/server-dhcp.conf)) |
| `tapclient3` | `dhcpedge` only | stock OpenVPN 2.6 with `dev tap`, configured by `udhcpc` (which also needs `NET_RAW`) |
| `webui-server` | `wan` + `edge` | softvpn with the web UI ([server-webui.conf](test/server-webui.conf)); locked down like `server`, its `/etc/softvpn` a writable volume (set up by the one-shot `webui-init` and `webui-pki`) |
| `webui-client` | `edge` only | drives the web UI's API with curl and connects with the stock OpenVPN 2.6 client using the profiles it downloads |
| `uitest` | `edge` only | headless Chromium (Playwright, [test/ui](test/ui)): logs in and visits every page at desktop and phone width, light and dark; fails on any JavaScript or console error. Screenshots go to `test/artifacts/` |

`wan`, `edge` and `lan` are dual-stack. `edge`, `lan`, `tapedge` and
`dhcpedge` are Docker `internal` networks, so anything a client reaches on
`wan` or the internet has gone through the tunnel and the server's software
NAT.
The checks cover: container privileges (the server process has an empty
effective capability set), address assignment, `redirect-gateway`, TCP, UDP,
and ICMP NAT (the web server sees the server's address), DNS through the VPN
gateway, client-to-client routing, a 50 MB transfer with throughput, real
HTTPS to example.com through the server's default gateway, and traffic
continuing across key renegotiations. For IPv6: pool and static addresses,
ping to the IPv6 gateway, `redirect-gateway ipv6`, TCP, UDP and ICMPv6 NAT to
the web server's IPv6 address, DNS over IPv6, client-to-client over IPv6, and
an OpenVPN 2.5 client connecting to the server over IPv6. For `iroute`: other
clients reach `lansvc` behind siteclient over IPv4 and IPv6 without NAT, and
siteclient isn't pushed routes to its own LAN. Real IPv6 internet access is
checked too, but only warns if the host has none. Authentication:
password login and AUTH_FAILED for a
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
For control-channel protection they check that each wrapped client connects
and is NATed by its server, that clients with the wrong HMAC digest, no key,
or a tls-crypt-v2 key from another server are refused, that a tls-crypt-v2
client key made by the stock `openvpn --genkey` from softvpn's server key is
accepted, and renegotiation over tls-crypt; all of those keys and profiles
come from softvpn's own generator (the `pki-tls-*` containers). Older clients and
compression: CBC ciphers negotiated, taken from an old client's options, or
used as the fallback (OpenVPN 2.6, 2.5 and 2.3 clients); uploads of
compressible data that the clients compress with LZ4, LZ4-v2, and LZO must
reach the web server byte for byte (it checks a SHA-256), and with
`allow-compression yes` the server's LZ4-compressed downloads must decompress
in the clients. The clients' own OpenVPN statistics confirm that compression
happened. For the web UI: the generated admin password is logged once,
a wrong password and a missing CSRF token are refused, a client created
through the API connects with exactly the profile downloaded from it and
reaches the web server through the NAT, a configuration change (a new
pushed option and keepalive) restarts the engine in-process while the UI
session survives, and the reconnected client receives the new options; an
invalid configuration is refused with its line number and changes nothing;
revoking the client through the API disconnects it within seconds; a
password user added through the API connects with its password-only
profile; *Disconnect* makes a client exit; and the browser test passes.

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
- IPv6 inside the tunnel: `server-ipv6`, `ifconfig-ipv6` pushed to clients,
  IPv6 client-to-client routing, and NAT of IPv6 TCP, UDP and ICMPv6 echo
  through the host's IPv6. Listening on IPv6: `proto udp`/`tcp` are
  dual-stack, as are `udp6`/`tcp6`; `udp4`/`tcp4` are IPv4 only.
- Networks behind clients: `route`, `route-ipv6`, and in `client-config-dir`
  `iroute` and `iroute-ipv6`, with longest-prefix-match routing and source
  address validation against each client's addresses and iroutes.
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
  - `web-ui ADDR` and the other `web-ui-*` directives: the optional
    [Web UI](#web-ui).
  - Relative file names in `server.conf` (including `client-config-dir`)
    are resolved against the file's directory.

Directives that only matter to kernel OpenVPN (`dh`, `persist-tun`, `user`,
and similar) are accepted and ignored, so existing configs load. Directives
softvpn doesn't implement are rejected at startup.

## Not supported (yet)

- `tls-crypt-v2-verify` and `tls-crypt-v2-max-age`: client key metadata is
  not checked.
- Plugins and scripts (`plugin`, `auth-user-pass-verify`, `client-connect`,
  ...): use the built-in user database instead. Deferred authentication,
  `crl-verify DIR dir`, and `auth-gen-token`'s renewal window and
  `external-auth` aren't supported.
- IPv6-only clients (every client gets an IPv4 address) and NAT64.
- In TAP mode: a client bridging a LAN behind it (more than one MAC per
  client), IPv6 (`server-ipv6`), `route`/`iroute`, and VLAN tags.
- OpenVPN 2.3 clients with `remote-cert-tls server` reject the ECDSA server
  certificates `softvpn pki` issues (2.3 expects RSA key usage); add
  `remote-cert-ku 80` to their profile or use an RSA certificate. Snappy
  compression isn't implemented.

## Layout

| path | what |
|---|---|
| [cmd/softvpn](cmd/softvpn/main.go) | CLI: `server`, `pki init/client/profile/revoke/crl/list/genkey`, `user add/passwd/del/list` |
| [internal/ovpn](internal/ovpn) | OpenVPN protocol: packets, reliability layer, tls-auth/tls-crypt/tls-crypt-v2 and their key formats, TLS-over-control-channel, key exchange, data-channel crypto, UDP/TCP transports |
| [internal/server](internal/server) | config, address pool, virtual router, soft-NAT policy, ICMP NAT; TAP mode's virtual switch and DHCP server; the supervisor that restarts it with a new configuration |
| [internal/webui](internal/webui) | the web UI: JSON API, login and sessions, structured config editing, profile generation, and the embedded front end ([static](internal/webui/static)) |
| [internal/logbuf](internal/logbuf), [internal/fsutil](internal/fsutil) | recent log lines for the UI; atomic (or, for bind-mounted files, in-place) file writes |
| [internal/vnet](internal/vnet) | gVisor stack in promiscuous/spoofing mode, TCP/UDP forwarders (the NAT) |
| [internal/pki](internal/pki) | minimal CA (easy-rsa replacement), CRL, control-channel keys, and `.ovpn` profile generation |
| [internal/users](internal/users) | user database for `auth-user-pass-file` (htpasswd-style bcrypt file) |
| [internal/config](internal/config) | OpenVPN config syntax: directives, quoting, inline `<ca>` blocks, argv |
