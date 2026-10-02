# Configuration reference

softvpn reads OpenVPN's `server.conf` syntax: one directive per line, `#` or
`;` comments, double quotes, and inline blocks such as `<ca>…</ca>`. Relative
file names are resolved against the directory of the file they appear in.

Any directive can also be given on the command line, after the config file,
where it overrides it:

```sh
softvpn server --config /pki/server.conf --verb 4 --port 443
```

softvpn refuses to start on a directive it doesn't know, rather than ignoring
it. The exceptions are directives that only matter to kernel OpenVPN, listed
[at the end](#accepted-and-ignored).

## Listening

| Directive | Notes |
|---|---|
| `port N` | Default `1194`. |
| `proto udp\|tcp` | `udp`/`tcp` (and `udp6`/`tcp6`) listen on IPv4 and IPv6; `udp4`/`tcp4` on IPv4 only. `tcp-server` is accepted. **softvpn extension:** repeat `proto` to listen on several at once. |
| `local ADDR` | Listen on one address only. |

## Addresses and routing

| Directive | Notes |
|---|---|
| `dev tun\|tap`, `dev-type` | `tun` (routed, the default) or `tap` (bridged, see below). |
| `topology subnet` | The only topology in tun mode, and the default. |
| `server NETWORK NETMASK` | The VPN subnet. The server is `.1`; clients get addresses from the rest. `NETWORK/BITS` also works. |
| `server-ipv6 PREFIX/BITS` | IPv6 inside the tunnel. The server is `::1`; each client's IPv6 address follows its IPv4 one. tun mode only. |
| `route NETWORK NETMASK`, `route-ipv6 PREFIX` | Marks a network as being inside the VPN, behind some client's `iroute`. Nothing is installed on the host; the network is simply never NATed out. |
| `client-to-client` | Lets clients reach each other, and other clients' `iroute` networks. |
| `push "OPTION"` | Pushed to every client: `redirect-gateway def1 [ipv6]`, `dhcp-option DNS 10.8.0.1`, `route …`, and so on. |
| `client-config-dir DIR` | Per-client files, named after the client's common name (or username with `username-as-common-name`). See below. |
| `max-clients N`, `duplicate-cn` | As in OpenVPN. |
| `tun-mtu N` | Default `1500`. |

**Gateway services.** The server's own addresses (`10.8.0.1`, and the IPv6
`::1`) answer ping and relay DNS to the host's resolver, so
`push "dhcp-option DNS 10.8.0.1"` works out of the box, including inside
Docker.

**`client-config-dir` files** accept `ifconfig-push IP NETMASK`,
`ifconfig-ipv6-push ADDR/BITS`, `iroute NETWORK NETMASK`, `iroute-ipv6
PREFIX`, `push "…"`, `push-reset`, `disable`, and `compress`/`comp-lzo`.
Changes take effect at the client's next connection; no restart needed.

### Site-to-site (`iroute`)

A client can be the gateway to a LAN behind it. In `server.conf`:

```
route 192.168.10.0 255.255.255.0
push "route 192.168.10.0 255.255.255.0"
client-to-client
```

and in that client's `client-config-dir` file:

```
iroute 192.168.10.0 255.255.255.0
```

The client must forward between its tunnel and the LAN, and the LAN needs a
route back to the VPN subnet through it, just as with OpenVPN.

### Bridged mode (`dev tap`)

The server becomes a virtual Ethernet switch, with its own port: it answers
ARP for the gateway and routes and NATs like tun mode. Clients may only send
from their own MAC and assigned IPv4 address.

| Directive | Notes |
|---|---|
| `server-bridge GATEWAY NETMASK START END` | Gateway address and pool, as in OpenVPN. `server NETWORK NETMASK` also works with `dev tap`. |
| `server-bridge` / `server-bridge nogw` | DHCP mode: clients configure themselves by DHCP, which softvpn answers. Takes its range from `server`. |
| `lladdr MAC` | The gateway's MAC. The default is derived from its IPv4 address. |

IPv6, `route` and `iroute` aren't available in tap mode.

## Encryption

| Directive | Notes |
|---|---|
| `ca`, `cert`, `key` | The CA and the server's certificate and key; files or inline blocks. `dh` isn't needed (accepted and ignored). |
| `data-ciphers LIST` | Colon-separated, in order of preference. Default `AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305`. Also `AES-256-CBC`, `AES-192-CBC`, `AES-128-CBC`, `BF-CBC` for old clients. `ncp-ciphers` is an alias. |
| `data-ciphers-fallback CIPHER`, `cipher CIPHER` | For clients that can't negotiate (OpenVPN 2.3, `--ncp-disable`). |
| `auth DIGEST` | HMAC digest for CBC ciphers and tls-auth: `SHA1` (default), `SHA224`, `SHA256`, `SHA384`, `SHA512`. Clients must use the same. |
| `tls-auth FILE [0\|1]`, `key-direction` | HMAC on every control packet. |
| `tls-crypt FILE` | Encrypts and authenticates control packets. |
| `tls-crypt-v2 FILE` | Like tls-crypt, with a separate key per client. |
| `compress [stub\|stub-v2\|lz4\|lz4-v2\|lzo]`, `comp-lzo [yes\|no\|adaptive]` | Compression framing, pushed to clients. |
| `allow-compression asym\|yes\|no` | `asym` (default) accepts compressed packets from clients but never compresses what it sends; compressing outbound traffic exposes you to VORACLE-style attacks. |

Only one of `tls-auth`, `tls-crypt` and `tls-crypt-v2` can be used. Keys
come from [`softvpn pki`](clients.md#control-channel-keys) or `openvpn
--genkey`.

## Authentication

| Directive | Notes |
|---|---|
| `crl-verify FILE` | Revoked certificates are refused, and connected clients are disconnected within seconds when the file changes. `softvpn pki revoke` maintains it. |
| `auth-user-pass-file FILE` | **softvpn extension:** username/password login against a bcrypt (htpasswd-style) file, instead of a script or plugin. Re-read when it changes. |
| `verify-client-cert none\|optional\|require` | Whether clients also need a certificate. Default `require`. |
| `auth-user-pass-optional` | Clients with a valid certificate don't need a password. |
| `username-as-common-name` | Name the session (and choose its `client-config-dir` file) by username. |
| `auth-gen-token [LIFETIME]`, `auth-gen-token-secret FILE` | Clients renegotiate with a token instead of resending the password. Without a secret file, tokens stop working when the server restarts; clients then fall back to their saved password. |

`plugin`, `auth-user-pass-verify`, `client-connect` and other script hooks
are refused: the image has no shell to run them. See
[clients](clients.md#usernames-and-passwords).

## Operations

| Directive | Notes |
|---|---|
| `keepalive INTERVAL TIMEOUT` | Default `10 60`, pushed to clients as in OpenVPN. |
| `status FILE [SECONDS]` | A table of connected clients, rewritten periodically. |
| `verb N` | `0` warnings only, `3` normal, `4`+ debug. |
| `upstream-dns IP[:PORT]` | **softvpn extension:** where DNS sent to the gateway goes. Default: the first `nameserver` in `/etc/resolv.conf`. |
| `nat-allow CIDR…`, `nat-deny CIDR…` | **softvpn extension:** which destinations clients may reach through the NAT. Loopback, link-local (cloud metadata), multicast and the VPN's own networks are always refused. |
| `web-ui ADDR`, `web-ui-*` | **softvpn extension:** the [web UI](web-ui.md). |

## Accepted and ignored

These only matter to kernel OpenVPN, so existing configs load unchanged:
`dh`, `persist-key`, `persist-tun`, `user`, `group`, `explicit-exit-notify`,
`ifconfig-pool-persist`, `tls-server`, `mode`, `tls-version-min`,
`remote-cert-tls`, `mute`, `log`, `log-append`, `daemon`, `script-security`,
`sndbuf`, `rcvbuf`, `txqueuelen`, `fast-io`, `mssfix`, `tun-mtu-extra`.
