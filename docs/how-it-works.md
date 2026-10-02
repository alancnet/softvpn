# How it works

A normal OpenVPN server hands decrypted packets to the kernel through a TUN
device, and relies on kernel routing and iptables to forward and NAT them.
All of that needs root or `NET_ADMIN`. softvpn does the same job in its own
process.

```
                    ┌──────────────────────────── softvpn ─────────────────────────────┐
openvpn client ──▶  │ OpenVPN protocol ──▶ virtual router ──▶ userspace TCP/IP stack   │ ──▶ host sockets
   (UDP / TCP)      │  (TLS, crypto)          │                 (gVisor netstack)      │     (default route)
                    │                         ├──▶ other clients                        │
                    │                         └──▶ ping NAT (unprivileged ICMP sockets) │
                    └──────────────────────────────────────────────────────────────────┘
```

**The protocol.** softvpn implements the server side of OpenVPN 2.x in Go:
the control channel with its reliability layer and TLS running over it,
key exchange, pushed options, renegotiation, and the encrypted data channel.
To a client it is an ordinary OpenVPN server.

**The router.** Every packet a client sends is checked against the addresses
that client owns (anti-spoofing), then routed with longest-prefix match: to
another client, to a network behind a client (`iroute`), to the server's own
gateway address, or out.

**The NAT.** Packets for the outside world go into a [gVisor](https://gvisor.dev)
network stack running in promiscuous mode, which accepts packets for any
destination. When a client opens a TCP connection, softvpn first dials the
real destination from the host; only if that succeeds does the client's
handshake complete, so refused and unreachable destinations look the same
as they would on a real network. UDP flows work the same way, with idle
timeouts. The host sees ordinary outgoing connections from softvpn's own
address, which is what masquerading NAT would produce. Ping is forwarded
through unprivileged ICMP sockets, which Docker permits by default.

**Bridged mode.** With `dev tap`, clients send Ethernet frames, and softvpn
runs a virtual switch: it learns MAC addresses, switches frames between
clients, and attaches its own port that answers ARP and DHCP and hands IP
traffic to the same router.

## Security model

- The server runs as an unprivileged user with no capabilities. It can only
  do what any process could: open sockets.
- Clients can only reach what the server's host can reach. The NAT always
  refuses loopback, link-local addresses (blocking cloud metadata
  endpoints), multicast, and the VPN's own networks; `nat-allow` and
  `nat-deny` narrow it further.
- A client may only send from the addresses assigned to it, and in tap mode
  only from its own MAC.
- With `tls-auth`, `tls-crypt` or `tls-crypt-v2`, packets without a valid key
  are dropped before any state is created for them.

## Performance

Relaying every connection through a userspace stack costs CPU, so softvpn is
slower than kernel OpenVPN. In testing between containers on one host,
transfers ran at several hundred Mbit/s. For most remote-access use that is
plenty; for high-throughput site links, kernel OpenVPN or WireGuard will do
better if you can give them the privileges they need.

## Code

| Package | Contents |
|---|---|
| [`cmd/softvpn`](../cmd/softvpn) | the command line |
| [`internal/ovpn`](../internal/ovpn) | the OpenVPN protocol |
| [`internal/server`](../internal/server) | configuration, router, NAT policy, tap switch, DHCP, supervisor |
| [`internal/vnet`](../internal/vnet) | the gVisor stack and TCP/UDP forwarding |
| [`internal/pki`](../internal/pki) | CA, CRL, control-channel keys, profiles |
| [`internal/users`](../internal/users) | the password file |
| [`internal/webui`](../internal/webui) | the web UI and its API |
| [`internal/config`](../internal/config) | the OpenVPN config file parser |
