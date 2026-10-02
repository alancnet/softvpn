# Compatibility

## Clients

softvpn is tested on every change against these stock OpenVPN clients:

| Client | Tested with |
|---|---|
| OpenVPN 2.6 | UDP and TCP, AES-GCM, tls-ekm key derivation, tls-auth, tls-crypt, tls-crypt-v2, passwords and auth tokens, IPv6, tap mode, DHCP, compression, renegotiation |
| OpenVPN 2.5 | ChaCha20-Poly1305, legacy key derivation, IPv6 transport, tap over TCP, tls-crypt-v2, fallback cipher with `comp-lzo` |
| OpenVPN 2.3 | AES-256-CBC without negotiation, `comp-lzo` |

Other clients that speak the OpenVPN 2.x protocol, such as OpenVPN Connect
and the mobile apps, are expected to work but aren't part of the test suite.

## Not supported

- **Scripts and plugins** (`plugin`, `auth-user-pass-verify`,
  `client-connect`, …): the image has no shell. Use the built-in
  [password file](clients.md#usernames-and-passwords) instead. Deferred
  authentication and `auth-gen-token`'s renewal window aren't implemented.
- **tls-crypt-v2 metadata checks** (`tls-crypt-v2-verify`,
  `tls-crypt-v2-max-age`).
- **CRL directories** (`crl-verify DIR dir`): use a CRL file.
- **IPv6-only clients and NAT64**: every client gets an IPv4 address.
- **In tap mode:** IPv6, `route`/`iroute`, VLAN tags, and clients bridging a
  LAN behind them (one MAC per client).
- **Snappy compression.**
- **OpenVPN 2.3 with `remote-cert-tls server`:** it rejects ECDSA server
  certificates; add `remote-cert-ku 80` to the profile.

## Differences from OpenVPN

- Several `proto` lines listen on all of them at once.
- `route` doesn't change any routing table; it marks a network as being
  inside the VPN.
- A client that enables compression the server doesn't configure is
  migrated to uncompressed framing automatically, as with OpenVPN's
  `compress migrate`.
- Unknown directives stop the server from starting instead of being
  ignored.
