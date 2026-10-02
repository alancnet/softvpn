# Clients and certificates

softvpn includes a small certificate authority, so you don't need easy-rsa
or an `openvpn` binary to set up a server. Everything lives in one
directory (`/pki` in the examples); in Docker, keep it in a volume.

The commands below run the image as a one-off container. Without Docker,
drop the `docker run … alancnet/softvpn` prefix and run `softvpn` directly.

```sh
alias softvpn='docker run --rm -i -v softvpn:/pki alancnet/softvpn'
```

## Setting up the CA

```sh
softvpn pki init -dir /pki
```

This creates `ca.crt`/`ca.key`, the server's `server.crt`/`server.key`, and
an empty `crl.pem`. Keys are ECDSA P-256 and certificates are valid for ten
years (`-days` changes that). Running `init` again keeps what exists, so it
is safe to run on every deploy.

## Adding clients

```sh
softvpn pki init -dir /pki -clients laptop,phone -remote vpn.example.com
```

For each name, this issues a client certificate if there isn't one, and
writes `NAME.ovpn`: a complete profile with the CA, the client's
certificate and key inlined, ready for the stock OpenVPN client or any app
that imports `.ovpn` files. Use `-port` and `-proto tcp` if the server
doesn't listen on 1194/udp.

To print a profile instead of writing it:

```sh
softvpn pki profile -dir /pki -remote vpn.example.com laptop > laptop.ovpn
```

A profile contains the client's private key: treat it like a password.

`softvpn pki list -dir /pki` shows issued and revoked certificates.

## Revoking a client

```sh
softvpn pki revoke -dir /pki laptop
```

The certificate is added to `crl.pem`, and its files move to `revoked/` so
the name can be issued again. With `crl-verify /pki/crl.pem` in
`server.conf`, the server refuses that certificate from then on and
disconnects the client within a few seconds, without a restart.

## Usernames and passwords

Instead of (or as well as) certificates, clients can log in with a password
checked against a user file:

```sh
softvpn user add -file /pki/users alice        # reads the password from stdin
softvpn user passwd -file /pki/users alice
softvpn user del -file /pki/users alice
softvpn user list -file /pki/users
```

The file is htpasswd-style with bcrypt hashes, so `htpasswd -B` works on it
too. In `server.conf`:

```
auth-user-pass-file /pki/users
verify-client-cert none          # passwords only; "optional" accepts either
username-as-common-name
```

Profiles for password users need `-auth-user-pass`, and `-no-cert` when the
server doesn't ask for certificates:

```sh
softvpn pki profile -dir /pki -remote vpn.example.com -auth-user-pass -no-cert alice > alice.ovpn
```

The server re-reads the file when it changes. Deleting a user disconnects
their sessions; a changed password applies at the next renegotiation.

## Control-channel keys

tls-auth, tls-crypt and tls-crypt-v2 add a key, shared or per client, that
every packet must carry before the server will even start a TLS handshake.
This hides the server from scanners and blunts denial-of-service attempts.
`-wrap` creates the key and puts it in profiles:

```sh
softvpn pki init -dir /pki -wrap tls-crypt-v2 -clients laptop -remote vpn.example.com
```

| `-wrap` | Files | Add to `server.conf` |
|---|---|---|
| `tls-auth` | `ta.key` | `tls-auth /pki/ta.key 0` |
| `tls-crypt` | `tc.key` | `tls-crypt /pki/tc.key` |
| `tls-crypt-v2` | `tls-crypt-v2.key`, plus `NAME-tls-crypt-v2.key` per client | `tls-crypt-v2 /pki/tls-crypt-v2.key` |

tls-crypt-v2 is the best choice for new setups: each client has its own key,
so one leaked profile doesn't expose the others. Changing the mode means
every client needs a new profile.

`softvpn pki genkey` makes individual keys, in the same formats as `openvpn
--genkey`, so keys made by either tool work with the other.

## Old clients

OpenVPN 2.3 and 2.4 clients that can't negotiate a cipher need a CBC cipher
on the server, for example:

```
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
data-ciphers-fallback AES-256-CBC
```

OpenVPN 2.3 also rejects the ECDSA server certificates softvpn issues under
`remote-cert-tls server`; add `remote-cert-ku 80` to those clients'
profiles. See [compatibility](compatibility.md).
