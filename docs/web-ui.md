# Web UI

softvpn has an optional web interface for running a server without editing
files by hand. It's built into the binary and works offline.

- **Dashboard:** who is connected, from where, with which address, client
  version and cipher, and how much traffic; reconnect or disconnect any
  session. Updates live.
- **Configuration:** a form for the common settings, and the raw
  `server.conf` with line numbers and live validation.
- **Clients:** create certificates, download `.ovpn` profiles that match the
  server's current settings (control-channel key, password login, tap mode,
  …), revoke them, and edit per-client settings such as static addresses.
- **Users:** add, change and delete password users.
- **Logs:** recent server log lines, live.

## Enabling it

Add `web-ui ADDR` to `server.conf`, or `--web-ui ADDR` on the command line,
and publish the port:

```sh
docker run -d --name softvpn --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 1194:1194/udp -p 8443:8443 -v softvpn:/pki \
  alancnet/softvpn server --config /pki/server.conf --web-ui 0.0.0.0:8443
```

The UI can only change things it can write. Keep `server.conf` in a
directory that is mounted read-write and writable by uid 65534, the user the
image runs as. A named volume mounted at `/pki` already is. For a host
directory, run `chown -R 65534:65534` on it. With a read-only mount, the UI
still shows everything but says why editing is disabled.

## Logging in

On first start, softvpn creates an `admin` account with a random password
and prints it once:

```sh
docker logs softvpn 2>&1 | grep 'administrator account'
```

To choose the password yourself, set `SOFTVPN_WEB_PASSWORD` instead. Admin
accounts live in `web-ui.users` next to `server.conf`, in the same format as
password users, so `softvpn user add -file /pki/web-ui.users NAME` adds
another administrator. Logged-in administrators can change their own
password in the UI.

## Saving changes

When you save the configuration, softvpn first validates it the same way it
would at startup. An invalid file is never written; the error points at the
line. A valid file is written over `server.conf`, and the VPN restarts
in-process with it. Connected clients are told to reconnect and are back
within seconds; the UI stays up. If the new configuration fails to start
(its port is taken, say), the previous file is restored and the previous
configuration restarted.

**softvpn keeps no history of your configuration.** Back it up yourself.

Changes to per-client settings, password users and revocations take effect
immediately, without a restart.

## Security

Anyone who can log in controls the VPN, so expose the port only where you
need it.

- HTTPS by default, with a self-signed certificate created on first start
  (its fingerprint is logged). Use your own with `web-ui-cert` and
  `web-ui-key`, or `web-ui-http` behind a TLS-terminating reverse proxy.
- Passwords are stored as bcrypt hashes, and repeated failed logins are
  locked out for 15 minutes.
- Sessions use `HttpOnly`, `Secure`, `SameSite=Strict` cookies; changes
  require a CSRF token and a same-origin request; responses carry a strict
  Content-Security-Policy.

## Directives

| Directive | Default |
|---|---|
| `web-ui ADDR` | off; e.g. `0.0.0.0:8443` |
| `web-ui-cert FILE`, `web-ui-key FILE` | self-signed `web-ui.crt`/`web-ui.key` next to `server.conf` |
| `web-ui-http` | off: serve plain HTTP |
| `web-ui-users FILE` | `web-ui.users` next to `server.conf` |
| `web-ui-pki DIR` | the directory of the `ca` file, if it contains `ca.key` |
| `web-ui-remote HOST [PORT [PROTO]]` | the host name you browse to, and the server's port and protocol |

`web-ui-remote` is the address written into downloaded profiles; set it
when clients reach the server at a different address than your browser does.
The `web-ui*` directives are read at startup, so changes to them apply at the
next container start.
