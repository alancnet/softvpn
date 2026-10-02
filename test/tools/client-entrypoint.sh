#!/bin/sh
# Runs the stock OpenVPN client. If SERVE_PORT is set, also answers HTTP on
# that port so other VPN clients can reach this one (client-to-client test).
set -e
if [ -n "$SERVE_PORT" ]; then
  socat TCP4-LISTEN:"$SERVE_PORT",fork,reuseaddr EXEC:"http-reply.sh hello" &
  socat TCP6-LISTEN:"$SERVE_PORT",ipv6only=1,fork,reuseaddr EXEC:"http-reply.sh hello" &
fi
exec openvpn "$@"
