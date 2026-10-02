#!/bin/sh
# One HTTP/1.0 response per connection, run by socat (SOCAT_PEERADDR is the
# caller). "http-reply.sh hello" greets the caller; "http-reply.sh bulk N"
# returns N zero bytes.
while IFS= read -r line; do [ "$(printf '%s' "$line" | tr -d '\r')" = "" ] && break; done
case "$1" in
  bulk)
    printf 'HTTP/1.0 200 OK\r\nContent-Length: %s\r\n\r\n' "$2"
    head -c "$2" /dev/zero ;;
  *)
    printf 'HTTP/1.0 200 OK\r\n\r\nhello from %s, you are %s\n' "$(hostname)" "$SOCAT_PEERADDR" ;;
esac
