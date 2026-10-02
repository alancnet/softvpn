#!/bin/sh
# udhcpc hook for the TAP DHCP check: applies the lease and records it.
case "$1" in
bound | renew)
  ip addr flush dev "$interface"
  ip addr add "$ip/$mask" dev "$interface"
  echo "ip=$ip/$mask router=$router dns=$dns" >/tmp/dhcp-lease
  ;;
esac
