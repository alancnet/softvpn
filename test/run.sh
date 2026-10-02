#!/usr/bin/env bash
# End-to-end test: stock OpenVPN clients <-> unprivileged softvpn server.
#
#   test/run.sh          build, run every check, tear down
#   KEEP=1 test/run.sh   leave the environment running afterwards
#
# Parallel runs (e.g. in several worktrees) must not share names or subnets:
#   SVT_ID=-2 SVT_NET=10.232 test/run.sh
set -uo pipefail
cd "$(dirname "$0")"
export SVT_ID=${SVT_ID:-} SVT_NET=${SVT_NET:-10.231}
WEB=$SVT_NET.10.10 SRV_WAN=$SVT_NET.10.100

dc() { docker compose "$@"; }
pass=0 fail=0 warn=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; fail=$((fail + 1)); }
soft() { printf '  \033[33mWARN\033[0m %s\n' "$1"; warn=$((warn + 1)); }
# check NAME CMD...: pass if CMD succeeds
check() { local name=$1; shift; local out; if out=$("$@" 2>&1); then ok "$name"; else bad "$name" "$(echo "$out" | tail -3)"; fi; }
x() { local svc=$1; shift; dc exec -T "$svc" "$@"; }

cleanup() {
  if [ -z "${KEEP:-}" ]; then
    dc down -v --remove-orphans >/dev/null 2>&1
  else
    echo "KEEP=1: environment left running (docker compose -f test/docker-compose.yml down -v to remove)"
  fi
}
trap cleanup EXIT

echo "==> building and starting"
dc down -v --remove-orphans >/dev/null 2>&1
if ! out=$(dc up -d --build --quiet-pull 2>&1); then
  echo "$out" | tail -20
  echo "docker compose up failed"
  exit 1
fi

echo "==> waiting for the clients to finish connecting"
for c in client1 client2 client3 client4 client5 client6 client7; do
  for _ in $(seq 1 30); do
    dc logs "$c" 2>/dev/null | grep -q "Initialization Sequence Completed" && break
    sleep 1
  done
done

echo "==> container privileges"
for svc in server client1 client2 client3; do
  id=$(dc ps -q "$svc")
  [ -n "$id" ] || { bad "$svc is running"; continue; }
  priv=$(docker inspect -f '{{.HostConfig.Privileged}}' "$id")
  [ "$priv" = false ] && ok "$svc is not privileged" || bad "$svc is not privileged" "Privileged=$priv"
done
sid=$(dc ps -q server)
read -r user caps capadd ro devs < <(docker inspect -f '{{.Config.User}} {{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}} {{.HostConfig.ReadonlyRootfs}} {{len .HostConfig.Devices}}' "$sid")
[ "$user" = "65534:65534" ] && ok "server runs as uid 65534 (nobody)" || bad "server runs as nobody" "User=$user"
[ "$caps" = '["ALL"]' ] && [ "$capadd" = null ] && ok "server has every capability dropped and none added" || bad "server has no capabilities" "CapDrop=$caps CapAdd=$capadd"
[ "$ro" = true ] && ok "server root filesystem is read-only" || bad "server read-only rootfs"
[ "$devs" = 0 ] && ok "server has no devices (no /dev/net/tun)" || bad "server has no devices" "Devices=$devs"
pid=$(docker inspect -f '{{.State.Pid}}' "$sid")
capeff=$(awk '/^CapEff/{print $2}' "/proc/$pid/status" 2>/dev/null)
[ "$capeff" = 0000000000000000 ] && ok "server process effective capability set is empty (CapEff=$capeff)" || bad "server process has no capabilities" "CapEff=$capeff"

echo "==> tunnel"
tunip() { x "$1" ip -4 -o addr show tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1; }
c1ip=$(tunip client1)
case "$c1ip" in 10.8.0.*) ok "client1 (UDP) got $c1ip from the server's address pool" ;; *) bad "client1 (UDP) got a pool address on tun0" "tun0: $c1ip" ;; esac
check "client2 (TCP) got static 10.8.0.20 from client-config-dir" sh -c "docker compose exec -T client2 ip -4 addr show tun0 | grep -q 'inet 10.8.0.20/24'"
check "client1 pings the server's virtual address 10.8.0.1" x client1 ping -c 3 -W 2 10.8.0.1
check "redirect-gateway: client1 routes web traffic via tun0" sh -c "docker compose exec -T client1 ip route get $WEB | grep -q 'dev tun0'"

srvlog() { dc logs --no-log-prefix server 2>/dev/null; }
line=$(srvlog | grep 'client connected' | grep 'client=client1 ')
echo "$line" | grep -q 'version=2.6' && echo "$line" | grep -q 'key_derivation=tls-ekm' &&
  ok "client1: OpenVPN $(echo "$line" | sed -n 's/.*version=\([^ ]*\).*/\1/p'), AES-256-GCM, tls-ekm keys" || bad "client1 negotiation" "$line"
line=$(srvlog | grep 'client connected' | grep 'client=client3 ')
echo "$line" | grep -q 'version=2.5' && echo "$line" | grep -q 'cipher=CHACHA20-POLY1305' && echo "$line" | grep -q 'key_derivation=openvpn-prf' &&
  ok "client3: OpenVPN $(echo "$line" | sed -n 's/.*version=\([^ ]*\).*/\1/p'), ChaCha20-Poly1305, legacy PRF keys" || bad "client3 negotiation (2.5 client, chacha, PRF)" "$line"
out=$(x client3 curl -s -m 5 http://$WEB/ 2>&1)
echo "$out" | grep -q "you are $SRV_WAN" && ok "client3 (OpenVPN 2.5) -> web through NAT" || bad "client3 -> web" "$out"

echo "==> isolation baseline (probe: same network as the clients, no VPN)"
if x probe curl -s -m 3 http://$WEB/ >/dev/null 2>&1; then
  bad "probe cannot reach web without VPN" "edge network is not isolated, test is meaningless"
else
  ok "probe cannot reach web ($WEB) without the VPN"
fi

echo "==> software NAT out through the server"
out=$(x client1 curl -s -m 5 http://$WEB/ 2>&1)
if echo "$out" | grep -q "hello from .*, you are $SRV_WAN"; then
  ok "client1 -> web over UDP tunnel; web saw the server's address: ${out##*you are }"
else
  bad "client1 -> web over UDP tunnel, NATed to server address" "$out"
fi
out=$(x client2 curl -s -m 5 http://$WEB/ 2>&1)
echo "$out" | grep -q "you are $SRV_WAN" && ok "client2 -> web over TCP tunnel, NATed" || bad "client2 -> web over TCP tunnel" "$out"
out=$(x client1 sh -c "echo udp-echo-test | socat -t 2 - UDP:$WEB:7" 2>&1)
[ "$out" = udp-echo-test ] && ok "UDP NAT: echo service answered" || bad "UDP NAT echo" "$out"
check "ICMP NAT: client1 pings web (unprivileged ping socket on server)" x client1 ping -c 3 -W 2 $WEB
out=$(x client1 dig +short +time=2 +tries=2 @10.8.0.1 web 2>&1)
[ "$out" = $WEB ] && ok "DNS via 10.8.0.1 resolves names only the server knows (web -> $out)" || bad "DNS via VPN gateway" "$out"

echo "==> client-to-client routing"
out=$(x client1 curl -s -m 5 http://10.8.0.20:8080/ 2>&1)
echo "$out" | grep -q "you are $c1ip\$" && ok "client1 -> client2 (10.8.0.20) directly over the VPN: $out" || bad "client-to-client" "$out"

echo "==> throughput (informational)"
if t=$(x client1 curl -s -m 60 -o /dev/null -w '%{size_download} %{speed_download}' http://$WEB:81/ 2>&1); then
  read -r size speed <<<"$t"
  if [ "$size" = 50000000 ]; then
    ok "50 MB download through tunnel + NAT, intact ($(awk "BEGIN{printf \"%.1f\", $speed*8/1e6}") Mbit/s)"
  else
    bad "50 MB download" "got $size bytes"
  fi
else
  bad "50 MB download" "$t"
fi

echo "==> real internet via the server's default gateway (optional)"
ip=$(x client1 dig +short +time=3 +tries=1 @10.8.0.1 example.com A 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
if [ -n "$ip" ] && code=$(x client1 curl -s -m 10 -o /dev/null -w '%{http_code}' --resolve "example.com:443:$ip" https://example.com/ 2>/dev/null) && [ "$code" = 200 ]; then
  ok "client1 -> https://example.com ($ip) via the VPN: HTTP $code"
else
  soft "internet check skipped/failed (no outbound internet from Docker?)"
fi

echo "==> key renegotiation (client1 uses reneg-sec 15)"
rekeys() { dc logs server 2>/dev/null | grep -c 'data channel rekeyed'; }
for _ in $(seq 1 40); do [ "$(rekeys)" -ge 2 ] && break; sleep 1; done
n=$(rekeys)
if [ "$n" -ge 2 ] && dc logs client1 2>/dev/null | grep -q 'TLS: soft reset'; then
  out=$(x client1 curl -s -m 5 http://$WEB/ 2>&1)
  echo "$out" | grep -q "you are $SRV_WAN" && ok "traffic still flows after $n client-initiated key renegotiations" || bad "traffic after renegotiation" "$out"
else
  bad "client1 renegotiated keys" "server saw $n rekeys"
fi

echo "==> control-channel protection: tls-auth, tls-crypt, tls-crypt-v2"
for svc in server-tls-auth server-tls-crypt server-tls-crypt-v2; do
  id=$(dc ps -q "$svc")
  [ -n "$id" ] || { bad "$svc is running"; continue; }
  got=$(docker inspect -f '{{.Config.User}} {{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}} {{.HostConfig.ReadonlyRootfs}} {{len .HostConfig.Devices}} {{.HostConfig.Privileged}}' "$id")
  [ "$got" = '65534:65534 ["ALL"] null true 0 false' ] && ok "$svc is locked down like server (uid 65534, no capabilities, read-only, no devices)" || bad "$svc locked down" "$got"
done
# wrapped CLIENT SERVER WAN_IP DESCRIPTION: connected, version, NAT through that server
wrapped() {
  local line out
  line=$(dc logs --no-log-prefix "$2" 2>/dev/null | grep 'client connected' | grep "client=$1 ")
  out=$(x "$1" curl -s -m 5 http://$WEB/ 2>&1)
  if [ -n "$line" ] && echo "$out" | grep -q "you are $3"; then
    ok "$1: $4 (OpenVPN $(echo "$line" | sed -n 's/.*version=\([^ ]*\).*/\1/p')) -> web, NATed by $2"
  else
    bad "$1: $4" "server: ${line:-not connected}; web: $out"
  fi
}
wrapped client4 server-tls-auth $SVT_NET.10.101 "tls-auth, key-direction 1, HMAC-SHA256 (auth SHA256), UDP"
wrapped client5 server-tls-crypt $SVT_NET.10.102 "tls-crypt over TCP"
wrapped client6 server-tls-crypt-v2 $SVT_NET.10.103 "tls-crypt-v2"
wrapped client7 server-tls-crypt-v2 $SVT_NET.10.103 "tls-crypt-v2"
dc logs --no-log-prefix server-tls-crypt-v2 2>/dev/null | grep 'client=client7 ' | grep -q 'version=2.5' &&
  ok "client7 is OpenVPN 2.5 (P_CONTROL_HARD_RESET_CLIENT_V3 without 2.6 extensions)" || bad "client7 is OpenVPN 2.5"

# trial SVC CONFIG [ARGS...]: a throwaway client (no tun device) in SVC;
# succeeds if it completes the handshake within 6 s.
trial() {
  local svc=$1 conf=$2; shift 2
  x "$svc" sh -c "openvpn --config $conf --dev null --ifconfig-noexec --route-noexec --verb 3 $* >/tmp/trial.log 2>&1 & p=\$!
    for i in \$(seq 12); do grep -q 'Initialization Sequence Completed' /tmp/trial.log && break; sleep 0.5; done
    kill \$p; wait \$p; grep -q 'Initialization Sequence Completed' /tmp/trial.log"
}
if trial client4 /pki/client4.ovpn; then bad "tls-auth: client with the default SHA1 HMAC is refused"; else ok "tls-auth: client with the default SHA1 HMAC is refused (server uses auth SHA256)"; fi
x client5 sh -c "sed '/<tls-crypt>/,/<\/tls-crypt>/d' /pki/client5.ovpn >/tmp/nokey.ovpn"
if trial client5 /tmp/nokey.ovpn; then bad "tls-crypt: client without the key is refused"; else ok "tls-crypt: client without the key is refused"; fi
# client8's certificate is only for these trials. Keys made by the stock
# openvpn binary: one wrapped by another server key, and one wrapped by
# softvpn's (Go-generated) server key.
x client6 sh -c "sed '/<tls-crypt-v2>/,/<\/tls-crypt-v2>/d' /pki/client8.ovpn >/tmp/nokey.ovpn &&
  openvpn --genkey tls-crypt-v2-server /tmp/other-server.key >/dev/null &&
  openvpn --tls-crypt-v2 /tmp/other-server.key --genkey tls-crypt-v2-client /tmp/foreign.key >/dev/null &&
  openvpn --tls-crypt-v2 /pki/tls-crypt-v2.key --genkey tls-crypt-v2-client /tmp/openvpn-made.key >/dev/null"
if trial client6 /tmp/nokey.ovpn --tls-crypt-v2 /tmp/foreign.key; then bad "tls-crypt-v2: client key wrapped by another server key is refused"; else ok "tls-crypt-v2: client key wrapped by another server key is refused"; fi
check "tls-crypt-v2: client key made by openvpn --genkey from softvpn's server key is accepted" trial client6 /tmp/nokey.ovpn --tls-crypt-v2 /tmp/openvpn-made.key

rekeys=$(dc logs server-tls-crypt 2>/dev/null | grep -c 'data channel rekeyed')
out=$(x client5 curl -s -m 5 http://$WEB/ 2>&1)
[ "$rekeys" -ge 2 ] && echo "$out" | grep -q "you are $SVT_NET.10.102" &&
  ok "tls-crypt: traffic still flows after $rekeys renegotiations over TCP (client5, reneg-sec 15)" || bad "tls-crypt renegotiation" "rekeys=$rekeys web: $out"

echo "==> server log"
dc logs --no-log-prefix server 2>/dev/null | grep -E 'connected|listening' | sed 's/^/    /'

echo
echo "passed: $pass  failed: $fail  warnings: $warn"
if [ "$fail" -gt 0 ]; then
  echo "--- server log"; dc logs --no-log-prefix server | tail -30
  exit 1
fi
