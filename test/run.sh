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
for c in client1 client2 client3 cbc-lz4-client fallback-lzo-client lz4v2-client stubv2-client openvpn23-client; do
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

echo "==> CBC ciphers for older clients"
connected() { srvlog | grep 'client connected' | grep "client=$1 " | tail -1; }
line=$(connected cbc-lz4-client)
echo "$line" | grep -q 'remote=tcp:' && echo "$line" | grep -q 'cipher=AES-256-CBC' && echo "$line" | grep -q 'auth=SHA256' &&
  ok "cbc-lz4-client (OpenVPN 2.6, TCP) negotiated AES-256-CBC with HMAC-SHA256 via data-ciphers" || bad "cbc-lz4-client negotiation (AES-256-CBC over TCP)" "$line"
line=$(connected fallback-lzo-client)
echo "$line" | grep -q 'version=2.5' && echo "$line" | grep -q 'cipher=AES-128-CBC' &&
  ok "fallback-lzo-client (OpenVPN 2.5, --ncp-disable) got data-ciphers-fallback AES-128-CBC" || bad "fallback-lzo-client negotiation (fallback cipher)" "$line"
line=$(connected openvpn23-client)
echo "$line" | grep -q 'version=2.3' && echo "$line" | grep -q 'cipher=AES-256-CBC' && echo "$line" | grep -q 'compress="comp-lzo no"' &&
  ok "openvpn23-client: OpenVPN $(echo "$line" | sed -n 's/.*version=\([^ ]*\).*/\1/p') (no negotiation): AES-256-CBC from its options, migrated to comp-lzo no" || bad "openvpn23-client negotiation (2.3 client)" "$line"
for c in cbc-lz4-client fallback-lzo-client openvpn23-client; do
  out=$(x $c curl -s -m 5 http://$WEB/ 2>&1)
  echo "$out" | grep -q "you are $SRV_WAN" && ok "$c -> web through NAT over CBC" || bad "$c -> web over CBC" "$out"
done
t=$(x fallback-lzo-client curl -s -m 60 -o /dev/null -w '%{size_download} %{speed_download}' http://$WEB:81/ 2>&1)
read -r size speed <<<"$t"
[ "$size" = 50000000 ] && ok "fallback-lzo-client: 50 MB download over AES-128-CBC/UDP intact ($(awk "BEGIN{printf \"%.1f\", $speed*8/1e6}") Mbit/s)" || bad "fallback-lzo-client 50 MB download over CBC" "$t"

echo "==> compression"
# counters SVC: the client's own pre/post-compress and pre/post-decompress
# byte counts, from the statistics OpenVPN logs on SIGUSR2.
counters() {
  x "$1" pkill -USR2 openvpn
  sleep 1
  dc logs --no-log-prefix "$1" 2>/dev/null | awk -F, '
    /pre-compress bytes,/ {v[1] = $2} /post-compress bytes,/ {v[2] = $2}
    /pre-decompress bytes,/ {v[3] = $2} /post-decompress bytes,/ {v[4] = $2}
    END {print v[1] + 0, v[2] + 0, v[3] + 0, v[4] + 0}'
}
mb() { awk "BEGIN{printf \"%.1f MB\", $1/1e6}"; }
# Upload ~2 MB of text: the client compresses it and the server must
# decompress it exactly (the web server answers with the SHA-256 it got).
for c in lz4v2-client:lz4-v2 cbc-lz4-client:lz4 fallback-lzo-client:"comp-lzo yes"; do
  svc=${c%%:*} algo=${c#*:}
  line=$(connected $svc)
  read -r pre0 post0 _ _ < <(counters $svc)
  out=$(x $svc sh -c "seq 1 300000 > /tmp/up && sha256sum < /tmp/up && socat -t 10 - TCP:$WEB:82 < /tmp/up" 2>&1)
  read -r pre post _ _ < <(counters $svc)
  pre=$((pre - pre0)) post=$((post - post0))
  sums=$(echo "$out" | awk '{print $1}' | sort -u | wc -l)
  if echo "$line" | grep -q "compress=\"compress $algo\"\|compress=\"$algo\"" && [ "$(echo "$out" | wc -l)" = 2 ] && [ "$sums" = 1 ] &&
    [ "$post" -gt 0 ] && [ "$post" -lt $((pre * 3 / 4)) ]; then
    ok "$svc ($algo): upload compressed by the client ($(mb $pre) -> $(mb $post)), decompressed by the server intact"
  else
    bad "$svc ($algo) compressed upload" "$line / $out / pre=$pre post=$post"
  fi
done
# allow-compression yes: the server compresses what it sends, with LZ4.
for svc in lz4v2-client cbc-lz4-client; do
  read -r _ _ pre0 post0 < <(counters $svc)
  t=$(x $svc curl -s -m 60 -o /dev/null -w '%{size_download}' http://$WEB:81/ 2>&1)
  read -r _ _ pre post < <(counters $svc)
  pre=$((pre - pre0)) post=$((post - post0))
  [ "$t" = 50000000 ] && [ "$pre" -gt 0 ] && [ "$pre" -lt $((post / 4)) ] &&
    ok "$svc: 50 MB download compressed by the server ($(mb $post) arrived as $(mb $pre)), intact" || bad "$svc server-compressed download" "size=$t pre=$pre post=$post"
done
line=$(connected stubv2-client)
out=$(x stubv2-client curl -s -m 5 http://$WEB/ 2>&1)
echo "$line" | grep -q 'compress="compress stub-v2"' && echo "$out" | grep -q "you are $SRV_WAN" &&
  ok "stubv2-client (compress stub-v2, nothing configured on the server) migrated and passes traffic" || bad "stubv2-client stub-v2 migration" "$line / $out"

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

echo "==> server log"
dc logs --no-log-prefix server 2>/dev/null | grep -E 'connected|listening' | sed 's/^/    /'

echo
echo "passed: $pass  failed: $fail  warnings: $warn"
if [ "$fail" -gt 0 ]; then
  echo "--- server log"; dc logs --no-log-prefix server | tail -30
  exit 1
fi
