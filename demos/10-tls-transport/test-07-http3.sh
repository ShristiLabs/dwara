#!/bin/bash
# test-07-http3.sh — HTTP/3 (QUIC) ingress.
#
# The edge-h3 listener (UDP :8445) serves HTTP/3 over QUIC. It is
# compiled into the default demo build (quinn + h3 are unconditional
# dependencies of dwara-bin), so the listener is LIVE: the gateway
# binds a UDP socket, runs the QUIC accept loop, and advertises the
# h3 port to HTTP/1.1/HTTP/2 clients via the Alt-Svc response header
# on edge-https (alt_svc: 'h3=":8445"; ma=86400' in dwara.yaml).
#
# What this test verifies:
#   1. the QUIC listener bound (startup log `listening_h3` and no
#      `h3_listener_failed`),
#   2. edge-https advertises Alt-Svc for the h3 port,
#   3. the published UDP port is listening on the host.
#
# Client note: macOS's bundled curl has NO HTTP/3 support, and neither
# does the stock curlimages/curl image. To send a real h3 request use
# a curl built with HTTP/3 (e.g. the `ghcr.io/curl/curl-http3` image:
#   docker run --rm --network host ghcr.io/curl/curl-http3 \
#     --http3-only --cacert /certs/server.crt https://localhost:8445/healthz
# ) or any modern browser (they upgrade via the advertised Alt-Svc).
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-07-http3 ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# --- 1. The gateway bound the QUIC (UDP) listener and it did not fail.
# (Retry the log fetch: docker compose can hiccup under rapid calls.)
logs=""
for _ in 1 2 3; do
  logs=$(docker compose logs dwara 2>&1) || true
  grep -q "listening_h3" <<< "$logs" && break
  sleep 1
done
assert_contains "$logs" "listening_h3" "startup log shows the h3 listener (listening_h3)"
assert_not_contains "$logs" "h3_listener_failed" "no h3 listener failure logged"

# The log line names the listener and its UDP address.
h3_log=$(echo "$logs" | grep "listening_h3" | tail -1)
assert_contains "$h3_log" "edge-h3" "h3 log names the edge-h3 listener"
assert_contains "$h3_log" "0.0.0.0:8445" "h3 listener bound on 0.0.0.0:8445 (UDP)"

# --- 2. edge-https advertises the h3 port via Alt-Svc (protocol
# upgrade discovery for HTTP/1.1 + HTTP/2 clients). GET with headers
# dumped (a HEAD against the h2 connection trips curl exit 16 even
# though the response is complete).
headers=$(curl -s -D - -o /dev/null --cacert ../_shared/certs/server.crt \
  https://localhost:8443/healthz || true)
assert_contains "$headers" 'alt-svc: h3=":8445"' "edge-https response advertises Alt-Svc h3=\":8445\""

# --- 3. The published UDP port is listening on the host (docker's
# UDP port forward for 8445).
udp_listening=$(netstat -an -p udp 2>/dev/null | grep -c '\*\.8445' || true)
if [ "${udp_listening:-0}" -ge 1 ] 2>/dev/null; then
  echo -e "${GREEN}PASS${NC}: UDP :8445 is listening on the host (published QUIC port)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: UDP :8445 is not listening on the host"
  FAIL=$((FAIL + 1))
fi

echo ""
# --- Live HTTP/3 request end to end (aioquic client; macOS curl has no
# h3 support). Docker Desktop does not reliably forward QUIC through
# published UDP ports, so the client dials the gateway's docker-network
# address directly; --server-name keeps certificate verification
# against the demo cert's localhost SAN. The dwara-demo/h3-client image
# is built on demand:
#   docker compose --profile tools build h3-client
if docker image inspect dwara-demo/h3-client >/dev/null 2>&1; then
  # QUIC over the docker bridge can drop a datagram on a fresh
  # connection; retry with a new connection before declaring failure.
  out=""
  for _ in 1 2 3; do
    out=$(docker run --rm --network 10-tls-transport_tls-net \
      -v "$PWD/../_shared/certs:/certs:ro" \
      dwara-demo/h3-client --cafile /certs/server.crt --server-name localhost \
      https://dwara:8445/healthz 2>&1 || true)
    grep -q '200 {' <<< "$out" && break
    sleep 1
  done
  assert_contains "$out" '200 {"error":{"code":"ok"' "live HTTP/3 GET over QUIC returns 200 (verified, h3 ALPN)"
else
  echo "NOTE: live h3 request skipped — dwara-demo/h3-client not built."
  echo "      Build it (one-time) and re-run:"
  echo "        docker compose --profile tools build h3-client"
  echo "      (macOS curl lacks HTTP/3; any h3-capable client also works,"
  echo "      and browsers upgrade via the advertised Alt-Svc.)"
fi

print_summary
