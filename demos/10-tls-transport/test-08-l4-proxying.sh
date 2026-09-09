#!/bin/bash
# test-08-l4-proxying.sh — L4 TCP proxying (byte splice).
#
# The edge-l4-tcp listener (:8446) accepts raw TCP connections and
# splices them byte-for-byte to the echo upstream's endpoint (picked
# through echo-upstream's load balancer). No HTTP pipeline runs on
# this listener — no routing, transforms, or auth — the gateway just
# moves bytes, which is exactly what non-HTTP protocols (databases,
# SMTP, custom binaries) need.
#
# The live test speaks minimal HTTP over the raw socket (the echo
# upstream happens to speak HTTP) using python3's stdlib socket
# module: send GET /l4-test, read the response, assert the echo JSON
# flowed back through the splice.
#
# UNWIRED REMAINDER (documented): UDP L4 proxying (protocol: udp) is
# config-accepted but STUBBED — the dispatcher returns Unimplemented
# and the listener does not bind (the gateway logs
# `udp_listener_skipped`). UDP session semantics (per-client session
# tracking, NAT timeouts) are a follow-up. TCP SNI routing
# (l4.sni_routing: true) shares the TLS passthrough limitation of
# test-03: it needs an HTTPS upstream to complete a handshake.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-08-l4-proxying ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# --- Raw TCP through the splice: python3 stdlib socket client.
resp=$(python3 - <<'EOF'
import socket

with socket.create_connection(("localhost", 8446), timeout=10) as s:
    s.sendall(
        b"GET /l4-byte-splice HTTP/1.1\r\n"
        b"Host: echo\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    chunks = []
    while True:
        data = s.recv(65536)
        if not data:
            break
        chunks.append(data)
print((b"".join(chunks)).decode("utf-8", errors="replace"))
EOF
)
assert_contains "$resp" " 200 " "L4 splice returns the echo upstream's HTTP 200 status line"
assert_contains "$resp" '"instance": "echo"' "L4 splice relays the echo JSON body"
assert_contains "$resp" '"/l4-byte-splice"' "L4 splice preserves the requested path bytes"

# --- The gateway logged the L4 listener bind (retry the log fetch:
# docker compose can hiccup under rapid calls).
logs=""
for _ in 1 2 3; do
  logs=$(docker compose logs dwara 2>&1) || true
  grep -q "l4 tcp proxy" <<< "$logs" && break
  sleep 1
done
assert_contains "$logs" "l4 tcp proxy" "startup log shows edge-l4-tcp in 'l4 tcp proxy' mode"

# --- The splice idle timeout is configured (config-shape check).
cfg=$(grep -c "idle_timeout_s" dwara.yaml || true)
if [ "${cfg:-0}" -ge 1 ]; then
  echo -e "${GREEN}PASS${NC}: l4.idle_timeout_s present in dwara.yaml"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: l4.idle_timeout_s missing from dwara.yaml"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "NOTE: UDP L4 proxying (protocol: udp) is accepted by the config"
echo "      schema but stubbed at runtime (DW-103 follow-up): the"
echo "      dispatcher returns Unimplemented and the listener is not"
echo "      bound. TCP SNI routing (l4.sni_routing) works but needs an"
echo "      HTTPS upstream for a live handshake (see test-03)."

print_summary
