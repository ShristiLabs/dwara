#!/bin/bash
# test-09-pq-tls.sh — post-quantum TLS opt-in (tls.pq).
#
# The edge-https listener sets tls.pq: true (DW-105): the listener
# OPTS IN to preferring the hybrid X25519+ML-KEM key-exchange group
# in its TLS handshakes. The flag is additive and the classical
# X25519 group stays in the list as a fallback, so ordinary clients
# (curl, browsers, grpcurl) complete the handshake either way — that
# fallback safety is exactly what this test asserts.
#
# STATUS (documented): the PQ wiring point (install_pq_kx_group) is a
# documented no-op in the pinned rustls version — the experimental
# rustls hybrid-kx API is not stable yet, so the handshake runs with
# the classical kx group list even with pq: true. The config flag,
# validation rules (rejected on passthrough listeners and in FIPS
# builds), and the dwara_tls_pq_handshakes_total metric are all in
# place; the kx group activates when the rustls API lands.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-09-pq-tls ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# --- Config shape: the terminate listener opts in (tls.pq: true).
cfg=$(grep -c "pq: true" dwara.yaml || true)
if [ "${cfg:-0}" -ge 1 ]; then
  echo -e "${GREEN}PASS${NC}: tls.pq: true present in dwara.yaml (edge-https)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: tls.pq: true missing from dwara.yaml"
  FAIL=$((FAIL + 1))
fi

# --- A normal curl handshake still succeeds with the PQ preference
# on: the classical fallback keeps non-PQ clients working.
status=$(http_status https://localhost:8443/healthz --cacert ../_shared/certs/server.crt)
assert_status 200 "$status" "curl --cacert handshake succeeds with tls.pq: true"

# --- The handshake still negotiates h2 via ALPN (the PQ flag does not
# disturb protocol negotiation).
proto=$(curl -s -o /dev/null -w '%{http_version}' \
  --http2 --cacert ../_shared/certs/server.crt \
  https://localhost:8443/healthz)
assert_status "2" "$proto" "ALPN still negotiates HTTP/2 with pq: true"

# --- Cert verification still applies (the flag changes only the kx
# group preference, not the trust model): the wrong CA is rejected.
bad=$(http_status https://localhost:8443/healthz --cacert ../_shared/certs/client-ca.crt 2>/dev/null || true)
assert_status "000" "$bad" "untrusted CA still fails the handshake (trust model unchanged)"

echo ""
echo "NOTE: the X25519+ML-KEM hybrid group itself is INERT in this"
echo "      build — rustls's experimental PQ kx API is not stable in"
echo "      the pinned version, so install_pq_kx_group() is a"
echo "      documented no-op and handshakes use the classical group"
echo "      list. The flag is accepted, validated (rejected with FIPS"
echo "      mode / passthrough listeners), and metrics are wired."

print_summary
