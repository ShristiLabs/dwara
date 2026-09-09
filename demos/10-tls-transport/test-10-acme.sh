#!/bin/bash
# test-10-acme.sh — ACME / Let's Encrypt automation (documented
# limitation: config-accepted, runtime stubbed).
#
# The edge-https listener carries a tls.acme block (SEC-02): domains,
# contact, challenge tls-alpn01, staging: true, state_dir. The config
# SCHEMA is fully accepted and validated (an empty domains list or a
# production config without contact emails is rejected), but the ACME
# CLIENT is not yet implemented: no account registration, challenge
# completion, issuance, or renewal task runs. Because ACME would only
# manage the FALLBACK certificates, the manual cert_file/key_file pair
# on the same listener keeps serving — the live assertions below
# verify exactly that graceful coexistence.
#
# To exercise real issuance once wired, a deployment needs:
#   - a publicly resolvable domain (api.example.com here is not),
#   - port 443 directly reachable by the CA's validation servers for
#     the tls-alpn01 challenge (the challenge is answered during the
#     TLS handshake; no separate HTTP listener is needed),
#   - staging: false and a contact email for Let's Encrypt production.
#
# Until then, use an external ACME client (certbot, lego,
# cert-manager) and point the gateway at the issued files.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-10-acme ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# --- Config shape: the acme block is present on the terminate
# listener with the documented fields.
cfg=$(cat dwara.yaml)
assert_contains "$cfg" "acme:" "tls.acme block present in dwara.yaml"
assert_contains "$cfg" "challenge: tls-alpn01" "acme challenge is tls-alpn01 (kebab-case value)"
assert_contains "$cfg" "staging: true" "acme staging directory selected (no rate-limit exposure)"
assert_contains "$cfg" "state_dir: /var/lib/dwara/acme" "acme state_dir points at the mounted data volume"

# --- The gateway started WITH the acme block in the config: the
# block is accepted, not fatal, and does not disturb TLS termination.
status=$(http_status https://localhost:8443/healthz --cacert ../_shared/certs/server.crt)
assert_status 200 "$status" "gateway serves TLS with an accepted-but-stubbed acme block"

# --- The manual certificate still serves (ACME has not replaced it):
# the presented leaf is the shared self-signed CN=localhost cert.
cert_subject=$(echo | openssl s_client -connect localhost:8443 \
  -servername localhost 2>/dev/null \
  | openssl x509 -noout -subject 2>/dev/null || true)
assert_contains "$cert_subject" "CN=localhost" "manual cert still serves (ACME issuance not wired)"

echo ""
echo "SKIP: live ACME issuance — the client is runtime-stubbed (SEC-02)."
echo "      The config block validates and coexists with the manual"
echo "      cert pair; see README.md for the TLS-ALPN-01/port-443"
echo "      requirements of a real deployment."

print_summary
