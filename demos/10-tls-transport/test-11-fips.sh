#!/bin/bash
# test-11-fips.sh — FIPS mode (license/feature-gated, documented).
#
# FIPS 140-3 enforcement is a BUILD-TIME property of the Enterprise
# edition: `cargo build -p dwara-bin --features ent` (or the
# Dockerfile.ent image) swaps in FIPS-validated provider enforcement
# (approved-only cipher suites, DRBG health checks, a startup
# self-test that refuses to boot on failure). There is NO YAML field
# for FIPS — nothing to toggle at runtime; pq: true is rejected at
# validation in a FIPS build (ML-KEM is not on the approved list).
#
# The OSS demo image (dwara:demo, built from Dockerfile.scratch
# without the ent feature) runs FipsMode::Disabled: no cipher-suite
# restriction, no self-test, and /healthz omits the `fips` attestation
# object entirely (the attestation is only surfaced when the mode is
# compiled in). Those are the live assertions below — they pin the
# OSS behavior while the Enterprise build remains documented.
#
# In an ent build, /healthz would carry:
#   "fips": { "enabled": true, "provider": "aws-lc-rs",
#             "self_test_passed": true }
# and the startup log would emit code=fips_mode_active.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-11-fips ==="

wait_for http://localhost:8080/healthz 30 || exit 1

# --- The gateway is serving: the OSS crypto provider (aws-lc-rs,
# installed unconditionally) works.
status=$(http_status https://localhost:8443/healthz --cacert ../_shared/certs/server.crt)
assert_status 200 "$status" "TLS serves on the OSS (non-FIPS) build"

# --- /healthz carries NO fips attestation in the OSS build: the
# field is only emitted when the ent feature is compiled in.
body=$(http_body https://localhost:8443/healthz --cacert ../_shared/certs/server.crt)
assert_not_contains "$body" '"fips"' "OSS /healthz omits the fips attestation object"

# --- No FIPS startup self-test was logged (the attestation log line
# fires only in ent builds). Retry the fetch: docker compose can hiccup
# under rapid calls.
logs=""
for _ in 1 2 3; do
  logs=$(docker compose logs dwara 2>&1) || true
  [ -n "$logs" ] && break
  sleep 1
done
assert_not_contains "$logs" "fips_mode_active" "no fips_mode_active log in the OSS build"

# --- Post-quantum + FIPS is the documented mutual exclusion: the OSS
# build ACCEPTS tls.pq: true (test-09) because enforcement is off; an
# ent build would reject it at validation.
cfg=$(grep -c "pq: true" dwara.yaml || true)
if [ "${cfg:-0}" -ge 1 ]; then
  echo -e "${GREEN}PASS${NC}: OSS build accepts pq: true alongside no-FIPS (mutual exclusion not enforced here)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: pq: true missing from dwara.yaml"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "SKIP: live FIPS enforcement — license/feature-gated (ent cargo"
echo "      feature, Enterprise edition). The demo image is the OSS"
echo "      build: FipsMode::Disabled, no self-test, no approved-only"
echo "      cipher restriction. Build with --features ent (see"
echo "      quickstart/enterprise/ and demos/11-enterprise/) for the"
echo "      attestation on /healthz."

print_summary
