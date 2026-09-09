#!/bin/bash
# test-11-kms-secrets.sh — KMS secrets (enterprise feature).
#
# The KMS SecretSource uses envelope encryption: secrets are stored
# encrypted in the config (or a file) as `key_id:ciphertext` references,
# and the KMS provider (aws-kms, gcp-kms, azure-kv, or a mock for
# testing) decrypts them at resolve time. This keeps secrets encrypted
# at rest while avoiding a live dependency on a secret server. External
# secret sources (Vault/KMS) fail closed: if a secret cannot be
# resolved, the gateway does not start (or does not reload). See
# docs-site/guide/kms-secrets.md and the SecretSource trait at
# crates/dwara-core/src/extensions/secrets.rs.
#
# Like Vault (test-05), KMS is an enterprise feature with NO
# config-level block in the OSS build: the SecretSource implementation
# is selected at startup based on compiled features and license. The
# OSS edition ships env/file-based secret resolution via the ${...}
# grammar (DW-045), which works in both editions.
#
# This test follows the documented style test-05 established, plus one
# fail-closed config-layer probe:
#   1) The gateway starts and proxies traffic (the OSS secret
#      resolution path is healthy).
#   2) A scratch config with a `secret_sources:` KMS block is REJECTED
#      by OSS validation (unknown field). The OSS build fails closed
#      on secret-source config it cannot honor -- it never silently
#      ignores a KMS source it cannot decrypt from.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-11-kms-secrets ==="

# Locate the host operator CLI (`dwara-cli`) for the fail-closed probe.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI=""
for c in "$SCRIPT_DIR/../../target/debug/dwara-cli" \
         "$SCRIPT_DIR/../../target/release/dwara-cli" \
         "$(command -v dwara-cli 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then CLI="$c"; break; fi
done
if [ -z "$CLI" ]; then
  echo -e "${RED}FAIL${NC}: dwara-cli not found (build it: cargo build -p dwara-cli)"
  FAIL=$((FAIL + 1))
  print_summary
  exit 1
fi

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# 1) Verify the gateway is running and proxying (the OSS secret
#    resolution path -- env/file via the ${...} grammar -- is healthy).
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "gateway started with valid config (OSS secret path)"

status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo"

status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static"

# 2) Fail-closed probe: the `secret_sources:` KMS block from the guide
#    is not part of the OSS config schema, so validation rejects it
#    outright. An OSS gateway never accepts (and then ignores) a KMS
#    secret source it cannot decrypt from -- unknown secret-source
#    config is a hard error, mirroring the runtime fail-closed
#    contract of the enterprise Vault/KMS sources.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
cat > "$SCRATCH/kms.yaml" <<'EOF'
listeners:
  - name: edge-http
    address: 127.0.0.1
    port: 9099
    protocol: http
routes:
  - name: healthz
    service: echo-service
    match:
      path:
        type: exact
        value: /healthz
    action:
      type: respond
      status: 200
      body: ok
    auth_required: false
services:
  - name: echo-service
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9098
secret_sources:
  - type: kms
    provider: aws-kms
    key_id: alias/dwara-secrets
EOF
out=$("$CLI" validate "$SCRATCH/kms.yaml" 2>&1) && rc=0 || rc=1
assert_status 1 "$rc" "secret_sources KMS block rejected by OSS schema (fail-closed)"
assert_contains "$out" "unknown field" "rejection names the unknown field (no silent KMS acceptance)"

echo ""
echo "NOTE: KMS envelope encryption is an ent-gated runtime concern"
echo "(selected at startup; no OSS config block). References look like"
echo "kms:alias/dwara-secrets:<base64 ciphertext> once licensed; the"
echo "provider decrypts at resolve time and fails closed on any"
echo "resolution failure. The OSS edition resolves secrets via the"
echo "\${ENV} / \${file:/path} grammar (DW-045). See"
echo "docs-site/guide/kms-secrets.md."

print_summary
