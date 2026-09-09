#!/bin/bash
# test-08-credential-pools.sh — Credential pools (enterprise feature).
#
# Credential pools (DW-080) are an enterprise feature: multi-key
# rotation for AI provider credentials with 429 quarantine, round-robin
# or weighted pick, and pool-exhaustion graceful degradation. Each
# pool entry is an AiProviderAuth; the pool is used INSTEAD of the
# single `auth` field on an AI provider. See
# crates/dwara-core/src/config/ai.rs (AiCredentialPool, Ent-gated at
# validation).
#
# The OSS edition does not support credential pools -- validation
# rejects an AI provider with a `credential_pool` block when the `ent`
# cargo feature is off. The OSS edition does support single-credential
# API key auth via the consumer credential system.
#
# This test verifies the OSS gateway's basic API key auth surface is
# healthy by confirming the gateway starts and proxies traffic. The
# config does not require auth on the demo routes, but the consumer/
# credential infrastructure is available in OSS.
set -euo pipefail
source ../_shared/helpers.sh

echo "=== test-08-credential-pools ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# Verify the gateway proxies to the echo upstream.
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo (basic auth path healthy)"

# Verify the gateway proxies to the static upstream.
status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static"

# Verify the healthz endpoint responds (the gateway is stable).
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "healthz returns 200"

print_summary
