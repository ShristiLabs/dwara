#!/bin/bash
# test-08-secrets.sh — secret references via environment variables.
#
# The gateway supports ${ENV_NAME} secret references (DW-045) on
# secret-bearing config fields (e.g. consumers[].credentials[].api_key.key).
# References resolve at config-compile time — cold start and every hot
# reload re-read the environment. Unset or empty fails closed: the
# gateway refuses to start, naming the field.
#
# This demo sets DEMO_SECRET in the container environment (see
# docker-compose.yml) and references it as ${DEMO_SECRET} in the
# ops-consumer's api_key credential. Because the gateway is running,
# the secret resolved successfully; if DEMO_SECRET were unset, startup
# would have failed.
#
# This test:
#   1) Verifies the gateway is running (the secret resolved at startup).
#   2) Verifies the DEMO_SECRET env var is set inside the container.
#   3) Verifies the admin /config endpoint redacts the inline secret
#      (the resolved value is never echoed; ${...} references are
#      redacted in every config echo).
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

# Resolve the compose file relative to this script so `docker compose
# exec` works regardless of the project-name-prefixed container name.
COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

echo "=== test-08-secrets ==="

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# 1) The gateway is running, which means the ${DEMO_SECRET} reference
#    resolved at config-compile time (unset/empty fails closed).
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "gateway is running (DEMO_SECRET resolved at startup)"

# 2) Verify the DEMO_SECRET env var is set on the container. The
#    scratch image (FROM scratch) has no shell, so we cannot `exec
#    printenv` inside it; instead we inspect the container's config
#    environment via docker inspect.
echo "--- checking DEMO_SECRET env var on the container ---"
container_id=$(docker compose -f "$COMPOSE_FILE" ps -q dwara 2>/dev/null || true)
secret_env=""
if [ -n "$container_id" ]; then
  secret_env=$(docker inspect "$container_id" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep '^DEMO_SECRET=' || true)
fi
if [ -n "$secret_env" ]; then
  echo -e "${GREEN}PASS${NC}: DEMO_SECRET is set on the container ($secret_env)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: DEMO_SECRET is not set on the container"
  FAIL=$((FAIL + 1))
fi

# 3) Verify the admin /config endpoint redacts the secret value.
#    The resolved secret is never echoed; ${...} references are
#    redacted in every config echo (DW-045).
echo "--- verifying secret is redacted in admin /config ---"
config_body=$(http_body https://localhost:2019/config \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$config_body" "ops-consumer" "admin /config contains ops-consumer"
assert_not_contains "$config_body" "ops-secret-key-123" "admin /config does NOT echo the resolved secret value"

echo ""
echo "NOTE: secrets use the \${ENV_NAME} grammar (DW-045) on"
echo "secret-bearing config fields. References resolve at"
echo "config-compile time; unset/empty fails closed (the gateway"
echo "refuses to start). The resolved value is never echoed — the"
echo "admin /config endpoint redacts it. A \${file:/path} form is"
echo "also supported for mounted-secret / systemd LoadCredential shapes."
echo "Default values (\${ENV:default}) are NOT supported: the grammar"
echo "is strictly \${ENV_NAME} (fail-closed on unset)."

print_summary
