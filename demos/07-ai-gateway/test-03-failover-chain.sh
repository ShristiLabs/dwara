#!/bin/bash
# Test 03: Failover chain.
#
# Sends a chat-completions request for the rate-limit-test alias. The
# primary provider (openai) forwards to the mock's rate-limit-test
# model, which returns 429. The gateway's failover chain then retries
# against the anthropic provider's gpt-4o-mini model (ai-mock-2),
# which returns 200. Asserts the final response is 200.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 03: Failover Chain ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"rate-limit-test","messages":[{"role":"user","content":"Hello"}]}')
assert_status 200 "$status" "rate-limit-test failovers to anthropic and returns 200"

body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"rate-limit-test","messages":[{"role":"user","content":"Hello"}]}')
assert_contains "$body" "Mock response" "failover response contains mock canned content"

print_summary
