#!/bin/bash
# Test 01: Provider adapters.
#
# Sends a chat-completions request for the gpt-4o-mini alias. The
# gateway's OpenAI provider adapter translates the alias to the
# provider model and forwards to the ai-mock upstream. Asserts the
# response is 200 and the body carries the mock's canned content.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 01: Provider Adapters ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}')
assert_status 200 "$status" "gpt-4o-mini chat completion returns 200"

body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}')
assert_contains "$body" "Mock response" "response body contains mock canned content"

print_summary
