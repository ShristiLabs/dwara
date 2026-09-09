#!/bin/bash
# Test 13: Model governance.
#
# Sends a chat-completions request for the claude-sonnet-4-5 model,
# which is NOT in the ai-budget policy's team allowlist
# ([gpt-4o-mini, gpt-4o]). The governance engine (DW-084) checks the
# requested model alias against the consumer's binding allowlists
# BEFORE routing and blocks a disallowed alias at the edge with 403
# `model_denied_by_policy`. Asserts the response is 403 or an error
# signaling the model was denied.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 13: Model Governance ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# claude-sonnet-4-5 is not in the ai-budget allowlist.
body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}')
status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}')
echo "  status: $status"
echo "  body:   $body"

if [ "$status" = "403" ]; then
  echo -e "${GREEN}PASS${NC}: disallowed model blocked with 403"
  PASS=$((PASS + 1))
elif echo "$body" | grep -qi "denied\|not_in_team_allowlist\|allowlist"; then
  echo -e "${GREEN}PASS${NC}: disallowed model blocked (body signals denial)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: disallowed model was not blocked (status $status)"
  FAIL=$((FAIL + 1))
fi

# Sanity check: an allowlisted model IS permitted.
allowed_status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}')
assert_status 200 "$allowed_status" "allowlisted model (gpt-4o-mini) is permitted"

print_summary
