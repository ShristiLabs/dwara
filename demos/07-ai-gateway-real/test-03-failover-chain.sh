#!/bin/bash
# Test 03: Failover chain (real LLMs).
#
# Sends a chat-completions request for the failover-chat alias. The
# primary provider (dead) points at a dead port (:9999), so the
# connection always fails. The gateway's failover chain then retries
# against the ollama provider's llama3.2 model, which returns 200.
# Asserts the final response is 200 and has non-empty content.
#
# Note: the dead primary has a 2-second connect timeout, so the
# failover takes ~2 seconds. The curl --max-time allows 30 seconds.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 03: Failover Chain (real LLMs) ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"failover-chat","messages":[{"role":"user","content":"Say hello"}]}' \
  --max-time 30)
assert_status 200 "$status" "failover-chat falls over to ollama and returns 200"

body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"failover-chat","messages":[{"role":"user","content":"Say hello"}]}' \
  --max-time 30)
content=$(echo "$body" | grep -o '"content": *"[^"]*"' | sed 's/.*"content": *"//;s/"$//' | head -1)
if [ -n "$content" ] && [ "$content" != "null" ]; then
  echo -e "${GREEN}PASS${NC}: failover response has non-empty content"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: failover response has empty content"
  FAIL=$((FAIL + 1))
fi

# The response model field should be the alias, not the provider model.
model=$(echo "$body" | grep -o '"model": *"[^"]*"' | sed 's/.*"model": *"//;s/"$//' | head -1)
if [ "$model" = "failover-chat" ]; then
  echo -e "${GREEN}PASS${NC}: failover response model is the alias (failover-chat)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: failover response model is '$model' (expected failover-chat)"
  FAIL=$((FAIL + 1))
fi

print_summary
