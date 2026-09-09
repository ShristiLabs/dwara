#!/bin/bash
# Test 02: Model aliasing.
#
# Sends a chat-completions request for the gpt-4o-mini alias and
# asserts the response's `model` field is gpt-4o-mini. The gateway
# resolves the alias to the provider model (here the same name) and
# the mock provider echoes the model it received back in the response.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 02: Model Alias ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}')

# Extract the `model` field from the JSON response.
model=$(echo "$body" | grep -o '"model": *"[^"]*"' | sed 's/.*"model": *"//;s/"$//' | head -1)
echo "  response model field: $model"

if [ "$model" = "gpt-4o-mini" ]; then
  echo -e "${GREEN}PASS${NC}: response model field is gpt-4o-mini"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: response model field is '$model' (expected gpt-4o-mini)"
  FAIL=$((FAIL + 1))
fi

print_summary
