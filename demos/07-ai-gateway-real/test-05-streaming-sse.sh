#!/bin/bash
# Test 05: Streaming SSE (real LLMs).
#
# Sends a chat-completions request with stream: true for the llama3.2
# alias (ollama, local and fast). The gateway forwards the streaming
# request to ollama, which returns Server-Sent Events. The gateway
# re-frames the SSE stream back to the client. Asserts the response
# contains data: SSE lines and the terminating data: [DONE] sentinel.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 05: Streaming SSE (real LLMs) ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# -N disables curl's output buffering so the SSE stream is captured.
body=$(curl -sN "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","stream":true,"messages":[{"role":"user","content":"Count from 1 to 5"}]}' \
  --max-time 60)
echo "  response (first 10 lines):"
echo "$body" | head -10 | sed 's/^/    /'

assert_contains "$body" 'data:' "SSE response contains data: lines"

# Use grep -F so [DONE] is treated as a literal string, not a regex
# character class.
if echo "$body" | grep -qF 'data: [DONE]'; then
  echo -e "${GREEN}PASS${NC}: SSE response terminates with data: [DONE]"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: SSE response does not terminate with data: [DONE]"
  FAIL=$((FAIL + 1))
fi

print_summary
