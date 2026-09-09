#!/bin/bash
# Test 14: Streaming SSE.
#
# Sends a chat-completions request with stream: true for the
# gpt-4o-mini alias. The gateway's AI proxy forwards the streaming
# request to the mock provider, which returns Server-Sent Events
# (data: {...}\n\n ... data: [DONE]\n\n). The gateway re-frames the
# SSE stream back to the client. Asserts the response contains
# `data:` SSE lines and the terminating `data: [DONE]` sentinel.
#
# The prompt is unique to this test: the demo config enables the AI
# semantic cache (test-05), and the non-streaming tests cache their
# "Hello" responses for the same alias -- a cache hit would replay the
# cached JSON body instead of streaming.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 14: Streaming SSE ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# -N disables curl's output buffering so the SSE stream is captured.
body=$(curl -sN "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"Write a streaming story about the sea"}]}')
echo "  response:"
echo "$body" | sed 's/^/    /'

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
