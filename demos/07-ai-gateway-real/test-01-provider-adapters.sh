#!/bin/bash
# Test 01: Provider adapters (real LLMs).
#
# Sends a chat-completions request to each of the three real providers
# (z.ai/GLM-5.3, Ollama/llama3.2, LM Studio). Asserts each returns
# 200 and the response body contains a non-empty content field.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 01: Provider Adapters (real LLMs) ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# z.ai (GLM-5.3)
status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"glm-5.3","messages":[{"role":"user","content":"Say hello in one word"}]}' \
  --max-time 60)
assert_status 200 "$status" "glm-5.3 (z.ai) returns 200"

body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"glm-5.3","messages":[{"role":"user","content":"Say hello in one word"}]}' \
  --max-time 60)
echo "Response from z.ai is: $body"
content=$(echo "$body" | grep -o '"content": *"[^"]*"' | sed 's/.*"content": *"//;s/"$//' | head -1)
if [ -n "$content" ] && [ "$content" != "null" ]; then
  echo -e "${GREEN}PASS${NC}: glm-5.3 response has non-empty content"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: glm-5.3 response has empty content"
  FAIL=$((FAIL + 1))
fi

# Ollama (llama3.2)
status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"Say hello in one word"}]}' \
  --max-time 60)
assert_status 200 "$status" "llama3.2 (ollama) returns 200"

body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"Say hello in one word"}]}' \
  --max-time 60)
echo "Response from ollama is: $body"
content=$(echo "$body" | grep -o '"content": *"[^"]*"' | sed 's/.*"content": *"//;s/"$//' | head -1)
if [ -n "$content" ] && [ "$content" != "null" ]; then
  echo -e "${GREEN}PASS${NC}: llama3.2 response has non-empty content"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: llama3.2 response has empty content"
  FAIL=$((FAIL + 1))
fi

# LM Studio (loaded model)
status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"lmstudio-model","messages":[{"role":"user","content":"Say hello in one word"}]}' \
  --max-time 60)
assert_status 200 "$status" "lmstudio-model (LM Studio) returns 200"

body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"lmstudio-model","messages":[{"role":"user","content":"Say hello in one word"}]}' \
  --max-time 60)
echo "Response from lm-studio is: $body"
content=$(echo "$body" | grep -o '"content": *"[^"]*"' | sed 's/.*"content": *"//;s/"$//' | head -1)
if [ -n "$content" ] && [ "$content" != "null" ]; then
  echo -e "${GREEN}PASS${NC}: lmstudio-model response has non-empty content"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: lmstudio-model response has empty content"
  FAIL=$((FAIL + 1))
fi

print_summary
