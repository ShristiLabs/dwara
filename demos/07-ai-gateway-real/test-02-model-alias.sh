#!/bin/bash
# Test 02: Model aliasing (real LLMs).
#
# Sends chat-completions requests for different aliases and asserts the
# response `model` field echoes the alias back (the gateway rewrites the
# provider model to the alias; the provider model never leaks).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 02: Model Alias (real LLMs) ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# Test glm-5.3 alias
body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"glm-5.3","messages":[{"role":"user","content":"Say hello"}]}' \
  --max-time 60)
model=$(echo "$body" | grep -o '"model": *"[^"]*"' | sed 's/.*"model": *"//;s/"$//' | head -1)
echo "  glm-5.3 -> response model: $model"
if [ "$model" = "glm-5.3" ]; then
  echo -e "${GREEN}PASS${NC}: glm-5.3 alias echoed back"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: glm-5.3 alias not echoed (got '$model')"
  FAIL=$((FAIL + 1))
fi

# Test llama3.2 alias
body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"Say hello"}]}' \
  --max-time 60)
model=$(echo "$body" | grep -o '"model": *"[^"]*"' | sed 's/.*"model": *"//;s/"$//' | head -1)
echo "  llama3.2 -> response model: $model"
if [ "$model" = "llama3.2" ]; then
  echo -e "${GREEN}PASS${NC}: llama3.2 alias echoed back"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: llama3.2 alias not echoed (got '$model')"
  FAIL=$((FAIL + 1))
fi

# Test lmstudio-model alias (LM Studio)
body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"lmstudio-model","messages":[{"role":"user","content":"Say hello"}]}' \
  --max-time 60)
model=$(echo "$body" | grep -o '"model": *"[^"]*"' | sed 's/.*"model": *"//;s/"$//' | head -1)
echo "  lmstudio-model -> response model: $model"
if [ "$model" = "lmstudio-model" ]; then
  echo -e "${GREEN}PASS${NC}: lmstudio-model alias echoed back"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: lmstudio-model alias not echoed (got '$model')"
  FAIL=$((FAIL + 1))
fi

print_summary
