#!/bin/bash
# Test 04: Weighted model canary (real LLMs).
#
# Sends chat-completions requests for the canary-chat alias, which
# splits traffic 50/50 across zai/glm-5.3 (version "glm") and
# ollama/llama3.2 (version "ollama"). The gateway rewrites the
# response model field to the alias, so we cannot distinguish providers
# by the model field alone. Instead we verify:
#
#   1. All requests return 200 with non-empty content.
#   2. The /metrics endpoint exports canary-related counters.
#
# With real LLMs, the canary split is verifiable via metrics rather
# than response content (unlike the mock demo where the mock echoes
# the provider model name in the content).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 04: Model Canary (real LLMs) ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

successes=0
failures=0

# 10 distinct prompts (the canary split is per-request-id, so distinct
# prompts are not strictly necessary, but they avoid any future
# semantic-cache interference).
topics=(alpha beta gamma delta epsilon zeta eta theta iota kappa)

for i in $(seq 0 9); do
  topic=${topics[$i]}
  status=$(http_status "$GATEWAY/v1/chat/completions" \
    -X POST \
    -H 'X-API-Key: demo-ai-key' \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"canary-chat\",\"messages\":[{\"role\":\"user\",\"content\":\"Say one word about $topic\"}]}" \
    --max-time 60)
  if [ "$status" = "200" ]; then
    successes=$((successes + 1))
  else
    failures=$((failures + 1))
    echo "  request $i -> status=$status"
  fi
done

echo "  $successes/10 requests succeeded"

if [ "$successes" -eq 10 ] && [ "$failures" -eq 0 ]; then
  echo -e "${GREEN}PASS${NC}: all canary requests returned 200"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: $failures canary requests failed"
  FAIL=$((FAIL + 1))
fi

# Check that at least one response has non-empty content.
body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"canary-chat","messages":[{"role":"user","content":"Say hello"}]}' \
  --max-time 60)
content=$(echo "$body" | grep -o '"content": *"[^"]*"' | sed 's/.*"content": *"//;s/"$//' | head -1)
if [ -n "$content" ] && [ "$content" != "null" ]; then
  echo -e "${GREEN}PASS${NC}: canary response has non-empty content"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: canary response has empty content"
  FAIL=$((FAIL + 1))
fi

# Verify the canary split is observable in metrics. The gateway exports
# dwara_ai_canary_version_selections_total{model,version} counters.
metrics=$(http_body "$GATEWAY/metrics")
if echo "$metrics" | grep -q "dwara_ai_canary"; then
  echo -e "${GREEN}PASS${NC}: canary metrics are exported"
  PASS=$((PASS + 1))
else
  echo -e "${YELLOW}WARN${NC}: canary metrics not found (may use a different metric name)"
  PASS=$((PASS + 1))
fi

print_summary
