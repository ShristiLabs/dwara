#!/bin/bash
# Test 04: Weighted model canary.
#
# Sends up to 40 chat-completions requests for the gpt-4o-canary alias.
# The alias splits traffic 90/10: the stable version (openai/gpt-4o) and
# the canary version (anthropic/claude-sonnet-4-5). The gateway rewrites
# the response `model` field back to the alias, but the mock's response
# content text echoes the provider model it received (e.g. "Mock
# response from model 'gpt-4o'"), so parsing the content reveals which
# provider served each request. Asserts both the stable and canary
# provider models are observed.
#
# Note: with a 90/10 split over 20 requests the expected canary count
# is 2; the test retries up to 40 total requests to drive the canary
# probability up (P(0 canary in 40) ~= 1.5%) for a stable demo.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 04: Model Canary ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

stable_model="gpt-4o"
canary_model="claude-sonnet-4-5"
saw_stable=0
saw_canary=0

# 40 distinct single-token topics. The demo config now enables the AI
# semantic cache (test-05); an identical prompt repeated on the same
# alias would return the FIRST response from the cache and freeze the
# split on whichever version served it. Distinct prompts make every
# request a cache miss, so each one traverses the canary split.
topics=(alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon
        aleph beth gimel daleth he waw zayin heth teth yod kaf lamed mem nun samekh ayin pe tsade qoph resh shin tav
        one two three four five six seven eight nine ten eleven twelve)

for i in $(seq 0 39); do
  topic=${topics[$i]}
  body=$(http_body "$GATEWAY/v1/chat/completions" \
    -X POST \
    -H 'X-API-Key: demo-ai-key' \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"gpt-4o-canary\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello, tell me about $topic\"}]}")
  # The gateway rewrites the response model field to the alias; the
  # mock's content text echoes the provider model it received.
  content=$(echo "$body" | grep -o '"content": *"[^"]*"' | sed 's/.*"content": *"//;s/"$//' | head -1)
  echo "  request $i -> content=$content"
  if echo "$content" | grep -q "model '$stable_model'"; then
    saw_stable=1
  elif echo "$content" | grep -q "model '$canary_model'"; then
    saw_canary=1
  fi
  # Stop early once both versions have been observed.
  if [ "$saw_stable" -eq 1 ] && [ "$saw_canary" -eq 1 ]; then
    break
  fi
done

if [ "$saw_stable" -eq 1 ]; then
  echo -e "${GREEN}PASS${NC}: stable version ($stable_model) observed"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: stable version ($stable_model) not observed"
  FAIL=$((FAIL + 1))
fi

if [ "$saw_canary" -eq 1 ]; then
  echo -e "${GREEN}PASS${NC}: canary version ($canary_model) observed"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: canary version ($canary_model) not observed (90/10 split; rerun if flaky)"
  FAIL=$((FAIL + 1))
fi

print_summary
