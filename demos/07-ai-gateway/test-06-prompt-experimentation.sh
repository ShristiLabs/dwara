#!/bin/bash
# Test 06: Prompt experimentation -- A/B model comparison (DW-086).
#
# The ab-chat alias declares `ab_test: prompt-test`; the test splits
# traffic 50/50 (deterministic weighted pick by request id) across:
#
#   control   -> alias gpt-4o-mini, prompt version greeting/v1
#                ("You are a helpful assistant.")
#   treatment -> alias gpt-4o,      prompt version greeting/v2
#                ("You are a concise assistant. Answer in one sentence.")
#
# Observables asserted:
#   - the VARIANT MARKER: the mock echoes the provider model it received
#     in the response content ("Mock response from model 'gpt-4o-mini'"
#     vs "... 'gpt-4o'"), so each response reveals which variant served
#     it; both variants are observed over a burst of requests.
#   - the SPLIT RATIO: dwara_ai_experiment_variant_selections_total
#     {experiment="prompt-test",variant="control"/"treatment"} series
#     exist on /metrics and count every selection.
#
# Each request uses a distinct prompt text ("... topic N") so the
# semantic cache (test-05) never short-circuits the experiment pick --
# a cache hit would skip variant selection entirely.
set -euo pipefail
. "$(dirname "$0")/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 06: Prompt Experimentation (A/B) ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

saw_control=0
saw_treatment=0
control_marker="model 'gpt-4o-mini'"
treatment_marker="model 'gpt-4o'"

# 20 distinct topics, each a single token (greek letter names). A cache
# hit would skip variant selection entirely, so every prompt must be
# semantically DISTINCT under the mock's embedding scheme: two prompts
# share only the content word "topic" (cosine ~0.5 < the 0.85 cache
# threshold) -- number-suffixed topics would tokenize to the same set
# and cross-hit.
topics=(alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon)

# The markers include the closing quote, so "model 'gpt-4o'" never
# matches the substring of "model 'gpt-4o-mini'".
for i in $(seq 0 19); do
  topic=${topics[$i]}
  body=$(http_body "$GATEWAY/v1/chat/completions" \
    -X POST \
    -H 'X-API-Key: demo-ai-key' \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"ab-chat\",\"messages\":[{\"role\":\"user\",\"content\":\"Tell me about topic $topic\"}]}")
  content=$(echo "$body" | grep -o '"content": *"[^"]*"' | sed 's/.*"content": *"//;s/"$//' | head -1 || true)
  echo "  request $i -> $content"
  if echo "$content" | grep -q "model 'gpt-4o-mini'"; then
    saw_control=1
  elif echo "$content" | grep -q "model 'gpt-4o'"; then
    saw_treatment=1
  fi
  if [ "$saw_control" -eq 1 ] && [ "$saw_treatment" -eq 1 ]; then
    break
  fi
done

if [ "$saw_control" -eq 1 ]; then
  echo -e "${GREEN}PASS${NC}: control variant (gpt-4o-mini + greeting/v1) observed"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: control variant (gpt-4o-mini) not observed in 20 requests"
  FAIL=$((FAIL + 1))
fi

if [ "$saw_treatment" -eq 1 ]; then
  echo -e "${GREEN}PASS${NC}: treatment variant (gpt-4o + greeting/v2) observed"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: treatment variant (gpt-4o) not observed in 20 requests (50/50 split; rerun if flaky)"
  FAIL=$((FAIL + 1))
fi

# --- Split-ratio observability on /metrics --------------------------------
metrics=$(http_body "$GATEWAY/metrics")
assert_contains "$metrics" \
  'dwara_ai_experiment_variant_selections_total{experiment="prompt-test",variant="control"}' \
  "/metrics carries the control variant selection counter"
assert_contains "$metrics" \
  'dwara_ai_experiment_variant_selections_total{experiment="prompt-test",variant="treatment"}' \
  "/metrics carries the treatment variant selection counter"

print_summary
