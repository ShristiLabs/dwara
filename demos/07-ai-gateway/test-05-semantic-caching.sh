#!/bin/bash
# Test 05: AI semantic caching (DW-083).
#
# The gateway's semantic cache is configured with the ai-mock as its
# embedding service (POST /v1/embeddings, deterministic token-set-hashed
# vectors: paraphrases that share content words land at cosine ~0.99,
# unrelated prompts near 0). Flow asserted:
#
#   1. prompt A ("What is the capital of France?")    -> miss, served by
#      the provider; dwara_ai_semantic_cache_misses_total{model} +1
#   2. prompt A again (identical)                      -> EXACT-match fast
#      tier hit, no provider call; hits_total +1; the cached response
#      body is replayed verbatim (same id)
#   3. prompt A' (paraphrase, >= 0.85 cosine)          -> SEMANTIC hit via
#      the HNSW index; hits_total +2; same cached body again
#
# The hit/miss counters are the guide-documented observable
# (dwara_ai_semantic_cache_hits_total / misses_total on /metrics).
set -euo pipefail
. "$(dirname "$0")/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"
MODEL="gpt-4o-mini"

echo "=== Test 05: Semantic Caching ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# metric_value <metric_line_regex>: the counter value of a metric series
# (empty string when the series has not been emitted yet; never aborts
# the script under `set -e`).
metric_value() {
  http_body "$GATEWAY/metrics" | grep -E "$1" | awk '{print $NF}' | head -1 || true
}

hits_line='dwara_ai_semantic_cache_hits_total\{model="gpt-4o-mini"\}'
misses_line='dwara_ai_semantic_cache_misses_total\{model="gpt-4o-mini"\}'

hits_before=$(metric_value "$hits_line"); hits_before=${hits_before:-0}
misses_before=$(metric_value "$misses_line"); misses_before=${misses_before:-0}
echo "  counters before: hits=$hits_before misses=$misses_before"

req() {
  http_body "$GATEWAY/v1/chat/completions" \
    -X POST \
    -H 'X-API-Key: demo-ai-key' \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":$1}]}"
}

json_field() { # json_field <body> <key> -- crude extraction of a top-level string field
  echo "$1" | grep -o "\"$2\": *\"[^\"]*\"" | head -1 | sed "s/.*\"$2\": *\"//;s/\"$//" || true
}

# --- 1. Prompt A: cache miss, served by the provider -----------------------
PROMPT_A='"What is the capital of France?"'
body_a=$(req "$PROMPT_A")
assert_contains "$body_a" "Mock response" "prompt A answered by the mock provider (first time)"
id_a=$(json_field "$body_a" "id")
echo "  response id for A: $id_a"

# The store is fire-and-forget (embedding + HNSW insert run after the
# response is sent); give it a moment before the repeat.
sleep 2

# --- 2. Prompt A again: exact-match fast-tier hit --------------------------
body_a2=$(req "$PROMPT_A")
assert_contains "$body_a2" "Mock response" "repeated prompt A answered 200"
id_a2=$(json_field "$body_a2" "id")
if [ -n "$id_a" ] && [ "$id_a" = "$id_a2" ]; then
  echo -e "${GREEN}PASS${NC}: identical prompt returned the cached response (same id $id_a)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: identical prompt did not replay the cached body (ids '$id_a' vs '$id_a2')"
  FAIL=$((FAIL + 1))
fi

# --- 3. Paraphrase A': semantic (embedding-similarity) hit -----------------
# Same content words as A, so the mock's embedding cosine similarity is
# ~0.99 -- above the configured 0.85 threshold.
PROMPT_B='"Can you tell me what the capital of France is?"'
body_b=$(req "$PROMPT_B")
assert_contains "$body_b" "Mock response" "paraphrase A-prime answered 200"
id_b=$(json_field "$body_b" "id")
if [ -n "$id_a" ] && [ "$id_b" = "$id_a" ]; then
  echo -e "${GREEN}PASS${NC}: paraphrase returned the cached response (same id $id_a)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: paraphrase did not hit the cache (ids '$id_a' vs '$id_b')"
  FAIL=$((FAIL + 1))
fi

# --- 4. Counters on /metrics -----------------------------------------------
sleep 1
hits_after=$(metric_value "$hits_line"); hits_after=${hits_after:-0}
misses_after=$(metric_value "$misses_line"); misses_after=${misses_after:-0}
echo "  counters after:  hits=$hits_after misses=$misses_after"

hits_delta=$((hits_after - hits_before))
misses_delta=$((misses_after - misses_before))
if [ "$misses_delta" -ge 1 ]; then
  echo -e "${GREEN}PASS${NC}: dwara_ai_semantic_cache_misses_total incremented (+$misses_delta)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: dwara_ai_semantic_cache_misses_total did not increment"
  FAIL=$((FAIL + 1))
fi
if [ "$hits_delta" -ge 2 ]; then
  echo -e "${GREEN}PASS${NC}: dwara_ai_semantic_cache_hits_total incremented twice (+$hits_delta: exact + semantic)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: expected +2 hits (exact + semantic), got +$hits_delta"
  FAIL=$((FAIL + 1))
fi

print_summary
