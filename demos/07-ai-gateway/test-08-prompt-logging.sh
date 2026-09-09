#!/bin/bash
# Test 08: Prompt logging.
#
# Sends a chat-completions request (which the gateway captures into
# the ai_prompt_logs table, DW-081, because prompt logging is enabled
# and the demo-user consumer opts in via ai_logging), then queries
# the mTLS-only admin API's POST /analytics/prompt-logs endpoint for
# the recent time window and asserts at least one captured row is
# returned.
#
# This test requires the admin API, which is mTLS-only. The client
# certificate (demos/_shared/certs/client.crt) is signed by the client
# CA the admin API trusts (client-ca.crt). The query body is a JSON
# object: { from_ms, to_ms, consumer?, limit? }.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"
ADMIN="https://localhost:2019"
CERTS="$SCRIPT_DIR/../_shared/certs"

echo "=== Test 08: Prompt Logging ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# 1. Send a chat request that should be captured.
chat_body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Log me please"}]}')
assert_contains "$chat_body" "Mock response" "chat request succeeded before querying logs"

# Give the fire-and-forget prompt-log writer a moment to flush.
sleep 1

# 2. Query the admin API for the recent prompt-log window (last hour).
now_ms=$(($(date +%s) * 1000))
from_ms=$((now_ms - 3600000))
query=$(cat <<EOF
{"from_ms": $from_ms, "to_ms": $now_ms, "consumer": "demo-user", "limit": 100}
EOF
)

echo "  querying admin API POST /analytics/prompt-logs ..."
# The admin API presents a self-signed server cert (CN=localhost), so
# we trust the server.crt as the CA and present the client cert signed
# by client-ca.crt for mutual TLS.
admin_body=$(curl -s --cacert "$CERTS/server.crt" \
  --cert "$CERTS/client.crt" --key "$CERTS/client.key" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d "$query" \
  "$ADMIN/analytics/prompt-logs")
echo "  admin response: $admin_body"

# The endpoint returns { "query": {...}, "rows": [...] }. Assert at
# least one row was captured for the demo-user consumer.
row_count=$(echo "$admin_body" | grep -o '"rows": *\[' | head -1)
if [ -n "$row_count" ]; then
  # Count the captured rows (number of "request_id" occurrences).
  count=$(echo "$admin_body" | grep -o '"request_id"' | wc -l | tr -d ' ')
  echo "  captured rows: $count"
  if [ "$count" -ge 1 ]; then
    echo -e "${GREEN}PASS${NC}: prompt log captured at least one row"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: prompt log query returned no rows"
    FAIL=$((FAIL + 1))
  fi
else
  echo -e "${RED}FAIL${NC}: prompt log query did not return a rows array"
  echo "  (this requires the admin API; ensure the gateway is running with mTLS certs)"
  FAIL=$((FAIL + 1))
fi

print_summary
