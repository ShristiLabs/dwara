#!/bin/bash
# Test 15: A2A (agent-to-agent) protocol -- wired subset (DW-114).
#
# WHAT IS WIRED: the A2A provider adapter. The a2a-echo model alias
# routes through the ai.a2a mock-agent provider: the gateway folds the
# canonical chat request into a JSON-RPC 2.0 tasks/submit body, POSTs
# it to the agent's upstream (ai-mock-2), and parses the task response
# (result.message / result.state / usage) back into the OpenAI chat
# shape. The Agent Card (inline JSON in dwara.yaml) is parsed and
# validated at config-compile time.
#
# DOCUMENTED LIMITATIONS (spec not frozen, task lifecycle partial in
# this build): gateway-served Agent Card discovery
# (/.well-known/agent-card.json) is not wired -- cards are config
# assets only; long-running task negotiation/streaming between agents
# and the admin task-lifecycle surface are not exposed. See the README.
set -euo pipefail
. "$(dirname "$0")/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 15: A2A Protocol (wired subset) ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

# --- 1. Chat request routed through the A2A adapter ------------------------
# The mock agent's /tasks/submit handler answers with an
# "A2A mock agent reply to: ..." message; only a request that actually
# traversed the a2a adapter (tasks/submit + result.message parsing)
# can surface that text in an OpenAI-shaped chat response.
body=$(http_body "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"a2a-echo","messages":[{"role":"user","content":"Hello from an agent"}]}')
status=$(http_status "$GATEWAY/v1/chat/completions" \
  -X POST \
  -H 'X-API-Key: demo-ai-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"a2a-echo","messages":[{"role":"user","content":"Hello from an agent"}]}')
echo "  status: $status"
echo "  body:   $body"

assert_status 200 "$status" "a2a-echo chat request returns 200"
assert_contains "$body" "A2A mock agent reply" "response content came from the A2A task result"
assert_contains "$body" "Hello from an agent" "the task message text round-tripped through the adapter"

# The task completed: the adapter maps the completed task state onto
# the standard finish reason.
assert_contains "$body" '"finish_reason": *"stop"' "completed task state maps to finish_reason stop"

# --- 2. Documented limitation: Agent Card discovery is NOT wired ----------
# The guide describes /.well-known/agent-card.json?id=<agent-id> as the
# gateway-managed discovery endpoint; this build serves cards from
# config only (no HTTP route). Asserting the 404 keeps the gap visible
# instead of silently passing.
status=$(http_status "$GATEWAY/.well-known/agent-card.json?id=mock-agent")
assert_status 404 "$status" "agent-card discovery endpoint is not wired (documented limitation)"

print_summary
