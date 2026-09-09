#!/bin/bash
# Test 11: MCP gateway.
#
# Sends an MCP JSON-RPC tools/list request to the /mcp path. The
# gateway (DW-087) compiles the ai.mcp.tools table into an MCP server
# and returns the tool definitions. The /mcp path shadows any
# configured route (it is checked before route resolution). Asserts
# the response is 200 and the result carries the configured tools
# (search_docs, get_status).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_shared/helpers.sh"

GATEWAY="http://localhost:8080"

echo "=== Test 11: MCP Gateway ==="

wait_for "$GATEWAY/healthz" 30 || exit 1

body=$(http_body "$GATEWAY/mcp" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}')
status=$(http_status "$GATEWAY/mcp" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}')
echo "  status: $status"
echo "  body:   $body"

assert_status 200 "$status" "MCP tools/list returns 200"
assert_contains "$body" "search_docs" "tools/list includes search_docs"
assert_contains "$body" "get_status" "tools/list includes get_status"

print_summary
