#!/bin/bash
# test-13-agent-operable-admin.sh — MCP endpoints on the admin API.
#
# Dwara ships agent-operable administration over MCP (Model Context
# Protocol): a typed tool surface over the admin data model
# (list_routes, get_route, create_route, update_route, delete_route,
# list_services, get_stats, get_health, get_config, purge_cache)
# with per-agent permissions (read / write / admin RBAC) and JSON
# Schema argument validation.
#
# The MCP SERVER (crates/dwara-core/src/mcp) is a compile-time
# library capability with no transport mounted yet — there is no
# /mcp tools/call endpoint on the admin listener; an embedding
# constructs the McpServer, connects a transport, and supplies a
# ToolHandler (see docs-site/guide/agent-operable-admin.md). That
# half is a documented limitation.
#
# What IS live on the admin listener (DW-087) and asserted here:
#   - GET  /mcp/sessions  — list active MCP sessions (from the
#     state store; this demo runs with DWARA_STATE_DB set, so the
#     store is configured).
#   - GET  /mcp/tools     — list configured MCP tools from the
#     current snapshot's ai.mcp block (empty here: the demo config
#     configures no AI MCP tools -> {"tools": []}).
#   - GET  /mcp/calls     — MCP tool call analytics (from_ms/to_ms
#     required); this demo runs WITHOUT an analytics store, so the
#     documented analytics_not_configured 404 is the expected shape.
#   - DELETE /mcp/sessions/:id — idempotent session teardown.
#
# All calls ride the admin listener's mTLS (client cert + key), the
# same authentication an MCP transport embedding would sit behind.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-13-agent-operable-admin ==="

# Wait for the admin API to be ready (mTLS handshake against /health).
echo "--- waiting for admin API (mTLS /health) ---"
elapsed=0
code=""
while [ $elapsed -lt 30 ]; do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    --cert "$CERTS/client.crt" \
    --key "$CERTS/client.key" \
    --cacert "$CERTS/server.crt" \
    https://localhost:2019/health 2>/dev/null || true)
  if [ "$code" = "200" ]; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [ "$code" != "200" ]; then
  echo "ERROR: admin API /health not ready after 30s"
  exit 1
fi

# 1) GET /mcp/sessions: 200 with a sessions array (the state store
#    is configured via DWARA_STATE_DB in docker-compose.yml).
status=$(http_status https://localhost:2019/mcp/sessions \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "GET /mcp/sessions returns 200"

sessions_body=$(http_body https://localhost:2019/mcp/sessions \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$sessions_body" '"sessions"' "sessions response is JSON with a sessions array"

# 2) GET /mcp/tools: 200; the demo configures no ai.mcp block, so
#    the tool list is empty ({"tools": []}).
status=$(http_status https://localhost:2019/mcp/tools \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$status" "GET /mcp/tools returns 200"

tools_body=$(http_body https://localhost:2019/mcp/tools \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$tools_body" '"tools"' "tools response is JSON with a tools array"

# 3) DELETE /mcp/sessions/:id: idempotent teardown — returns 200
#    whether or not the id existed.
status=$(http_status https://localhost:2019/mcp/sessions/nonexistent-session \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt" \
  -X DELETE)
assert_status 200 "$status" "DELETE /mcp/sessions/:id returns 200 (idempotent)"

# 4) GET /mcp/calls without an analytics store: the documented 404
#    analytics_not_configured envelope (this demo runs without a
#    gateway.analytics block).
status=$(http_status "https://localhost:2019/mcp/calls?from_ms=0&to_ms=9999999999999" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 404 "$status" "GET /mcp/calls returns 404 without an analytics store"

calls_body=$(http_body "https://localhost:2019/mcp/calls?from_ms=0&to_ms=9999999999999" \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$calls_body" "analytics_not_configured" \
  "calls 404 names analytics_not_configured"

# 5) mTLS is the only way in (an agent embedding the MCP transport
#    inherits the same gate).
echo "--- verifying agent endpoints inherit mTLS (no client cert) ---"
no_cert_code=$(curl -s -o /dev/null -w '%{http_code}' \
  --cacert "$CERTS/server.crt" \
  https://localhost:2019/mcp/tools 2>/dev/null) || true
if [ "$no_cert_code" != "200" ]; then
  echo -e "${GREEN}PASS${NC}: MCP admin endpoints reject request without client cert (got '$no_cert_code')"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: MCP admin endpoint served without a client cert"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "SKIP (documented limitation): the MCP SERVER itself (tools/call"
echo "      dispatch with per-agent RBAC and JSON Schema argument"
echo "      validation, crates/dwara-core/src/mcp) is a library"
echo "      surface with no transport mounted yet — there is no"
echo "      tools/call endpoint to drive end to end. The admin"
echo "      endpoints above (sessions/tools/calls) are the live"
echo "      operational surface for MCP traffic today. To exercise"
echo "      the engine: cargo test -p dwara-core --features mcp mcp"

print_summary
