#!/bin/bash
# test-12-audit-log.sh — audit log (enterprise feature).
#
# The enterprise workspace audit log is an append-only record of
# administrative activity: every admin action is recorded with who
# performed it (mTLS cert subject), what they did (action), which
# workspace was affected, the before/after state, a request id, a
# timestamp, and a monotonically increasing, gap-free sequence number.
# Entries cannot be modified or deleted after the fact. It completes
# the multi-tenant story: workspaces provide the isolation boundary,
# RBAC decides who may act, and the audit log records what they
# actually did. It is queried via the admin API
# (GET /workspaces/<name>/audit). See docs-site/guide/audit-log.md and
# crates/dwara-core/src/workspace/mod.rs (ent-gated).
#
# The OSS-adjacent config surface that IS real: the `admin.audit`
# block (SEC-01). When present, all mutating admin actions (PATCH
# /config, purge) are specified to be recorded in an append-only audit
# table in the state store (actor cert fingerprint or token hash,
# action, before/after config hash, timestamp). In the OSS build the
# block is accepted but INERT -- no runtime consumer records entries.
#
# This test verifies the accepted-but-inert behavior:
#   1) The gateway starts with the `admin.audit` block in the demo
#      config (proving the block is accepted).
#   2) The admin API is reachable over mTLS and serves reads normally
#      (no audit-gated behavior in OSS).
#   3) The block's shape validates via `dwara-cli validate` on a
#      scratch config.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-12-audit-log ==="

# Locate the host operator CLI (`dwara-cli`) for the config-shape probe.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI=""
for c in "$SCRIPT_DIR/../../target/debug/dwara-cli" \
         "$SCRIPT_DIR/../../target/release/dwara-cli" \
         "$(command -v dwara-cli 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then CLI="$c"; break; fi
done
if [ -z "$CLI" ]; then
  echo -e "${RED}FAIL${NC}: dwara-cli not found (build it: cargo build -p dwara-cli)"
  FAIL=$((FAIL + 1))
  print_summary
  exit 1
fi

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

# 1) The gateway started successfully with the admin.audit block in
#    ./dwara.yaml -- the block is accepted-but-inert in the OSS build
#    (no runtime consumer records audit entries).
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "gateway started with inert admin.audit block (accepted)"

status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo (no audit gating in OSS)"

# 2) The admin API is reachable over mTLS and serves reads normally.
admin_status=$(http_status https://localhost:2019/health \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$admin_status" "admin API /health reachable over mTLS"

# The config echo contains the accepted audit block (shape round-trips
# through the running gateway).
config_body=$(http_body https://localhost:2019/config \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_contains "$config_body" "audit" "admin /config echo contains the audit block"

# 3) Config-shape probe: a scratch config with the admin.audit block
#    validates via dwara-cli (the OSS schema accepts the block).
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
cat > "$SCRATCH/audit.yaml" <<'EOF'
listeners:
  - name: edge-http
    address: 127.0.0.1
    port: 9099
    protocol: http
routes:
  - name: healthz
    service: echo-service
    match:
      path:
        type: exact
        value: /healthz
    action:
      type: respond
      status: 200
      body: ok
    auth_required: false
services:
  - name: echo-service
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9098
admin:
  bind: 127.0.0.1:2019
  tls:
    cert_file: /etc/dwara/certs/server.crt
    key_file: /etc/dwara/certs/server.key
    client_ca_file: /etc/dwara/certs/client-ca.crt
  audit:
    enabled: true
EOF
out=$("$CLI" validate "$SCRATCH/audit.yaml" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "admin.audit block shape validates via dwara-cli"
assert_contains "$out" "ok:" "validation prints ok for the audit block shape"

echo ""
echo "NOTE: the workspace audit log (append-only, seq/timestamp/"
echo "principal/action/workspace/before/after/request_id, queried via"
echo "GET /workspaces/<name>/audit) requires the ent build. The OSS"
echo "build accepts the admin.audit block (SEC-01 shape) but records"
echo "no entries. See docs-site/guide/audit-log.md."

print_summary
