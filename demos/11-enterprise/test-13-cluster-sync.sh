#!/bin/bash
# test-13-cluster-sync.sh — cluster sync GA surface (enterprise).
#
# Cluster sync (DW-074) is the GA-hardened convergence layer for the
# CP/DP split control plane: conflict resolution, split-brain guards,
# and version-skew tolerance so a fleet of edge gateways converges on
# the correct configuration under partitions, slow members, and
# rollbacks. See docs-site/guide/cluster-sync.md and
# crates/dwara-core/src/cp_dp/cluster_sync.rs (library components
# behind the cluster_sync cargo feature).
#
#   - Conflict resolution: highest_generation (default) /
#     most_recent_timestamp / leader_wins.
#   - Split-brain guards: a controller is active if it heartbeated
#     within the lease timeout; when more than one is active, edges
#     refuse new generations and keep serving their cached one until
#     the split resolves.
#   - Version skew: allow / allow_minor_skew (default) /
#     require_exact; edges on an incompatible version reject the
#     generation (VersionSkewError) and keep serving cached config.
#   - Chaos-validated: partition, slow member, and rollback scenarios
#     must all converge for the GA gate.
#
# The OSS gateway-side config surface that IS real: the `fleet` block
# (DW-098). It carries the skew policy, the rolling-upgrade wave order
# (label-selected entries, concurrency cap, halt-on-failure), the
# controller reference version, and the stale-edge timeout. In the OSS
# build the block is accepted but INERT (no controller runs). The
# controller-side `controller:` YAML in the guide
# (conflict_resolution, lease_timeout_seconds) is the ent controller
# binary's own config surface, not this gateway schema.
#
# This test verifies the accepted-but-inert behavior:
#   1) The gateway starts with the `fleet` block in the demo config
#      (proving the block is accepted).
#   2) The gateway proxies traffic normally.
#   3) The fleet block's shape (schema naming: fleet.upgrade.order[])
#      validates via `dwara-cli validate` on a scratch config.
set -euo pipefail
source ../_shared/helpers.sh

CERTS=../_shared/certs

echo "=== test-13-cluster-sync ==="

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

# 1) The gateway started successfully with the fleet block in
#    ./dwara.yaml -- the block is accepted-but-inert in the OSS build
#    (no controller, no skew enforcement, no fleet status endpoints).
status=$(http_status http://localhost:8080/healthz)
assert_status 200 "$status" "gateway started with inert fleet block (accepted)"

# 2) The gateway proxies traffic normally (single-node behavior).
status=$(http_status http://localhost:8080/v1/echo/test)
assert_status 200 "$status" "gateway proxies to echo (no fleet in OSS)"

status=$(http_status http://localhost:8080/)
assert_status 200 "$status" "gateway proxies to static (no fleet in OSS)"

# 3) Config-shape probe: a scratch config with the fleet block
#    validates via dwara-cli. NOTE the schema naming: the rolling
#    upgrade order is fleet.upgrade.order[] entries (name + labels),
#    not the guide's controller-side `waves[].selector` shorthand.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
cat > "$SCRATCH/fleet.yaml" <<'EOF'
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
fleet:
  enabled: true
  controller_version: "1.2.0"
  stale_timeout_secs: 90
  upgrade:
    skew: allow_minor_skew
    order:
      - name: canary
        labels:
          env: canary
      - name: prod
        labels:
          env: prod
    max_concurrent: 2
    halt_on_failure: true
EOF
out=$("$CLI" validate "$SCRATCH/fleet.yaml" 2>&1) && rc=0 || rc=1
assert_status 0 "$rc" "fleet block shape validates via dwara-cli (schema naming)"
assert_contains "$out" "ok:" "validation prints ok for the fleet block shape"

# The fleet status endpoints are ent-gated admin surface; the OSS admin
# API serves its core endpoints normally.
admin_status=$(http_status https://localhost:2019/health \
  --cert "$CERTS/client.crt" \
  --key "$CERTS/client.key" \
  --cacert "$CERTS/server.crt")
assert_status 200 "$admin_status" "admin API /health reachable (fleet endpoints ent-gated)"

echo ""
echo "NOTE: cluster sync GA (conflict resolution, split-brain guards,"
echo "version skew tolerance, chaos-validated convergence) requires the"
echo "ent controller/edge binaries. The gateway-side fleet block is"
echo "accepted-but-inert in OSS. Split-brain: edges refuse new"
echo "generations and keep serving cached config until one controller"
echo "remains. Version skew: allow / allow_minor_skew / require_exact."
echo "See docs-site/guide/cluster-sync.md."

print_summary
