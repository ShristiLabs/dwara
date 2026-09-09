#!/bin/bash
# test-10-terraform-state.sh — Terraform-compatible state export + plan (DW-065).
#
# `dwara-cli tf` brings a running gateway's config under
# Infrastructure-as-Code management WITHOUT a Terraform binary or a
# gRPC plugin: it speaks to the admin API directly and emits
# Terraform-shaped artifacts.
#
#   dwara-cli tf export --admin URL --out-state F --out-hcl F
#     GET /config from the gateway, then write a tfstate JSON (state
#     format version 4; resources[] of managed instances) and an HCL
#     .tf file. Dwara entities map to resource types:
#       listener -> dwara_listener    route   -> dwara_route
#       service  -> dwara_service     upstream-> dwara_upstream
#       consumer -> dwara_consumer
#   dwara-cli tf plan --admin URL --state F
#     diff the local tfstate against the running gateway; exit 0 if
#     no drift, 1 if a diff is present.
#   dwara-cli tf apply --admin URL --state F [--config F]
#     push the desired config via PATCH /config.
#
# TRANSPORT CAVEAT (modeled on test-03's CLI-on-host note): the tf
# tool's HTTP client is plaintext http:// ONLY — the mTLS admin is a
# documented follow-up (--ca/--client-cert/--client-key are reserved
# flags). Its primary target is the dev admin: the loopback-only
# plaintext admin enabled by DWARA_ADMIN_DEV=1. The compose gateway's
# admin binds 0.0.0.0:2019 with mTLS and dev mode refuses
# non-loopback binds, so this test runs a small HOST gateway
# (fixtures/tf-demo.yaml: listener 127.0.0.1:18080, dev admin
# 127.0.0.1:20190) and points the CLI at it.
#
# HOST BINARIES: uses target/debug/dwara and target/debug/dwara-cli;
# skips with a message if either is missing.
set -euo pipefail
source ../_shared/helpers.sh

REPO_ROOT="$(cd "$(dirname $0)/../.." && pwd)"
DWARA="$REPO_ROOT/target/debug/dwara"
DWARA_CLI="$REPO_ROOT/target/debug/dwara-cli"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$DEMO_DIR/fixtures/tf-demo.yaml"

ADMIN_URL="http://127.0.0.1:20190"
STATE="$DEMO_DIR/data/tf-demo.tfstate"
HCL="$DEMO_DIR/data/tf-demo.tf"

echo "=== test-10-terraform-state ==="

if [ ! -x "$DWARA" ] || [ ! -x "$DWARA_CLI" ]; then
  echo "SKIP: host binaries not found ($DWARA / $DWARA_CLI)."
  echo "      Build them with: cargo build -p dwara-bin -p dwara-cli"
  echo "      The tf state tool is documented in README.md and"
  echo "      docs-site/guide/terraform-state.md."
  PASS=0
  FAIL=0
  print_summary
  exit 0
fi

cleanup() {
  [ -n "${gw_pid:-}" ] && kill "$gw_pid" 2>/dev/null || true
  # PATCH /config persists the published config back to the config
  # file on disk (normalized YAML, comments dropped), and the drift
  # injection below uses PATCH — restore the pristine demo config.
  if [ -n "${config_backup:-}" ] && [ -f "$config_backup" ]; then
    cp "$config_backup" "$CONFIG"
    rm -f "$config_backup"
  fi
}
trap cleanup EXIT
config_backup=$(mktemp /tmp/dwara-tf-demo-config-XXXXXX.yaml)
cp "$CONFIG" "$config_backup"

# 1) Start the host gateway with the dev (plaintext loopback) admin.
echo "--- starting host gateway (dev admin on $ADMIN_URL) ---"
DWARA_CONFIG="$CONFIG" DWARA_ADMIN_DEV=1 "$DWARA" >/tmp/dwara-tf-demo.log 2>&1 &
gw_pid=$!

elapsed=0
until curl -sf -o /dev/null "$ADMIN_URL/health" 2>/dev/null; do
  elapsed=$((elapsed + 1))
  if [ $elapsed -ge 20 ]; then
    echo "ERROR: dev admin did not become ready; logs:"
    cat /tmp/dwara-tf-demo.log
    exit 1
  fi
  sleep 1
done
assert_status 200 "$(http_status "$ADMIN_URL/health")" \
  "dev admin /health is up (plaintext loopback, DWARA_ADMIN_DEV=1)"

# 2) Export: tfstate JSON + HCL from the RUNNING gateway's config.
echo "--- dwara-cli tf export ---"
rm -f "$STATE" "$HCL"
"$DWARA_CLI" tf export --admin "$ADMIN_URL" --out-state "$STATE" --out-hcl "$HCL"

if [ -f "$STATE" ]; then
  echo -e "${GREEN}PASS${NC}: tfstate file emitted ($STATE)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: tfstate file missing ($STATE)"
  FAIL=$((FAIL + 1))
fi
if [ -f "$HCL" ]; then
  echo -e "${GREEN}PASS${NC}: HCL file emitted ($HCL)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: HCL file missing ($HCL)"
  FAIL=$((FAIL + 1))
fi

state_json=$(cat "$STATE" 2>/dev/null || true)
assert_contains "$state_json" '"version": 4' \
  "tfstate declares state format version 4"
assert_contains "$state_json" '"dwara_route"' \
  "tfstate contains dwara_route resources"
assert_contains "$state_json" '"echo-route"' \
  "tfstate names the known route echo-route"
assert_contains "$state_json" '"dwara_upstream"' \
  "tfstate contains dwara_upstream resources"

hcl_text=$(cat "$HCL" 2>/dev/null || true)
assert_contains "$hcl_text" 'resource "dwara_route" "echo-route"' \
  "HCL declares resource \"dwara_route\" \"echo-route\""

# 3) Plan against the just-exported state: no drift -> exit 0.
echo "--- dwara-cli tf plan (no drift expected) ---"
plan_out=$("$DWARA_CLI" tf plan --admin "$ADMIN_URL" --state "$STATE" 2>&1) && plan_rc=0 || plan_rc=$?
assert_status 0 "$plan_rc" "tf plan exits 0 (no drift between state and gateway)"

# 4) Drift detection: hot-reload the gateway with a config that adds
#    a route (PATCH via the dev admin using the tf apply path is the
#    CLI's own mechanism; here we PATCH directly), then plan again
#    and expect exit 1 naming the added resource.
echo "--- injecting drift (PATCH /config with an extra route) ---"
drift_conf="$DEMO_DIR/data/tf-demo-drift.yaml"
sed 's|value: /v1/echo/|value: /v2/echo/|' "$CONFIG" >"$drift_conf"
patch_rc=$(curl -s -o /tmp/dwara-tf-patch.json -w '%{http_code}' \
  -X PATCH --data-binary @"$drift_conf" \
  -H 'Content-Type: application/yaml' \
  "$ADMIN_URL/config")
rm -f "$drift_conf"
assert_status 200 "$patch_rc" "PATCH /config accepted the drifting config (hot reload)"

plan_out=$("$DWARA_CLI" tf plan --admin "$ADMIN_URL" --state "$STATE" 2>&1) && plan_rc=0 || plan_rc=$?
assert_status 1 "$plan_rc" "tf plan exits 1 once the gateway drifted from state"
assert_contains "$plan_out" "echo-route" \
  "drift report names the changed route (echo-route)"

echo ""
echo "NOTE: 'tf apply' pushes the desired config back via PATCH /config"
echo "(optionally from --config YAML, else derived from the tfstate)."
echo "The tfstate is structurally Terraform-compatible so a future"
echo "provider or 'terraform import' could consume it. mTLS admin"
echo "support (--ca/--client-cert/--client-key) is a documented"
echo "follow-up; the dev plaintext admin is the tool's target."

print_summary
