#!/bin/bash
# test-08-api-lifecycle.sh — API lifecycle management (DW-110).
# Config-shape test + current-status documentation. PARTIAL.
#
# dwara.yaml carries a top-level `lifecycle` block:
#   portal:   enabled, path /portal, specs: [{file: openapi.yaml}]
#   profiles: base_config + dev/prod profile_overrides (YAML strings)
#   journey:  enabled, retention_hours 24
#
# WHAT IS WIRED TODAY (documented limitation, see README): the block is
# accepted by the configuration schema and the gateway BOOTS with it
# (startup validation passed — asserted below via the health route).
# The runtime consumers are library components not yet dispatched from
# the server binary: the portal renderer is not served at its reserved
# path, the profile overlay (DWARA_PROFILE) is not applied at config
# load, and the journey recorder is not fed by the request path.
#
# This test asserts the config-shape half live (gateway up with the
# block) and records the unwired half as evidence (/portal is not
# served). If dwara-cli is available it also re-validates the config on
# the host.
set -u
. "$(dirname "$0")/../_shared/helpers.sh"

echo "=== test-08: API lifecycle ==="

wait_for http://localhost:8080/healthz 30 || exit 1

echo "--- gateway booted with the lifecycle block ---"
status=$(http_status "http://localhost:8080/healthz")
assert_status 200 "$status" \
  "gateway is serving (startup validation accepted the lifecycle block)"

# ---------------------------------------------------------------------------
# Host-side validation of the exact config the gateway booted with
# (optional: skipped with a note when dwara-cli is absent).
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/../../target/debug/dwara-cli"
if [ -x "$CLI" ]; then
  echo "--- dwara-cli validate dwara.yaml (host) ---"
  validate_out=$(cd "$SCRIPT_DIR" && "$CLI" validate dwara.yaml 2>&1)
  echo "$validate_out" | sed 's/^/  /'
  if echo "$validate_out" | grep -q "ok: 8 routes"; then
    echo -e "${GREEN}PASS${NC}: dwara-cli validate prints 'ok: 8 routes' (lifecycle block included)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: dwara-cli validate did not print 'ok: 8 routes'"
    FAIL=$((FAIL + 1))
  fi
else
  echo "NOTE: dwara-cli not found at $CLI; the running gateway above already"
  echo "      proves the config (lifecycle block included) validates."
fi

# ---------------------------------------------------------------------------
# Evidence of the unwired runtime: the portal path is configured but
# not served (the renderer is a library component today).
# ---------------------------------------------------------------------------
echo "--- GET /portal (portal.enabled: true, path: /portal) ---"
status=$(http_status "http://localhost:8080/portal")
echo "  status=$status"

assert_status 404 "$status" \
  "portal path is configured but NOT served (renderer not dispatched — documented limitation)"

echo ""
echo "NOTE: the lifecycle block (portal / profiles / journey) validates and"
echo "      boots, but its runtime consumers are library components today:"
echo "      no portal HTML at /portal, no DWARA_PROFILE overlay at load, no"
echo "      journey recording. See README.md (Documented limitations)."

print_summary
