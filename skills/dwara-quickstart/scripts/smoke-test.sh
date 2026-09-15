#!/usr/bin/env bash
# Smoke-test a freshly started Dwara gateway (defaults match
# assets/minimal-dwara.yaml). No dependencies beyond curl.
#
# Usage:
#   DWARA_URL=http://127.0.0.1:8080 ./smoke-test.sh
set -uo pipefail

BASE="${DWARA_URL:-http://127.0.0.1:8080}"
EXPECT="${DWARA_EXPECT:-hello from dwara}"
fail=0

check() {
  local name="$1" cmd="$2" want="$3" got
  got="$(eval "$cmd" 2>/dev/null)" || true
  if [[ "$got" == *"$want"* ]]; then
    echo "PASS  $name"
  else
    echo "FAIL  $name  (wanted '$want', got: '${got:0:120}')"
    fail=1
  fi
}

# Wait up to ~15s for the listener to accept connections.
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "$BASE/healthz" 2>/dev/null && break
  sleep 0.5
done

check "healthz responds 200 ok" "curl -fsS $BASE/healthz" "ok"
check "root route served by gateway" "curl -fsS $BASE" "$EXPECT"
check "metrics endpoint is Prometheus text" "curl -fsS $BASE/metrics | head -c 200" "#"

if (( fail )); then
  echo "SMOKE TEST FAILED - see FAIL lines above."
  exit 1
fi
echo "Gateway is up and serving."
