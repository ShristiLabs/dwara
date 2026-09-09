#!/bin/bash
# test-07-replay-debugging.sh — replay time-travel debugging (DW-102).
#
# Replay debugging answers "why did this request go there?" offline:
# run the gateway's decision path (routing, authz, rate limits,
# transforms, upstream pick) for RECORDED requests against a
# CANDIDATE config and diff it against the BASELINE config the
# requests were captured under — no live traffic, no upstreams
# touched. Exit 0 = no decision differences, 1 = diffs found
# (usable as a CI gate before shipping a config change), 2 = load
# error.
#
# The CLI flow is `dwara-cli replay --recording <recording.json>
# --config <candidate.yaml>`. A recording is a JSON document
# {baseline_config: "<YAML string>", requests: [{method, path,
# headers, auth_identity, timestamp_ms}]} — exported from the
# analytics store or authored from captured traffic, which is what
# this test does:
#
#   1) Send a few requests through the LIVE gateway (the compose
#      stack) and record their method+path — the capture.
#   2) Build the recording file with the demo config as the
#      baseline_config (the config the requests were served under).
#   3) Replay against the IDENTICAL config: exit 0, "no decision
#      differences".
#   4) Replay against a DIVERGING candidate (the echo-route prefix
#      moved): exit 1 with a per-request diff naming the path and
#      the changed stage (route).
#
# NOTE: the replay CLI compiles both configs, and the demo config's
# ${DEMO_SECRET} reference resolves from the environment at compile
# time — so DEMO_SECRET is exported here exactly as the compose file
# sets it for the container.
#
# HOST BINARY: dwara-cli is NOT in the scratch image; this test uses
# the prebuilt host CLI (target/debug/dwara-cli) and skips with a
# message if it is missing.
set -euo pipefail
source ../_shared/helpers.sh

REPO_ROOT="$(cd "$(dirname $0)/../.." && pwd)"
DWARA_CLI="$REPO_ROOT/target/debug/dwara-cli"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== test-07-replay-debugging ==="

if [ ! -x "$DWARA_CLI" ]; then
  echo "SKIP: host dwara-cli not found at $DWARA_CLI."
  echo "      Build it with: cargo build -p dwara-cli"
  echo "      The replay flow is documented in README.md and"
  echo "      docs-site/guide/replay-debugging.md."
  PASS=0
  FAIL=0
  print_summary
  exit 0
fi

# Wait for the gateway to be ready.
wait_for http://localhost:8080/healthz 30 || exit 1

workdir=$(mktemp -d /tmp/dwara-replay-XXXXXX)
trap 'rm -rf "$workdir"' EXIT

# 1) Capture: send a few requests through the live gateway and
#    record their method + path. These are the decisions we will
#    replay offline.
echo "--- capturing live traffic (routing decisions) ---"
paths=(
  "/v1/echo/replay-1"
  "/v1/echo/replay-2"
  "/healthz"
)
for p in "${paths[@]}"; do
  status=$(http_status "http://localhost:8080$p")
  assert_status 200 "$status" "captured request $p served 200 by the live gateway"
done

# 2) Build the recording: baseline_config = the demo config the
#    requests were served under; requests = the captured traffic.
#    python3 builds the JSON (the YAML is embedded as a JSON string).
echo "--- building the recording file ---"
recording="$workdir/recording.json"
DEMO_CONFIG="$DEMO_DIR/dwara.yaml" \
PATHS="${paths[*]}" \
python3 - "$recording" <<'PYEOF'
import json, os, sys, time

with open(os.environ["DEMO_CONFIG"]) as f:
    baseline = f.read()
now_ms = int(time.time() * 1000)
requests = [
    {"method": "GET", "path": p, "headers": [], "timestamp_ms": now_ms + i}
    for i, p in enumerate(os.environ["PATHS"].split())
]
recording = {"baseline_config": baseline, "requests": requests}
with open(sys.argv[1], "w") as f:
    json.dump(recording, f)
print(f"recording: {len(requests)} requests, baseline = demo dwara.yaml")
PYEOF
assert_contains "$(cat "$recording" | head -c 200)" "baseline_config" \
  "recording file is JSON with a baseline_config"

# 3) Replay against the IDENTICAL config: every recorded request
#    must decide the same way -> exit 0, "no decision differences".
echo "--- replay against the identical config (expect no diffs) ---"
cp "$DEMO_DIR/dwara.yaml" "$workdir/candidate-identical.yaml"
identical_out=$(DEMO_SECRET=ops-secret-key-123 "$DWARA_CLI" replay \
  --recording "$recording" \
  --config "$workdir/candidate-identical.yaml" 2>&1) && identical_rc=0 || identical_rc=$?
assert_status 0 "$identical_rc" \
  "replay vs identical config exits 0 (CI-gate clean)"
assert_contains "$identical_out" "no decision differences" \
  "replay vs identical config reports 'no decision differences'"

# 4) Replay against a DIVERGING candidate: move the echo-route
#    prefix from /v1/echo/ to /v1/echoalt/. The captured /v1/echo/*
#    requests now match no route -> their route decision changed ->
#    exit 1 with a per-request diff naming the path and the stage.
echo "--- replay against a diverging candidate (expect diffs) ---"
sed 's|value: /v1/echo/|value: /v1/echoalt/|' \
  "$DEMO_DIR/dwara.yaml" > "$workdir/candidate-diverging.yaml"
diverging_out=$(DEMO_SECRET=ops-secret-key-123 "$DWARA_CLI" replay \
  --recording "$recording" \
  --config "$workdir/candidate-diverging.yaml" 2>&1) && diverging_rc=0 || diverging_rc=$?
assert_status 1 "$diverging_rc" \
  "replay vs diverging config exits 1 (diffs found)"
assert_contains "$diverging_out" "/v1/echo/replay-1" \
  "diff report names the diverging request path"
assert_contains "$diverging_out" "route" \
  "diff report names the changed decision stage (route)"
echo "--- diverging replay report ---"
echo "$diverging_out" | sed 's/^/    /'

echo ""
echo "NOTE: replay is read-only (no upstreams are contacted) and runs"
echo "entirely offline; capture comes from the analytics store"
echo "(--from/--to --analytics-db --baseline) or a hand/exported"
echo "recording JSON as used here. The exit-code contract (0 clean /"
echo "1 diffs) makes it a CI gate for config changes."

print_summary
