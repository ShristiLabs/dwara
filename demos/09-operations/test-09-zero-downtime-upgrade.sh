#!/bin/bash
# test-09-zero-downtime-upgrade.sh — SO_REUSEPORT binary hand-off (DW-049).
#
# HOST-BASED DEMO (no compose): the zero-downtime upgrade swaps the
# gateway BINARY under load via two OS processes binding the SAME
# port, which cannot be demonstrated inside one container. It uses
# the prebuilt host gateway (target/debug/dwara) and host CLI
# (target/debug/dwara-cli); both skip-with-message if missing.
#
# The mechanism (crates/dwara-bin/src/upgrade.rs):
#   1) Every listening socket is bound with SO_REUSEPORT (plus
#      SO_REUSEADDR), so a second process can bind the same port
#      while the first still listens (Linux load-balances accepts
#      across both sockets; on macOS both may accept — the hand-off
#      still works).
#   2) On SIGUSR2 the OLD process spawns a NEW copy of the binary
#      (DWARA_UPGRADE_BINARY or current_exe) with the environment
#      inherited (same DWARA_CONFIG, same listeners).
#   3) The NEW process binds its listeners, spawns accept tasks,
#      then signals READY to the old process over a Unix domain
#      socket (/tmp/dwara-upgrade-<oldpid>.sock).
#   4) The OLD process receives READY, runs the SIGTERM drain
#      sequence, and exits 0. The new process is already accepting,
#      so no connection is refused and none is reset.
#   5) If the new process fails to signal READY within
#      DWARA_UPGRADE_READY_TIMEOUT_SECS (default 30s), the old
#      process logs an error and KEEPS RUNNING — a failed upgrade
#      never takes the gateway down.
#
# This test:
#   1) Starts instance A on 127.0.0.1:18099 with DWARA_PID_FILE set
#      (config: fixtures/upgrade-demo.yaml — a direct-respond /healthz
#      route so the load loop needs no upstream).
#   2) Hammers /healthz in a background loop, counting failures.
#   3) Triggers the upgrade (dwara-cli upgrade --pid-file, i.e.
#      SIGUSR2).
#   4) Verifies the hand-off log trail (upgrade_initiated ->
#      upgrade_child_spawned -> upgrade_ready), that the OLD pid
#      exited, that a NEW pid now owns the port, and that the load
#      loop saw ZERO failed requests.
set -euo pipefail
source ../_shared/helpers.sh

REPO_ROOT="$(cd "$(dirname $0)/../.." && pwd)"
DWARA="$REPO_ROOT/target/debug/dwara"
DWARA_CLI="$REPO_ROOT/target/debug/dwara-cli"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$DEMO_DIR/fixtures/upgrade-demo.yaml"

PORT=18099
BASE_URL="http://127.0.0.1:$PORT/healthz"

echo "=== test-09-zero-downtime-upgrade ==="

if [ ! -x "$DWARA" ]; then
  echo "SKIP: host gateway binary not found at $DWARA."
  echo "      Build it with: cargo build -p dwara-bin"
  echo "      The upgrade mechanism is documented in README.md and"
  echo "      docs-site/guide/zero-downtime-upgrade.md."
  PASS=0
  FAIL=0
  print_summary
  exit 0
fi

pid_file=$(mktemp -u /tmp/dwara-upgrade-demo-XXXXXX.pid)
log_a=$(mktemp /tmp/dwara-upgrade-demo-XXXXXX.log)
cleanup() {
  [ -n "${load_pid:-}" ] && kill "$load_pid" 2>/dev/null || true
  [ -n "${old_pid:-}" ] && kill "$old_pid" 2>/dev/null || true
  # The upgrade child runs in its own process group; kill any
  # listener still holding the demo port.
  lsof -ti tcp:$PORT 2>/dev/null | xargs kill 2>/dev/null || true
  rm -f "$pid_file" "$log_a" /tmp/dwara-upgrade-*.sock 2>/dev/null || true
}
trap cleanup EXIT

# 1) Start instance A: PID file + config via env, logs to a file the
#    upgrade child will INHERIT (spawn_upgrade_child keeps the old
#    process's stdio), so both generations write one hand-off trail.
echo "--- starting instance A on 127.0.0.1:$PORT ---"
DWARA_CONFIG="$CONFIG" DWARA_PID_FILE="$pid_file" \
  "$DWARA" >"$log_a" 2>&1 &
old_pid=$!

elapsed=0
until curl -sf -o /dev/null "$BASE_URL" 2>/dev/null; do
  elapsed=$((elapsed + 1))
  if [ $elapsed -ge 20 ]; then
    echo "ERROR: instance A did not become ready; logs:"
    cat "$log_a"
    exit 1
  fi
  sleep 1
done
assert_status 200 "$(http_status "$BASE_URL")" "instance A serves /healthz before the upgrade"

[ "$(cat "$pid_file")" = "$old_pid" ] && a_pid_ok=yes || a_pid_ok=no
if [ "$a_pid_ok" = "yes" ]; then
  echo -e "${GREEN}PASS${NC}: DWARA_PID_FILE contains instance A's PID ($old_pid)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: PID file has '$(cat "$pid_file" 2>/dev/null)', expected $old_pid"
  FAIL=$((FAIL + 1))
fi

# 2) Background load loop: hammer /healthz until stopped, counting
#    every non-200 (or curl failure) as a failed request.
counter=$(mktemp /tmp/dwara-upgrade-count-XXXXXX)
: >"$counter"
(
  while :; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE_URL" 2>/dev/null || echo 000)
    if [ "$code" != "200" ]; then
      echo "fail code=$code" >>"$counter"
    fi
  done
) &
load_pid=$!

# 3) Trigger the upgrade while the load runs. Use the CLI when
#    available (it only delivers SIGUSR2; the hand-off is async),
#    else kill -USR2 directly.
sleep 1
if [ -x "$DWARA_CLI" ]; then
  echo "--- dwara-cli upgrade --pid-file (sends SIGUSR2 to $old_pid) ---"
  "$DWARA_CLI" upgrade --pid-file "$pid_file"
else
  echo "--- kill -USR2 $old_pid (dwara-cli not found) ---"
  kill -USR2 "$old_pid"
fi

# 4) The OLD process must drain and exit 0 once the child signals
#    READY (bounded by DWARA_UPGRADE_READY_TIMEOUT_SECS, default 30).
echo "--- waiting for the old process to drain and exit ---"
exited=no
elapsed=0
while [ $elapsed -lt 40 ]; do
  if ! kill -0 "$old_pid" 2>/dev/null; then
    exited=yes
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
# Give the port a moment to settle fully on the new process.
sleep 2
kill "$load_pid" 2>/dev/null || true
load_pid=""

if [ "$exited" = "yes" ]; then
  echo -e "${GREEN}PASS${NC}: old process exited after the hand-off"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: old process $old_pid still running 40s after SIGUSR2 (upgrade failed; it keeps serving by design)"
  FAIL=$((FAIL + 1))
fi

# The hand-off log trail (both generations share the inherited
# stderr, so one file holds the sequence). Grep the FILE directly —
# the load loop makes it large, and piping it through assert_contains
# trips a benign broken pipe (grep -q exits on first match).
for marker in upgrade_initiated upgrade_child_spawned upgrade_ready; do
  if grep -q "\"$marker\"" "$log_a" 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}: log trail contains $marker"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC}: log trail is missing $marker"
    FAIL=$((FAIL + 1))
  fi
done

# The PID file now carries the NEW process's PID (the child
# overwrites it after signaling READY).
new_pid=$(cat "$pid_file" 2>/dev/null || echo "")
if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] && kill -0 "$new_pid" 2>/dev/null; then
  echo -e "${GREEN}PASS${NC}: PID file now names the new process ($new_pid != $old_pid) and it is alive"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: PID file has '$new_pid' (expected the new child's pid, alive)"
  FAIL=$((FAIL + 1))
fi

# The new generation serves the same listener.
assert_status 200 "$(http_status "$BASE_URL")" \
  "the new process serves /healthz on the same port after the hand-off"

# 5) Zero failed requests across the entire window.
failures=$(wc -l <"$counter" | tr -d ' ')
rm -f "$counter"
if [ "$failures" = "0" ]; then
  echo -e "${GREEN}PASS${NC}: zero failed requests across the binary swap"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC}: $failures failed request(s) during the upgrade:"
  head -5 "$counter" 2>/dev/null || true
  FAIL=$((FAIL + 1))
fi

echo ""
echo "NOTE: the listener bind set is fixed at startup — an upgrade"
echo "inherits the same listeners; changing binds still requires a"
echo "full restart. systemd operators: set Restart=on-failure so the"
echo "old process's clean exit 0 is not double-started."

print_summary
