#!/usr/bin/env bash
# DW-024 macro load rig: boots the gateway against an in-process echo
# upstream and drives it with dwara-loadgen at several concurrency
# levels, printing a comparison table.
#
# Usage:
#   scripts/bench-macro.sh [DURATION_SECS] [CONNS...]
#   scripts/bench-macro.sh            # 10s at 10 / 100 / 1000 conns
#   scripts/bench-macro.sh 5 50 500   # 5s at 50 and 500 conns
#
# Environment:
#   BENCH_GATEWAY_PORT  default 18080
#   BENCH_ECHO_PORT     default 18081
#
# Connection-count caveat (100k-connection test):
#   This script deliberately stays at <= 10,000 connections by default —
#   it is meant for developer laptops. macOS default file-descriptor
#   limits (often 2560) cap open sockets hard. The 100k-connection test
#   runs ONLY in CI (.github/workflows/bench.yml, Linux) where the job
#   raises the limit first: `ulimit -n 1048576`. To attempt 100k on a
#   tuned Linux host: `ulimit -n 1048576 && scripts/bench-macro.sh 60 100000`
#   (two sockets per connection pair are involved client+server side; the
#   kernel also needs net.ipv4.ip_local_port_range and somaxconn headroom).
#
# Topology (all loopback, single host):
#   dwara-loadgen --echo :18081   (echo upstream + load driver)
#         |
#     dwara :18080                (gateway under test, 1 route -> upstream)
#         |
#     echo upstream :18081

set -euo pipefail

ARGS=("$@")
DURATION="${ARGS[0]:-10}"
if [ $# -ge 1 ]; then
    CONNS=("${ARGS[@]:1}")
else
    CONNS=(10 100 1000)
fi

GW_PORT="${BENCH_GATEWAY_PORT:-18080}"
ECHO_PORT="${BENCH_ECHO_PORT:-18081}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release"

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

echo "== building (release) =="
cargo build --release -p dwara-cli --bin dwara-loadgen -p dwara-bin --bin dwara >/dev/null

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dwara-bench.XXXXXX")"
trap 'kill ${GW_PID:-0} ${ECHO_PID:-0} 2>/dev/null || true; rm -rf "$WORK"' EXIT

cat >"$WORK/dwara.yaml" <<EOF
listeners:
  - name: bench
    address: 127.0.0.1
    port: ${GW_PORT}
routes:
  - name: catch-all
    service: bench-svc
    match:
      path:
        type: prefix
        value: /bench
    action:
      type: proxy
services:
  - name: bench-svc
    upstream: bench-upstream
upstreams:
  - name: bench-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: ${ECHO_PORT}
EOF

echo "== starting echo upstream + gateway =="
DWARA_LOG=error "$BIN/dwara-loadgen" --echo "$ECHO_PORT" --echo-only &
ECHO_PID=$!
DWARA_CONFIG="$WORK/dwara.yaml" DWARA_BIND="127.0.0.1:${GW_PORT}" DWARA_LOG=error "$BIN/dwara" &
GW_PID=$!
# Detach from job control so the cleanup kill does not print
# "Terminated" noise over the results table.
disown "$ECHO_PID" "$GW_PID" 2>/dev/null || true

# Wait for the gateway to be READY at the HTTP level (up to 30s): a TCP
# accept only proves the listener socket exists, not that the proxy is
# serving — probe the reserved /healthz path with curl instead. Fail fast
# with a clear message if it never comes up (a hung gateway would
# otherwise produce a results table full of connection errors).
command -v curl >/dev/null || { echo "curl required for the readiness probe" >&2; exit 2; }
READY=0
for _ in $(seq 1 150); do
    if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:${GW_PORT}/healthz" 2>/dev/null; then
        READY=1
        break
    fi
    if ! kill -0 "${GW_PID:-0}" 2>/dev/null; then
        echo "gateway process (pid ${GW_PID}) exited before becoming ready" >&2
        exit 2
    fi
    sleep 0.2
done
if [ "$READY" != "1" ]; then
    echo "gateway on 127.0.0.1:${GW_PORT} did not become HTTP-ready within 30s (/healthz probe failed); aborting" >&2
    exit 2
fi

printf '\n%-12s %10s %10s %10s %10s %10s %10s %8s\n' \
    CONNECTIONS REQUESTS RPS ERRORS 'P50(us)' 'P90(us)' 'P99(us)' 'P999(us)'
printf '%.0s-' {1..84}; echo

FAIL=0
for C in "${CONNS[@]}"; do
    OUT="$("$BIN/dwara-loadgen" \
        --url "http://127.0.0.1:${GW_PORT}/bench" \
        --connections "$C" --duration "$DURATION" --rate 0 2>/dev/null)" || FAIL=1
    ROW="$(printf '%s\n' "$OUT" | grep '^RESULT: ' | sed 's/^RESULT: //')"
    REQUESTS="$(printf '%s\n' "$OUT" | grep -o 'requests=[0-9]*' | head -1 | cut -d= -f2)"
    RPS="$(printf '%s' "$ROW" | grep -o 'rps=[0-9.]*' | cut -d= -f2)"
    ERRORS="$(printf '%s' "$ROW" | grep -o 'errors=[0-9]*' | cut -d= -f2)"
    P50="$(printf '%s' "$ROW" | grep -o 'p50_ns=[0-9]*' | cut -d= -f2)"
    P90="$(printf '%s' "$ROW" | grep -o 'p90_ns=[0-9]*' | cut -d= -f2)"
    P99="$(printf '%s' "$ROW" | grep -o 'p99_ns=[0-9]*' | cut -d= -f2)"
    P999="$(printf '%s' "$ROW" | grep -o 'p999_ns=[0-9]*' | cut -d= -f2)"
    printf '%-12s %10s %10.0f %10s %10s %10s %10s %10s\n' \
        "$C" "$REQUESTS" "$RPS" "$ERRORS" \
        "$((P50 / 1000))" "$((P90 / 1000))" "$((P99 / 1000))" "$((P999 / 1000))"
    [ "${ERRORS:-1}" = "0" ] || FAIL=1
done

echo
echo "machine-dependent numbers; absolute NFR bars are NOT asserted here (see docs)"
exit $FAIL
