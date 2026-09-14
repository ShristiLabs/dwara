#!/usr/bin/env bash
# Phase 2: Rate-limited sweep to find the throughput saturation knee.
#
# Boots the gateway against an in-process echo upstream and drives it
# at progressively higher target request rates. At each rate the
# loadgen paces requests to the target; when the actual RPS stops
# increasing proportionally with the target, the gateway has reached
# its saturation point (the "knee").
#
# This complements bench-macro.sh (which sweeps concurrency at
# unbounded rate) by sweeping the rate at fixed concurrency, revealing
# the RPS ceiling independent of connection count.
#
# Usage:
#   scripts/bench-rate-sweep.sh [DURATION_SECS] [CONNS] [RATES...]
#   scripts/bench-rate-sweep.sh                           # 10s, 1000 conns, 1k-100k
#   scripts/bench-rate-sweep.sh 15 500 1000 5000 10000 25000 50000 100000
#
# Environment:
#   BENCH_GATEWAY_PORT    default 18080
#   BENCH_ECHO_PORT       default 18081
#   BENCH_PROTOCOL        h1 | h2 | h3 (default h1)
#   BENCH_WORKLOAD        throughput | pool-reuse | streaming (default throughput)
#   BENCH_JSON            set to 1 to emit JSON: lines (default 0)
#   BENCH_H3_FEATURE      set to 1 to build with --features h3 (default 0)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release"

ARGS=("$@")
DURATION="${ARGS[0]:-10}"
CONNS="${ARGS[1]:-1000}"
if [ $# -ge 3 ]; then
    RATES=("${ARGS[@]:2}")
else
    RATES=(1000 5000 10000 25000 50000 100000)
fi

GW_PORT="${BENCH_GATEWAY_PORT:-18080}"
ECHO_PORT="${BENCH_ECHO_PORT:-18081}"
PROTOCOL="${BENCH_PROTOCOL:-h1}"
WORKLOAD="${BENCH_WORKLOAD:-throughput}"
JSON="${BENCH_JSON:-0}"
H3_FEATURE="${BENCH_H3_FEATURE:-0}"

command -v curl >/dev/null || { echo "curl required" >&2; exit 2; }

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------
echo "== building (release) =="
LOADGEN_ARGS=(-p dwara-cli --bin dwara-loadgen)
GATEWAY_ARGS=(-p dwara-bin --bin dwara)
if [ "$H3_FEATURE" = "1" ]; then
    LOADGEN_ARGS+=(--features h3)
    GATEWAY_ARGS+=(--features h3)
fi
cargo build --release "${LOADGEN_ARGS[@]}" >/dev/null
cargo build --release "${GATEWAY_ARGS[@]}" >/dev/null

# -------------------------------------------------------------------
# Start echo upstream + gateway
# -------------------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dwara-rate-sweep.XXXXXX")"
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
disown "$ECHO_PID" "$GW_PID" 2>/dev/null || true

# Readiness probe
READY=0
for _ in $(seq 1 150); do
    if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:${GW_PORT}/healthz" 2>/dev/null; then
        READY=1
        break
    fi
    if ! kill -0 "${GW_PID:-0}" 2>/dev/null; then
        echo "gateway process exited before becoming ready" >&2
        exit 2
    fi
    sleep 0.2
done
[ "$READY" = "1" ] || { echo "gateway did not become ready within 30s" >&2; exit 2; }

# -------------------------------------------------------------------
# Header
# -------------------------------------------------------------------
if [ "$JSON" = "0" ]; then
    printf '\n%-14s %14s %14s %10s %10s %10s %10s %10s\n' \
        TARGET_RPS ACTUAL_RPS REQUESTS ERRORS 'P50(us)' 'P99(us)' 'P999(us)' 'UTIL_%'
    printf '%.0s-' {1..100}; echo
fi

FAIL=0
PREV_RPS=0
for RATE in "${RATES[@]}"; do
    LOADGEN_RUN=("$BIN/dwara-loadgen" \
        --url "http://127.0.0.1:${GW_PORT}/bench" \
        --protocol "$PROTOCOL" --workload "$WORKLOAD" \
        --connections "$CONNS" --duration "$DURATION" --rate "$RATE")
    if [ "$WORKLOAD" = "streaming" ]; then
        LOADGEN_RUN+=(--stream-chunks 8 --stream-chunk-bytes 1024)
    fi
    if [ "$JSON" = "1" ]; then
        LOADGEN_RUN+=(--json)
    fi

    OUT="$("${LOADGEN_RUN[@]}" 2>/dev/null)" || FAIL=1
    ROW="$(printf '%s\n' "$OUT" | grep '^RESULT: ' | sed 's/^RESULT: //')"
    REQUESTS="$(printf '%s\n' "$OUT" | grep -o 'requests=[0-9]*' | head -1 | cut -d= -f2)"
    RPS="$(printf '%s' "$ROW" | grep -o ' rps=[0-9.]*' | cut -d= -f2)"
    ERRORS="$(printf '%s' "$ROW" | grep -o ' errors=[0-9]*' | cut -d= -f2)"
    P50="$(printf '%s' "$ROW" | grep -o ' p50_ns=[0-9]*' | cut -d= -f2)"
    P99="$(printf '%s' "$ROW" | grep -o ' p99_ns=[0-9]*' | cut -d= -f2)"
    P999="$(printf '%s' "$ROW" | grep -o ' p999_ns=[0-9]*' | cut -d= -f2)"

    # Utilization: actual RPS / target RPS * 100 (>100% means the
    # gateway exceeded the pace; <100% means it could not keep up)
    UTIL="$(python3 -c "
r = float('${RPS:-0}')
t = float('$RATE')
print(f'{min(r / t * 100, 999.9):.1f}' if t > 0 else '100.0')
")"

    # Detect the knee: first rate where actual RPS stops growing
    # proportionally (utilization drops below 95%)
    KNEE=""
    if [ "$PREV_RPS" != "0" ]; then
        GROWTH="$(python3 -c "
prev = float('$PREV_RPS')
curr = float('${RPS:-0}')
print(f'{((curr - prev) / prev * 100):.1f}' if prev > 0 else '0.0')
")"
        if [ "$(python3 -c "print(1 if float('$UTIL') < 95.0 else 0)")" = "1" ]; then
            KNEE=" <-- saturation knee (util < 95%)"
        fi
    fi
    PREV_RPS="${RPS:-0}"

    if [ "$JSON" = "1" ]; then
        printf '%s\n' "$OUT" | grep '^JSON: '
    else
        printf '%-14s %14.0f %14s %10s %10s %10s %10s %10s%s\n' \
            "$RATE" "$RPS" "$REQUESTS" "$ERRORS" \
            "$((P50 / 1000))" "$((P99 / 1000))" "$((P999 / 1000))" \
            "$UTIL" "$KNEE"
    fi

    [ "${ERRORS:-1}" = "0" ] || FAIL=1
done

echo
echo "saturation knee: the target rate where actual RPS stops scaling proportionally" >&2
echo "machine-dependent numbers; not asserted here (see docs)" >&2
exit $FAIL
