#!/usr/bin/env bash
# Phase 2: Enhanced macro concurrency sweep with system metrics.
#
# Boots the gateway against an in-process echo upstream and drives it
# with dwara-loadgen at multiple concurrency levels. For each level it
# captures system metrics (RSS, fd count, CPU) and scrapes the gateway
# /metrics endpoint, producing a richer result than scripts/bench-macro.sh.
#
# This script extends bench-macro.sh (DW-024) with:
#   * Per-run system metrics (RSS, fd count, CPU%)
#   * Gateway /metrics scrape (active_requests, requests_total, etc.)
#   * Best-of-N methodology (run each level N times, keep best RPS)
#   * JSON output with system metrics for machine analysis
#
# Usage:
#   scripts/bench-macro-sweep.sh [DURATION_SECS] [CONNS...]
#   scripts/bench-macro-sweep.sh                      # 10s at 10/100/1000
#   scripts/bench-macro-sweep.sh 30 1 10 100 1000 10000
#   BENCH_BEST_OF=3 scripts/bench-macro-sweep.sh 10 100 1000
#
# Environment:
#   BENCH_GATEWAY_PORT    default 18080
#   BENCH_ECHO_PORT       default 18081
#   BENCH_PROTOCOL        h1 | h2 | h3 (default h1; h3 needs BENCH_H3_FEATURE=1)
#   BENCH_WORKLOAD        throughput | pool-reuse | streaming (default throughput)
#   BENCH_BEST_OF         run each level N times, keep best RPS (default 1)
#   BENCH_JSON            set to 1 to emit JSON: lines (default 0)
#   BENCH_H3_FEATURE      set to 1 to build with --features h3 (default 0)
#   BENCH_SYSMETRICS      set to 1 to capture system metrics (default 1)
#   BENCH_METRICS_URL     gateway /metrics URL (default http://127.0.0.1:<port>/metrics)
#   BENCH_CONNECTION_CAP  upstream connection_cap (default 1024; the
#                        config default of 64 causes unbounded memory
#                        growth when client connections exceed the cap)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release"
source "$ROOT/scripts/bench-sysmetrics.sh"

ARGS=("$@")
DURATION="${ARGS[0]:-10}"
if [ $# -ge 1 ]; then
    CONNS=("${ARGS[@]:1}")
else
    CONNS=(10 100 1000)
fi

GW_PORT="${BENCH_GATEWAY_PORT:-18080}"
ECHO_PORT="${BENCH_ECHO_PORT:-18081}"
PROTOCOL="${BENCH_PROTOCOL:-h1}"
WORKLOAD="${BENCH_WORKLOAD:-throughput}"
BEST_OF="${BENCH_BEST_OF:-1}"
JSON="${BENCH_JSON:-0}"
H3_FEATURE="${BENCH_H3_FEATURE:-0}"
DO_SYSMETRICS="${BENCH_SYSMETRICS:-1}"
METRICS_URL="${BENCH_METRICS_URL:-http://127.0.0.1:${GW_PORT}/metrics}"

command -v curl >/dev/null || { echo "curl required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

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
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dwara-bench-sweep.XXXXXX")"
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
    connection_cap: ${BENCH_CONNECTION_CAP:-1024}
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

# Capture baseline system metrics
if [ "$DO_SYSMETRICS" = "1" ]; then
    BASELINE_RSS="$(sample_rss_kb "$GW_PID")"
    echo "  gateway baseline RSS: ${BASELINE_RSS:-0} KB" >&2
fi

# -------------------------------------------------------------------
# Header
# -------------------------------------------------------------------
if [ "$JSON" = "0" ]; then
    printf '\n%-12s %10s %10s %10s %10s %10s %10s %8s %10s %10s %10s\n' \
        CONNECTIONS REQUESTS RPS ERRORS 'P50(us)' 'P90(us)' 'P99(us)' 'P999(us)' 'RSS(KB)' 'FD_COUNT' 'CPU_%'
    printf '%.0s-' {1..120}; echo
fi

FAIL=0
for C in "${CONNS[@]}"; do
    BEST_RPS=0
    BEST_ROW=""
    BEST_OUT=""
    BEST_RSS=""
    BEST_FDS=""
    BEST_CPU=""

    for attempt in $(seq 1 "$BEST_OF"); do
        # Pre-run metrics scrape
        if [ "$DO_SYSMETRICS" = "1" ]; then
            scrape_metrics "$METRICS_URL" >/dev/null 2>&1 || true
        fi

        LOADGEN_RUN=("$BIN/dwara-loadgen" \
            --url "http://127.0.0.1:${GW_PORT}/bench" \
            --protocol "$PROTOCOL" --workload "$WORKLOAD" \
            --connections "$C" --duration "$DURATION" --rate 0)
        if [ "$WORKLOAD" = "streaming" ]; then
            LOADGEN_RUN+=(--stream-chunks 8 --stream-chunk-bytes 1024)
        fi
        if [ "$JSON" = "1" ]; then
            LOADGEN_RUN+=(--json)
        fi

        OUT="$("${LOADGEN_RUN[@]}" 2>/dev/null)" || FAIL=1
        ROW="$(printf '%s\n' "$OUT" | grep '^RESULT: ' | sed 's/^RESULT: //')"
        RPS="$(printf '%s' "$ROW" | grep -o ' rps=[0-9.]*' | cut -d= -f2)"

        # Track best run by RPS
        if [ "$(python3 -c "print(1 if float('$RPS') > float('$BEST_RPS') else 0)")" = "1" ]; then
            BEST_RPS="$RPS"
            BEST_ROW="$ROW"
            BEST_OUT="$OUT"
            if [ "$DO_SYSMETRICS" = "1" ]; then
                BEST_RSS="$(sample_rss_kb "$GW_PID")"
                BEST_FDS="$(sample_fd_count "$GW_PID")"
                BEST_CPU="$(sample_cpu_pct "$GW_PID")"
            fi
        fi
    done

    # Extract fields from best run
    REQUESTS="$(printf '%s\n' "$BEST_OUT" | grep -o 'requests=[0-9]*' | head -1 | cut -d= -f2)"
    ERRORS="$(printf '%s' "$BEST_ROW" | grep -o ' errors=[0-9]*' | cut -d= -f2)"
    P50="$(printf '%s' "$BEST_ROW" | grep -o ' p50_ns=[0-9]*' | cut -d= -f2)"
    P90="$(printf '%s' "$BEST_ROW" | grep -o ' p90_ns=[0-9]*' | cut -d= -f2)"
    P99="$(printf '%s' "$BEST_ROW" | grep -o ' p99_ns=[0-9]*' | cut -d= -f2)"
    P999="$(printf '%s' "$BEST_ROW" | grep -o ' p999_ns=[0-9]*' | cut -d= -f2)"

    BEST_RSS="${BEST_RSS:-0}"
    BEST_FDS="${BEST_FDS:-0}"
    BEST_CPU="${BEST_CPU:-0.0}"

    if [ "$JSON" = "1" ]; then
        # Emit JSON line with system metrics
        python3 -c "
import json, sys
d = {
    'protocol': '$PROTOCOL',
    'workload': '$WORKLOAD',
    'connections': $C,
    'duration_s': $DURATION,
    'rate': 0,
    'requests': ${REQUESTS:-0},
    'errors': ${ERRORS:-0},
    'rps': float(${BEST_RPS:-0}),
    'p50_ns': int(${P50:-0}),
    'p90_ns': int(${P90:-0}),
    'p99_ns': int(${P99:-0}),
    'p999_ns': int(${P999:-0}),
    'sysmetrics': {
        'rss_kb': int(${BEST_RSS:-0}),
        'fd_count': int(${BEST_FDS:-0}),
        'cpu_pct': float(${BEST_CPU:-0}),
    },
}
print('JSON: ' + json.dumps(d))
"
    else
        printf '%-12s %10s %10.0f %10s %10s %10s %10s %10s %10s %10s %10s\n' \
            "$C" "$REQUESTS" "$BEST_RPS" "$ERRORS" \
            "$((P50 / 1000))" "$((P90 / 1000))" "$((P99 / 1000))" "$((P999 / 1000))" \
            "$BEST_RSS" "$BEST_FDS" "$BEST_CPU"
    fi

    [ "${ERRORS:-1}" = "0" ] || FAIL=1
done

echo
echo "machine-dependent numbers; absolute NFR bars are NOT asserted here (see docs)" >&2

# Final metrics scrape
if [ "$DO_SYSMETRICS" = "1" ]; then
    FINAL_RSS="$(sample_rss_kb "$GW_PID")"
    echo "  gateway final RSS: ${FINAL_RSS:-0} KB (delta: $(( ${FINAL_RSS:-0} - ${BASELINE_RSS:-0} )) KB)" >&2
fi

exit $FAIL
