#!/usr/bin/env bash
# PERF-06 (#171) macro regression harness.
#
# Boots the real gateway (dwara) against an in-process echo upstream
# (dwara-loadgen --echo-only) and drives the full client -> gateway ->
# upstream -> gateway -> client path with dwara-loadgen --json across
# the H1/H2 protocols and the throughput/pool-reuse/streaming workloads.
# H3 is opt-in (DWARA_BENCH_H3_URL) because h3 is feature-gated and
# needs a TLS/QUIC listener the plain rig does not provision.
#
# Each workload emits one machine-parseable `JSON:` line on stdout; the
# human table goes to stderr so stdout stays a clean stream for
# scripts/bench-regression.py.
#
# Usage:
#   scripts/bench-regression.sh | scripts/bench-regression.py \
#       --baseline scripts/bench-macro-baseline.json
#
# Environment:
#   BENCH_DURATION        per-workload seconds        (default 5)
#   BENCH_CONNECTIONS     concurrent connections      (default 10)
#   BENCH_GATEWAY_PORT    gateway port                (default 18090)
#   BENCH_ECHO_PORT       echo upstream port          (default 18091)
#   BENCH_H3_FEATURE      build loadgen with --features h3 (default 0)
#   DWARA_BENCH_H3_URL    h3 target URL; enables h3 runs (default unset)
#   BENCH_SKIP_H2         set to 1 to skip h2 workloads (default unset)

set -euo pipefail

DURATION="${BENCH_DURATION:-5}"
CONNS="${BENCH_CONNECTIONS:-10}"
GW_PORT="${BENCH_GATEWAY_PORT:-18090}"
ECHO_PORT="${BENCH_ECHO_PORT:-18091}"
H3_FEATURE="${BENCH_H3_FEATURE:-0}"
H3_URL="${DWARA_BENCH_H3_URL:-}"
SKIP_H2="${BENCH_SKIP_H2:-0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release"

command -v curl >/dev/null || { echo "curl required for the readiness probe" >&2; exit 2; }

# Build the loadgen (+ h3 feature only when requested) and the gateway.
LOADGEN_ARGS=(-p dwara-cli --bin dwara-loadgen)
if [ "$H3_FEATURE" = "1" ]; then
    LOADGEN_ARGS+=(--features h3)
fi
echo "== building (release) ==" >&2
cargo build --release "${LOADGEN_ARGS[@]}" -p dwara-bin --bin dwara >/dev/null

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dwara-bench-reg.XXXXXX")"
cleanup() {
    # Kill child processes reliably; ignore failures from already-exited PIDs.
    kill "${GW_PID:-0}" "${ECHO_PID:-0}" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# One route -> the echo upstream. The cleartext listener speaks both
# HTTP/1.1 and h2c (prior knowledge), so the same gateway serves the h1
# and h2 workloads without reconfiguration.
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

echo "== starting echo upstream + gateway ==" >&2
DWARA_LOG=error "$BIN/dwara-loadgen" --echo "$ECHO_PORT" --echo-only &
ECHO_PID=$!
DWARA_CONFIG="$WORK/dwara.yaml" DWARA_BIND="127.0.0.1:${GW_PORT}" DWARA_LOG=error "$BIN/dwara" &
GW_PID=$!
disown "$ECHO_PID" "$GW_PID" 2>/dev/null || true

# Readiness probe (up to 30s): /healthz proves the proxy is serving, not
# just that the listener socket exists. Fail fast if the gateway dies.
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
    echo "gateway on 127.0.0.1:${GW_PORT} did not become HTTP-ready within 30s; aborting" >&2
    exit 2
fi

# Run one workload and emit its JSON: line on stdout. The human table row
# goes to stderr. Returns nonzero if the loadgen run itself failed.
run_workload() {
    local proto="$1" workload="$2" url="$3" extra=()
    case "$workload" in
        streaming) extra=(--workload streaming --stream-chunks 8 --stream-chunk-bytes 1024);;
        *)         extra=(--workload "$workload");;
    esac
    local out
    out="$("$BIN/dwara-loadgen" \
        --url "$url" --protocol "$proto" "${extra[@]}" \
        --connections "$CONNS" --duration "$DURATION" --rate 0 \
        --timeout-ms 10000 --json 2>/dev/null)" || {
        echo "loadgen run failed for $proto/$workload" >&2
        return 1
    }
    # Forward the JSON: line to stdout (the regression gate consumes it).
    printf '%s\n' "$out" | grep '^JSON: '
    # Human row to stderr. Anchor field greps with a leading space so
    # `p99_ns=` does not also match `err_p99_ns=` in the RESULT line.
    local row requests rps errors p99
    row="$(printf '%s\n' "$out" | grep '^RESULT: ' | sed 's/^RESULT: //')"
    requests="$(printf '%s\n' "$out" | grep -o 'requests=[0-9]*' | head -1 | cut -d= -f2)"
    rps="$(printf '%s' "$row" | grep -o ' rps=[0-9.]*' | cut -d= -f2)"
    errors="$(printf '%s' "$row" | grep -o ' errors=[0-9]*' | cut -d= -f2)"
    p99="$(printf '%s' "$row" | grep -o ' p99_ns=[0-9]*' | cut -d= -f2)"
    printf '%-10s %-12s %10s %10.0f %8s %10s\n' \
        "$proto" "$workload" "$requests" "$rps" "$errors" "$((p99 / 1000))" >&2
    [ "${errors:-1}" = "0" ] || return 1
}

printf '\n%-10s %-12s %10s %10s %8s %10s\n' \
    PROTOCOL WORKLOAD REQUESTS RPS ERRORS 'P99(us)' >&2
printf '%.0s-' {1..66} >&2; echo >&2

FAIL=0
H1_URL="http://127.0.0.1:${GW_PORT}/bench"
run_workload h1 throughput  "$H1_URL" || FAIL=1
run_workload h1 pool-reuse  "$H1_URL" || FAIL=1
run_workload h1 streaming   "$H1_URL" || FAIL=1

if [ "$SKIP_H2" != "1" ]; then
    # h2c prior-knowledge against the same cleartext gateway listener.
    run_workload h2 throughput "$H1_URL" || FAIL=1
    run_workload h2 pool-reuse "$H1_URL" || FAIL=1
fi

# H3 is opt-in: it needs a TLS/QUIC gateway listener (feature-gated,
# default-off) which the plain rig does not provision. When
# DWARA_BENCH_H3_URL is set, drive h3 throughput against it; the loadgen
# must have been built with --features h3 (BENCH_H3_FEATURE=1).
if [ -n "$H3_URL" ]; then
    if [ "$H3_FEATURE" != "1" ]; then
        echo "DWARA_BENCH_H3_URL set but BENCH_H3_FEATURE!=1; build loadgen with --features h3 first" >&2
        exit 2
    fi
    run_workload h3 throughput "$H3_URL" || FAIL=1
fi

echo >&2
echo "machine-dependent numbers; the regression gate compares against a captured baseline" >&2
exit $FAIL
