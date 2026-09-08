#!/usr/bin/env bash
# REL-03 (#174) soak harness: RSS-ceiling + p99-drift assertions.
#
# Boots the real gateway (dwara) against an in-process echo upstream
# (dwara-loadgen --echo-only) and drives SUSTAINED load through it in
# fixed-width windows. After each window it samples the gateway's RSS
# (resident set size, in KB) and records the window's p99 latency from
# the loadgen JSON output. At the end it pipes the sample stream to
# scripts/soak.py which asserts:
#   * max RSS   <= SOAK_RSS_CEILING_KB   (memory-leak ceiling)
#   * p99 drift <= SOAK_P99_DRIFT        (latency-drift ceiling)
# and prints a summary table.
#
# The soak is SEPARATE from the per-PR gate (ci.yml) and the macro
# regression gate (bench-nightly.yml): it is slow and meant for the
# nightly CI job (.github/workflows/soak.yml) or dedicated hosts. The
# default CI duration is 10 minutes; set SOAK_DURATION=86400 for a 24h
# run on a dedicated host (raise the RSS ceiling and the workflow
# timeout accordingly).
#
# The spawn/readiness pattern mirrors scripts/bench-regression.sh: one
# cleartext listener that speaks both HTTP/1.1 and h2c, one route to the
# echo upstream, /healthz readiness probe.
#
# Usage:
#   scripts/soak.sh
#   SOAK_DURATION=10 scripts/soak.sh                 # quick smoke
#   SOAK_DURATION=86400 SOAK_RSS_CEILING_KB=1048576 scripts/soak.sh
#
# Environment:
#   SOAK_DURATION          total soak seconds                (default 600)
#   SOAK_RATE              target requests/sec (0=unbounded) (default 1000)
#   SOAK_CONNECTIONS       concurrent connections            (default 50)
#   SOAK_SAMPLE_SECS       per-window loadgen seconds        (default 30)
#   SOAK_RSS_CEILING_KB    max gateway RSS in KB             (default 262144 = 256MB)
#   SOAK_P99_DRIFT         max fractional p99 drift          (default 0.50)
#   SOAK_GATEWAY_PORT      gateway port                      (default 18092)
#   SOAK_ECHO_PORT         echo upstream port                (default 18093)
#   SOAK_PROTOCOL          h1 | h2                           (default h1)
#   SOAK_WORKLOAD          throughput | pool-reuse | streaming (default throughput)
#
# stdout: one `SAMPLE:` line per window (consumed by scripts/soak.py).
# stderr: human-readable progress.

set -euo pipefail

DURATION="${SOAK_DURATION:-600}"
RATE="${SOAK_RATE:-1000}"
CONNS="${SOAK_CONNECTIONS:-50}"
SAMPLE_SECS="${SOAK_SAMPLE_SECS:-30}"
RSS_CEILING_KB="${SOAK_RSS_CEILING_KB:-262144}"
P99_DRIFT="${SOAK_P99_DRIFT:-0.50}"
GW_PORT="${SOAK_GATEWAY_PORT:-18092}"
ECHO_PORT="${SOAK_ECHO_PORT:-18093}"
PROTOCOL="${SOAK_PROTOCOL:-h1}"
WORKLOAD="${SOAK_WORKLOAD:-throughput}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release"

command -v curl >/dev/null || { echo "curl required for the readiness probe" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required for the assertion gate" >&2; exit 2; }

# Build the loadgen and the gateway (release). The soak drives real
# traffic, so a release build is the only meaningful profile.
echo "== building (release) ==" >&2
cargo build --release -p dwara-cli --bin dwara-loadgen >/dev/null
cargo build --release -p dwara-bin --bin dwara >/dev/null

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dwara-soak.XXXXXX")"
SAMPLES="$WORK/samples.txt"
cleanup() {
    # Kill child processes reliably; ignore failures from already-exited PIDs.
    kill "${GW_PID:-0}" "${ECHO_PID:-0}" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# One route -> the echo upstream. The cleartext listener speaks both
# HTTP/1.1 and h2c (prior knowledge), so the same gateway serves h1 and
# h2 soaks without reconfiguration.
cat >"$WORK/dwara.yaml" <<EOF
listeners:
  - name: soak
    address: 127.0.0.1
    port: ${GW_PORT}
routes:
  - name: catch-all
    service: soak-svc
    match:
      path:
        type: prefix
        value: /soak
    action:
      type: proxy
services:
  - name: soak-svc
    upstream: soak-upstream
upstreams:
  - name: soak-upstream
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

# Sample the gateway's RSS in KB. `ps -o rss=` works on both Linux and
# macOS and reports RSS in KB on both. Returns empty if the process died.
sample_rss_kb() {
    ps -o rss= -p "$1" 2>/dev/null | tr -d ' '
}

URL="http://127.0.0.1:${GW_PORT}/soak"
echo "== soak: ${DURATION}s @ ${RATE} rps, ${CONNS} conns, ${SAMPLE_SECS}s windows ==" >&2
printf '%-8s %12s %14s %12s %10s %10s\n' \
    T_S RSS_KB P99_NS RPS ERRORS REQUESTS >&2
printf '%.0s-' {1..70} >&2; echo >&2

elapsed=0
FAIL=0
while [ "$elapsed" -lt "$DURATION" ]; do
    # The final window is clipped so the soak does not overshoot DURATION.
    remaining=$((DURATION - elapsed))
    window=$((SAMPLE_SECS < remaining ? SAMPLE_SECS : remaining))
    [ "$window" -ge 1 ] || break

    extra=()
    case "$WORKLOAD" in
        streaming) extra=(--workload streaming --stream-chunks 8 --stream-chunk-bytes 1024);;
        *)         extra=(--workload "$WORKLOAD");;
    esac

    out="$("$BIN/dwara-loadgen" \
        --url "$URL" --protocol "$PROTOCOL" "${extra[@]}" \
        --connections "$CONNS" --duration "$window" --rate "$RATE" \
        --timeout-ms 10000 --json 2>/dev/null)" || {
        echo "window at t=${elapsed}s: loadgen run failed" >&2
        FAIL=1
        # Still record a sample so the gate sees the window happened.
        rss="$(sample_rss_kb "$GW_PID")"
        rss="${rss:-0}"
        printf 'SAMPLE: t=%s rss_kb=%s p99_ns=0 rps=0 errors=1 requests=0\n' \
            "$elapsed" "$rss" | tee -a "$SAMPLES"
        elapsed=$((elapsed + window))
        continue
    }

    json_line="$(printf '%s\n' "$out" | grep '^JSON: ' | head -1)"
    if [ -z "$json_line" ]; then
        echo "window at t=${elapsed}s: no JSON line from loadgen" >&2
        FAIL=1
        elapsed=$((elapsed + window))
        continue
    fi
    payload="${json_line#JSON: }"
    # Parse the fields we assert on with python3 (the gate already needs it).
    read -r p99 rps errors requests <<<"$(printf '%s\n' "$payload" | python3 -c \
        'import json,sys
v=json.loads(sys.stdin.read())
print(v.get("p99_ns",0), v.get("rps",0.0), v.get("errors",0), v.get("requests",0))')"

    rss="$(sample_rss_kb "$GW_PID")"
    rss="${rss:-0}"

    printf 'SAMPLE: t=%s rss_kb=%s p99_ns=%s rps=%s errors=%s requests=%s\n' \
        "$elapsed" "$rss" "$p99" "$rps" "$errors" "$requests" | tee -a "$SAMPLES"
    printf '%-8s %12s %14s %12.0f %10s %10s\n' \
        "$elapsed" "$rss" "$p99" "$rps" "$errors" "$requests" >&2

    elapsed=$((elapsed + window))
done

echo >&2
echo "== running assertion gate ==" >&2
python3 "$ROOT/scripts/soak.py" \
    --rss-ceiling "$RSS_CEILING_KB" \
    --p99-drift "$P99_DRIFT" \
    < "$SAMPLES"
gate_rc=$?

# A nonzero FAIL (loadgen/window failure) takes precedence so a crashed
# window is not masked by a passing drift/RSS gate.
[ "$FAIL" -eq 0 ] || exit 2
exit "$gate_rc"
