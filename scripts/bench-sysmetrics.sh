#!/usr/bin/env bash
# System metrics capture helper for production-grade benchmarking.
#
# Provides functions to sample RSS, CPU, and file-descriptor count for
# a gateway process. Works on both macOS and Linux. Designed to be
# sourced by other bench scripts (bench-macro-sweep.sh, bench-rate-sweep.sh)
# or used standalone for ad-hoc sampling.
#
# Usage (sourced):
#   source scripts/bench-sysmetrics.sh
#   rss=$(sample_rss_kb "$PID")
#   fds=$(sample_fd_count "$PID")
#   cpu=$(sample_cpu_pct "$PID")
#
# Usage (standalone):
#   scripts/bench-sysmetrics.sh <pid> [interval_secs] [count]
#   # samples every 1s for 10s:
#   scripts/bench-sysmetrics.sh 12345 1 10

# -------------------------------------------------------------------
# sample_rss_kb PID — resident set size in KB (works on macOS + Linux)
# -------------------------------------------------------------------
sample_rss_kb() {
    ps -o rss= -p "$1" 2>/dev/null | tr -d ' '
}

# -------------------------------------------------------------------
# sample_fd_count PID — open file descriptor count
# -------------------------------------------------------------------
sample_fd_count() {
    local pid="$1"
    if [ -d "/proc/$pid/fd" ]; then
        # Linux: count entries in /proc/<pid>/fd
        ls "/proc/$pid/fd" 2>/dev/null | wc -l | tr -d ' '
    else
        # macOS: use lsof (slower but portable)
        lsof -p "$pid" 2>/dev/null | wc -l | tr -d ' '
    fi
}

# -------------------------------------------------------------------
# sample_cpu_pct PID — instantaneous CPU percentage (0-100 * ncpu)
# Uses ps which reports cumulative CPU since process start; for a
# delta, call twice and compute the difference.
# -------------------------------------------------------------------
sample_cpu_pct() {
    ps -o %cpu= -p "$1" 2>/dev/null | tr -d ' '
}

# -------------------------------------------------------------------
# sample_all PID — one-shot snapshot of all metrics as a single line
# Output format: SYSMETRIC: rss_kb=<n> fd_count=<n> cpu_pct=<f>
# -------------------------------------------------------------------
sample_all() {
    local pid="$1"
    local rss fds cpu
    rss="$(sample_rss_kb "$pid")"
    fds="$(sample_fd_count "$pid")"
    cpu="$(sample_cpu_pct "$pid")"
    rss="${rss:-0}"
    fds="${fds:-0}"
    cpu="${cpu:-0.0}"
    printf 'SYSMETRIC: rss_kb=%s fd_count=%s cpu_pct=%s\n' "$rss" "$fds" "$cpu"
}

# -------------------------------------------------------------------
# scrape_metrics URL — fetch gateway /metrics endpoint, extract key
# counters/gauges relevant to benchmarking. Returns a single line:
# METRICSCRAPE: active_requests=<n> requests_total=<n> ...
# -------------------------------------------------------------------
scrape_metrics() {
    local url="$1"
    local out
    out="$(curl -fsS --max-time 5 "$url" 2>/dev/null)" || return 0
    local active reqs rate_limited shed cache_hits cache_miss
    active="$(printf '%s\n' "$out" | grep -o '^active_requests [0-9]*' | head -1 | awk '{print $2}')"
    reqs="$(printf '%s\n' "$out" | grep -o '^requests_total{[^}]*} [0-9]*' | awk '{sum += $2} END {print sum+0}')"
    rate_limited="$(printf '%s\n' "$out" | grep -o '^rate_limited_total{[^}]*} [0-9]*' | awk '{sum += $2} END {print sum+0}')"
    shed="$(printf '%s\n' "$out" | grep -o '^shed_total{[^}]*} [0-9]*' | awk '{sum += $2} END {print sum+0}')"
    cache_hits="$(printf '%s\n' "$out" | grep -o '^dwara_cache_lookups_total{[^}]*outcome="hit"[^}]*} [0-9]*' | awk '{print $2+0}')"
    cache_miss="$(printf '%s\n' "$out" | grep -o '^dwara_cache_lookups_total{[^}]*outcome="miss"[^}]*} [0-9]*' | awk '{print $2+0}')"
    printf 'METRICSCRAPE: active_requests=%s requests_total=%s rate_limited=%s shed=%s cache_hits=%s cache_miss=%s\n' \
        "${active:-0}" "${reqs:-0}" "${rate_limited:-0}" "${shed:-0}" "${cache_hits:-0}" "${cache_miss:-0}"
}

# -------------------------------------------------------------------
# Standalone mode: sample a PID at regular intervals
# -------------------------------------------------------------------
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    if [ $# -lt 1 ]; then
        echo "usage: $0 <pid> [interval_secs] [count]" >&2
        echo "  samples RSS, fd count, CPU every <interval> for <count> samples" >&2
        exit 2
    fi
    PID="$1"
    INTERVAL="${2:-1}"
    COUNT="${3:-10}"
    T=0
    printf '%-8s %12s %10s %10s\n' "T_S" "RSS_KB" "FD_COUNT" "CPU_%"
    printf '%.0s-' {1..42}; echo
    for i in $(seq 1 "$COUNT"); do
        rss="$(sample_rss_kb "$PID")"
        fds="$(sample_fd_count "$PID")"
        cpu="$(sample_cpu_pct "$PID")"
        printf '%-8s %12s %10s %10s\n' "$T" "${rss:-0}" "${fds:-0}" "${cpu:-0.0}"
        T=$((T + INTERVAL))
        [ "$i" -lt "$COUNT" ] && sleep "$INTERVAL" || true
    done
fi
