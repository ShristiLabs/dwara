#!/usr/bin/env bash
# Phase 0: Environment setup for production-grade benchmarking.
#
# Detects the OS, applies OS-specific tuning (file descriptor limits,
# TCP stack parameters on Linux), builds release binaries, and
# optionally captures machine-specific baselines for the micro and
# macro regression gates.
#
# Usage:
#   scripts/bench-env-setup.sh              # tune + build
#   scripts/bench-env-setup.sh --baseline   # tune + build + capture baselines
#   BENCH_MACHINE=myhost scripts/bench-env-setup.sh --baseline
#
# Environment:
#   BENCH_MACHINE         machine label for baseline capture (default: auto)
#   BENCH_SKIP_TUNE       set to 1 to skip OS tuning (default: 0)
#   BENCH_SKIP_BUILD      set to 1 to skip release build (default: 0)
#   BENCH_FEATURES_ENT    set to 1 to build with --features ent (default: 0)
#   BENCH_FD_LIMIT        file descriptor limit to request (default: 65536 macOS, 1048576 Linux)
#
# macOS notes:
#   macOS default fd limits (~2560) cap concurrent connections hard.
#   This script raises the per-shell limit but cannot raise the
#   system-wide hard limit (that requires launchctl or a SIP exception).
#   Stay at 10k connections or fewer on macOS.
#
# Linux notes:
#   On Linux this script raises the fd limit and applies TCP stack
#   sysctls (ip_local_port_range, somaxconn, tcp_tw_reuse,
#   tcp_max_syn_backlog). sysctl writes require root; the script
#   skips tuning silently if it lacks privileges and prints a warning.
#   For bare-metal production benchmarks, also pin CPU frequency
#   scaling to 'performance' and isolate cores via taskset/cgroups
#   (not done here because it requires root and is host-specific).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release"

DO_BASELINE=0
for arg in "$@"; do
    case "$arg" in
        --baseline) DO_BASELINE=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

SKIP_TUNE="${BENCH_SKIP_TUNE:-0}"
SKIP_BUILD="${BENCH_SKIP_BUILD:-0}"
FEATURES_ENT="${BENCH_FEATURES_ENT:-0}"

# -------------------------------------------------------------------
# OS detection
# -------------------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
    Darwin) MACHINE_LABEL="${BENCH_MACHINE:-macos-local}" ;;
    Linux)  MACHINE_LABEL="${BENCH_MACHINE:-linux-local}" ;;
    *)      MACHINE_LABEL="${BENCH_MACHINE:-unknown}" ;;
esac

echo "== phase 0: environment setup ($OS, machine=$MACHINE_LABEL) =="

# -------------------------------------------------------------------
# OS tuning
# -------------------------------------------------------------------
if [ "$SKIP_TUNE" = "0" ]; then
    FD_LIMIT="${BENCH_FD_LIMIT:-}"
    if [ -z "$FD_LIMIT" ]; then
        case "$OS" in
            Darwin) FD_LIMIT=65536 ;;
            Linux)  FD_LIMIT=1048576 ;;
        esac
    fi

    echo "== raising file descriptor limit to $FD_LIMIT =="
    ulimit -n "$FD_LIMIT" 2>/dev/null || {
        echo "warning: could not raise fd limit to $FD_LIMIT (current: $(ulimit -n))" >&2
        echo "  on macOS the system-wide hard limit may need launchctl:" >&2
        echo "    sudo launchctl limit maxfiles $FD_LIMIT $FD_LIMIT" >&2
    }
    echo "  current fd limit: $(ulimit -n)"

    if [ "$OS" = "Linux" ]; then
        echo "== applying TCP sysctls (requires root; skipped if denied) =="
        # These improve connection scaling on Linux. All are safe for
        # loopback benchmarks and standard for high-throughput servers.
        sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1 \
            && echo "  net.ipv4.ip_local_port_range=1024 65535" \
            || echo "  warning: could not set ip_local_port_range (need root)" >&2
        sudo sysctl -w net.core.somaxconn=65535 >/dev/null 2>&1 \
            && echo "  net.core.somaxconn=65535" \
            || echo "  warning: could not set somaxconn (need root)" >&2
        sudo sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1 \
            && echo "  net.ipv4.tcp_tw_reuse=1" \
            || echo "  warning: could not set tcp_tw_reuse (need root)" >&2
        sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535 >/dev/null 2>&1 \
            && echo "  net.ipv4.tcp_max_syn_backlog=65535" \
            || echo "  warning: could not set tcp_max_syn_backlog (need root)" >&2
        sudo sysctl -w net.core.netdev_max_backlog=65535 >/dev/null 2>&1 \
            && echo "  net.core.netdev_max_backlog=65535" \
            || echo "  warning: could not set netdev_max_backlog (need root)" >&2

        # CPU frequency scaling (bare metal only; no-op on VMs).
        if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
            echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo >/dev/null 2>&1 \
                && echo "  intel_pstate/no_turbo=1 (turbo disabled for stable clocks)" \
                || true
        fi
        cpupower frequency-set -g performance >/dev/null 2>&1 \
            && echo "  cpupower governor=performance" \
            || true
    fi

    if [ "$OS" = "Darwin" ]; then
        echo "== macOS: no TCP sysctls applied (kernel auto-tunes loopback) =="
        echo "  for production numbers, re-run on a dedicated Linux host"
    fi
else
    echo "== skipping OS tuning (BENCH_SKIP_TUNE=1) =="
fi

# -------------------------------------------------------------------
# Build release binaries
# -------------------------------------------------------------------
if [ "$SKIP_BUILD" = "0" ]; then
    echo "== building release binaries =="
    CARGO_ARGS=(--release)
    if [ "$FEATURES_ENT" = "1" ]; then
        CARGO_ARGS+=(--features ent)
    fi
    cargo build "${CARGO_ARGS[@]}" -p dwara-cli --bin dwara-loadgen
    cargo build "${CARGO_ARGS[@]}" -p dwara-bin --bin dwara
    echo "  binaries at: $BIN/dwara-loadgen, $BIN/dwara"
else
    echo "== skipping build (BENCH_SKIP_BUILD=1) =="
fi

# -------------------------------------------------------------------
# Baseline capture
# -------------------------------------------------------------------
if [ "$DO_BASELINE" = "1" ]; then
    echo "== capturing baselines (machine=$MACHINE_LABEL) =="

    echo "-- micro-benchmark baseline --"
    cargo bench --workspace --bench micro -- --output-format bencher \
        | python3 "$ROOT/scripts/bench-baseline.py" \
            --write "$ROOT/crates/dwara-core/benches/baseline.json" \
            --force --machine "$MACHINE_LABEL"
    echo "  written: crates/dwara-core/benches/baseline.json"

    echo "-- macro-benchmark baseline --"
    # Use a short duration for baseline capture; the values are
    # machine-relative and the gate uses a 10% tolerance.
    BENCH_DURATION=10 BENCH_CONNECTIONS=100 \
        "$ROOT/scripts/bench-regression.sh" 2>/dev/null \
        | python3 "$ROOT/scripts/bench-regression.py" \
            --write "$ROOT/scripts/bench-macro-baseline.json" \
            --force --machine "$MACHINE_LABEL"
    echo "  written: scripts/bench-macro-baseline.json"
fi

echo "== phase 0 complete =="
