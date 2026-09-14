#!/usr/bin/env bash
# Phase 1: Micro-benchmark regression runner.
#
# Runs the criterion micro-benchmarks (micro + cel) and gates the
# micro results against the checked-in baseline. Saves raw output
# to a timestamped file for later analysis or cross-run comparison.
#
# The micro benchmarks measure per-primitive hot-path cost (route
# lookup, config compile, header strip, balancer pick, GCRA check,
# API-key verify, CEL evaluation). They are the first gate before
# macro benchmarks: any >25% regression should be investigated.
#
# Usage:
#   scripts/bench-micro-run.sh                    # run + gate
#   scripts/bench-micro-run.sh --write            # capture new baseline
#   scripts/bench-micro-run.sh --skip-cel         # skip CEL benchmarks
#   BENCH_MACHINE=myhost scripts/bench-micro-run.sh
#
# Environment:
#   BENCH_MACHINE         machine label (default: auto-detected)
#   BENCH_FEATURES_ENT    set to 1 to build with --features ent (default: 0)
#   BENCH_OUTPUT_DIR      directory for raw output files (default: bench-results/)
#   BENCH_TOLERANCE       regression tolerance override (default: baseline's, 0.25)
#   BENCH_EXPECT_MACHINE  fail-open if baseline machine differs (default: unset)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DO_WRITE=0
SKIP_CEL=0
for arg in "$@"; do
    case "$arg" in
        --write)      DO_WRITE=1 ;;
        --skip-cel)   SKIP_CEL=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

FEATURES_ENT="${BENCH_FEATURES_ENT:-0}"
OUTPUT_DIR="${BENCH_OUTPUT_DIR:-$ROOT/bench-results}"
OS="$(uname -s)"
case "$OS" in
    Darwin) MACHINE_LABEL="${BENCH_MACHINE:-macos-local}" ;;
    Linux)  MACHINE_LABEL="${BENCH_MACHINE:-linux-local}" ;;
    *)      MACHINE_LABEL="${BENCH_MACHINE:-unknown}" ;;
esac

mkdir -p "$OUTPUT_DIR"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MICRO_OUT="$OUTPUT_DIR/micro-$TIMESTAMP.txt"
CEL_OUT="$OUTPUT_DIR/cel-$TIMESTAMP.txt"

CARGO_ARGS=(--workspace)
if [ "$FEATURES_ENT" = "1" ]; then
    CARGO_ARGS+=(--features ent)
fi

# -------------------------------------------------------------------
# Micro-benchmarks
# -------------------------------------------------------------------
echo "== phase 1: micro-benchmark regression (machine=$MACHINE_LABEL) =="
echo "== running criterion micro benchmarks =="
cargo bench "${CARGO_ARGS[@]}" --bench micro -- --output-format bencher \
    | tee "$MICRO_OUT"

# -------------------------------------------------------------------
# Gate or write baseline
# -------------------------------------------------------------------
GATE_ARGS=()
if [ -n "${BENCH_EXPECT_MACHINE:-}" ]; then
    GATE_ARGS+=(--expect-machine "$BENCH_EXPECT_MACHINE")
fi
if [ -n "${BENCH_TOLERANCE:-}" ]; then
    GATE_ARGS+=(--tolerance "$BENCH_TOLERANCE")
fi

if [ "$DO_WRITE" = "1" ]; then
    echo "== writing new micro baseline (machine=$MACHINE_LABEL) =="
    python3 "$ROOT/scripts/bench-baseline.py" \
        --write "$ROOT/crates/dwara-core/benches/baseline.json" \
        --force --machine "$MACHINE_LABEL" \
        < "$MICRO_OUT"
    echo "  written: crates/dwara-core/benches/baseline.json"
else
    echo "== gating micro benchmarks against baseline =="
    python3 "$ROOT/scripts/bench-baseline.py" \
        --baseline "$ROOT/crates/dwara-core/benches/baseline.json" \
        "${GATE_ARGS[@]}" \
        < "$MICRO_OUT"
    GATE_RC=$?
    if [ "$GATE_RC" -ne 0 ]; then
        echo "micro-benchmark regression gate FAILED (exit $GATE_RC)" >&2
        echo "raw output: $MICRO_OUT" >&2
        exit "$GATE_RC"
    fi
    echo "  micro gate: PASS"
fi

# -------------------------------------------------------------------
# CEL benchmarks (no regression gate — no checked-in baseline)
# -------------------------------------------------------------------
if [ "$SKIP_CEL" = "0" ]; then
    echo "== running CEL benchmarks =="
    cargo bench "${CARGO_ARGS[@]}" --bench cel 2>&1 | tee "$CEL_OUT"
    echo "  raw output: $CEL_OUT"
fi

echo "== phase 1 complete =="
echo "  micro output: $MICRO_OUT"
[ "$SKIP_CEL" = "0" ] && echo "  cel output:   $CEL_OUT"
