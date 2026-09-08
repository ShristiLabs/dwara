#!/usr/bin/env python3
"""PERF-06 (#171) macro-benchmark regression gate.

Comares the machine-parseable `JSON:` lines emitted by `dwara-loadgen
--json` (collected by scripts/bench-regression.sh) against a checked-in
macro baseline and FAILS (exit 1) when any workload regressed more than
the tolerance (default 10%).

Each `JSON:` line is one workload run and looks like:

    JSON: {"protocol":"h1","workload":"throughput","connections":10,
           "duration_s":10,"rate":0,"requests":12345,"errors":0,
           "rps":1234.5,"p50_ns":...,"p90_ns":...,"p99_ns":...,
           "p999_ns":...,"err_p99_ns":...}

The gate keys each run by `protocol/workload` and compares two metrics:

  * rps      - regression is LOWER (throughput dropped)
  * p99_ns   - regression is HIGHER (tail latency grew)

Both directions use the same tolerance. A run with errors > 0 is a hard
failure regardless of metrics (the workload did not complete cleanly).

Usage:

    # gate (CI + humans):
    scripts/bench-regression.sh | scripts/bench-regression.py \
        --baseline scripts/bench-macro-baseline.json

    # refresh the baseline (commit the result; --write is guarded):
    scripts/bench-regression.sh | scripts/bench-regression.py \
        --write scripts/bench-macro-baseline.json --force \
        --machine <label-of-the-machine-that-ran-it>

Absolute numbers are machine-dependent (loadgen rps/latency on loopback
vary with CPU, kernel, and load). The baseline carries meta.machine; the
gate accepts --expect-machine LABEL and SKIPS the comparison (fail-open,
exit 0) when the baseline machine differs, mirroring the micro-benchmark
gate (scripts/bench-baseline.py). Capture the baseline on the CI runner
once, then the nightly gate compares like-for-like.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterator

TOLERANCE = 0.10
# Metrics and their regression direction: True = higher is worse.
METRICS = {"rps": False, "p99_ns": True}


def parse_json_lines(stream) -> dict[str, dict]:
    """Collect `JSON: {...}` lines into {protocol/workload: metrics}."""
    out: dict[str, dict] = {}
    for line in stream:
        line = line.strip()
        if not line.startswith("JSON: "):
            continue
        payload = line[len("JSON: "):]
        try:
            v = json.loads(payload)
        except json.JSONDecodeError:
            print(f"bench-regression: skipping malformed JSON line: {payload!r}",
                  file=sys.stderr)
            continue
        proto = v.get("protocol")
        work = v.get("workload")
        if not proto or not work:
            print(f"bench-regression: skipping JSON line missing protocol/workload: {v!r}",
                  file=sys.stderr)
            continue
        key = f"{proto}/{work}"
        out[key] = v
    return out


def _metric_change(base: float, cur: float, higher_is_worse: bool) -> float:
    """Fractional regression magnitude (>= 0 means a regression)."""
    if base <= 0:
        return 0.0
    if higher_is_worse:
        return (cur - base) / base
    return (base - cur) / base


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", default="scripts/bench-macro-baseline.json")
    ap.add_argument("--write", metavar="FILE",
                    help="write current run as the new baseline "
                         "(requires --force and --machine)")
    ap.add_argument("--force", action="store_true",
                    help="confirm the --write overwrite (guarded: a stray --write "
                         "silently re-bases the regression gate)")
    ap.add_argument("--machine", metavar="LABEL",
                    help="label of the machine the current run executed on "
                         "(required with --write; recorded as meta.machine)")
    ap.add_argument("--expect-machine", metavar="LABEL",
                    help="skip the comparison (fail-open, exit 0) when the baseline's "
                         "meta.machine differs from LABEL")
    ap.add_argument("--tolerance", type=float, default=TOLERANCE)
    args = ap.parse_args()

    if args.write and not args.force:
        print("bench-regression: --write requires --force (re-basing the regression "
              "gate is a deliberate act)", file=sys.stderr)
        return 2
    if args.write and not args.machine:
        print("bench-regression: --write requires --machine LABEL (recorded in meta so "
              "the gate can avoid cross-machine comparison)", file=sys.stderr)
        return 2

    current = parse_json_lines(sys.stdin)
    if not current:
        print("bench-regression: no JSON: lines parsed on stdin "
              "(did the harness emit --json?)", file=sys.stderr)
        return 2

    if args.write:
        meta: dict = {}
        try:
            with open(args.write, encoding="utf-8") as f:
                meta = json.load(f).get("meta", {})
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        meta.update({"machine": args.machine,
                     "tolerance": args.tolerance,
                     "note": "macro loadgen JSON: rps + latency percentiles; "
                             "machine-dependent, loopback"})
        with open(args.write, "w", encoding="utf-8") as f:
            json.dump({"meta": meta, "workloads": current}, f, indent=2,
                      sort_keys=True)
            f.write("\n")
        print(f"wrote macro baseline with {len(current)} workloads to {args.write} "
              f"(machine: {args.machine})")
        return 0

    try:
        with open(args.baseline, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"bench-regression: baseline not found: {args.baseline}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"bench-regression: baseline {args.baseline} is not valid JSON: {e}",
              file=sys.stderr)
        return 2
    baseline: dict[str, dict] = data.get("workloads", {})

    if args.expect_machine:
        machine = data.get("meta", {}).get("machine")
        if machine != args.expect_machine:
            print("bench-regression: SKIP comparison (fail-open): baseline machine "
                  f"{machine!r} != this runner {args.expect_machine!r}.")
            print("bench-regression: cross-machine rps/latency comparison is not "
                  "meaningful. Capture a CI-runner baseline once (--write --force "
                  "--machine <runner-label>), then the nightly gate compares "
                  "like-for-like.")
            return 0

    failures: list[str] = []
    print(f"{'workload':24s} {'metric':>8s} {'baseline':>12s} {'current':>12s} "
          f"{'change':>8s}")
    for key in sorted(set(baseline) | set(current)):
        base = baseline.get(key)
        cur = current.get(key)
        if cur is None:
            print(f"{key:24s} {'MISSING':>8s}")
            failures.append(f"{key}: missing from current run")
            continue
        if base is None:
            print(f"{key:24s} {'-':>8s} {'-':>12s} "
                  f"{cur.get('rps'):12.0f}    (new; baseline lacks it)")
            continue
        # A run with errors is a hard failure regardless of metrics.
        errs = cur.get("errors", 0)
        if errs:
            print(f"{key:24s} {'errors':>8s} {'-':>12s} {errs:>12}   FAIL")
            failures.append(f"{key}: {errs} errors (workload did not complete cleanly)")
            continue
        for metric, higher_is_worse in METRICS.items():
            b = float(base.get(metric, 0))
            c = float(cur.get(metric, 0))
            change = _metric_change(b, c, higher_is_worse)
            flag = ""
            if change > args.tolerance:
                flag = "  REGRESSION"
                failures.append(
                    f"{key}/{metric}: {change * 100:+.1f}% > {args.tolerance * 100:.0f}%"
                )
            print(f"{key:24s} {metric:>8s} {b:12.0f} {c:12.0f} "
                  f"{change * 100:+7.1f}%{flag}")

    if failures:
        print(f"\nbench-regression: FAIL ({len(failures)} regression(s) beyond "
              f"{args.tolerance * 100:.0f}%):", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("\nbench-regression: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
