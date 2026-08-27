#!/usr/bin/env python3
"""DW-024 micro-benchmark regression gate.

Compares criterion `--output-format bencher` output against a checked-in
baseline (crates/dwara-core/benches/baseline.json) and FAILS (exit 1) when
any benchmark regressed more than the tolerance (default 25%).

Bencher-format input lines look like:

    test route/find_full_prefix_hit ... bench:         163.2 ns/iter (+/- 5.1)

Usage:

    # gate (CI + humans):
    cargo bench --workspace --bench micro -- --output-format bencher \
        | scripts/bench-baseline.py --baseline crates/dwara-core/benches/baseline.json

    # refresh the baseline (commit the result; --write is guarded):
    cargo bench --workspace --bench micro -- --output-format bencher \
        | scripts/bench-baseline.py --write crates/dwara-core/benches/baseline.json \
            --force --machine <label-of-the-machine-that-ran-it>

Absolute numbers are machine-dependent: the baseline was captured on one
specific machine (see the JSON's "meta.machine"). Refresh it whenever
benchmarked code changes shape (new/renamed benches) or the reference
machine changes; the gate only ever compares a run to that file.

Machine matching: the gate accepts --expect-machine LABEL. When the
baseline's meta.machine does not match LABEL, the comparison is SKIPPED
(exit 0, fail-open) with a clear notice — comparing absolute ns/iter
across machines is meaningless. The intended flow: dispatch the
baseline refresh on the CI runner ONCE (gh workflow run bench.yml
--ref main -f job=baseline-refresh; it re-runs the benches on the CI
runner and commits a CI-captured baseline with meta.machine set to the
runner label), after which the weekly gate compares like-for-like.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

BENCH_LINE = re.compile(r"^test\s+(\S+)\s+\.\.\.\s+bench:\s+([\d.]+)\s+ns/iter")
TOLERANCE = 0.25


def parse_bencher(stream) -> dict[str, float]:
    out: dict[str, float] = {}
    for line in stream:
        m = BENCH_LINE.match(line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", default="crates/dwara-core/benches/baseline.json")
    ap.add_argument("--write", metavar="FILE", help="write current run as the new baseline "
                    "(requires --force and --machine)")
    ap.add_argument("--force", action="store_true",
                    help="confirm the --write overwrite (guarded: a stray --write silently "
                         "re-bases the regression gate)")
    ap.add_argument("--machine", metavar="LABEL",
                    help="label of the machine the current run executed on "
                         "(required with --write; recorded as meta.machine)")
    ap.add_argument("--expect-machine", metavar="LABEL",
                    help="skip the comparison (fail-open, exit 0) when the baseline's "
                         "meta.machine differs from LABEL")
    ap.add_argument("--tolerance", type=float, default=TOLERANCE)
    args = ap.parse_args()

    if args.write and not args.force:
        print("bench-baseline: --write requires --force (re-basing the regression gate "
              "is a deliberate act)", file=sys.stderr)
        return 2
    if args.write and not args.machine:
        print("bench-baseline: --write requires --machine LABEL (recorded in meta so the "
              "gate can avoid cross-machine comparison)", file=sys.stderr)
        return 2

    current = parse_bencher(sys.stdin)
    if not current:
        print("bench-baseline: no bencher-format benchmarks parsed on stdin", file=sys.stderr)
        return 2

    if args.write:
        # Preserve the existing meta block on refresh; only the values
        # this run actually determines (machine, tolerance) are replaced.
        meta: dict = {}
        try:
            with open(args.write, encoding="utf-8") as f:
                meta = json.load(f).get("meta", {})
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        meta.update({"machine": args.machine,
                     "tolerance": args.tolerance,
                     "note": "ns/iter, bencher format"})
        with open(args.write, "w", encoding="utf-8") as f:
            json.dump({"meta": meta, "benches": current}, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"wrote baseline with {len(current)} benchmarks to {args.write} "
              f"(machine: {args.machine})")
        return 0

    try:
        with open(args.baseline, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"bench-baseline: baseline not found: {args.baseline}", file=sys.stderr)
        return 2
    baseline: dict[str, float] = data.get("benches", data)

    if args.expect_machine:
        machine = data.get("meta", {}).get("machine")
        if machine != args.expect_machine:
            print("bench-baseline: SKIP comparison (fail-open): baseline machine "
                  f"{machine!r} != this runner {args.expect_machine!r}.")
            print("bench-baseline: cross-machine ns/iter comparison is not meaningful. "
                  "Dispatch the baseline refresh once to capture a CI-runner baseline "
                  "(gh workflow run bench.yml --ref main -f job=baseline-refresh), then "
                  "the weekly gate will compare like-for-like.")
            return 0

    failures = []
    print(f"{'benchmark':40s} {'baseline':>12s} {'current':>12s} {'change':>8s}")
    for name, base in sorted(baseline.items()):
        cur = current.get(name)
        if cur is None:
            print(f"{name:40s} {base:12.1f} {'MISSING':>12}")
            failures.append(f"{name}: missing from current run")
            continue
        change = (cur - base) / base if base else 0.0
        flag = ""
        if change > args.tolerance:
            flag = "  REGRESSION"
            failures.append(f"{name}: +{change * 100:.1f}% > {args.tolerance * 100:.0f}%")
        print(f"{name:40s} {base:12.1f} {cur:12.1f} {change * 100:+7.1f}%{flag}")

    added = sorted(set(current) - set(baseline))
    for name in added:
        print(f"{name:40s} {'-':>12} {current[name]:12.1f}    (new; baseline lacks it)")

    if failures:
        print(f"\nbench-baseline: FAIL ({len(failures)} regression(s) beyond "
              f"{args.tolerance * 100:.0f}%):", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("\nbench-baseline: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
