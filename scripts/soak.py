#!/usr/bin/env python3
"""REL-03 (#174) soak assertion gate.

Reads `SAMPLE:` lines emitted by scripts/soak.sh and FAILS (exit 1) when
either ceiling is breached:

  * RSS ceiling  -- max sampled RSS (KB) > --rss-ceiling
  * p99 drift    -- late-window p99 grew beyond --p99-drift relative to
                    the early-window baseline

Each `SAMPLE:` line is one loadgen window and looks like:

    SAMPLE: t=<elapsed_s> rss_kb=<n> p99_ns=<n> rps=<f> errors=<n> requests=<n>

p99 drift is the fractional growth from the EARLY baseline (mean p99 of
the first quarter of windows) to the LATE tail (mean p99 of the last
quarter). A windowed mean sheds single-sample noise; the default 50%
tolerance is generous for shared CI runners but catches the steady
growth a leak causes. A window with errors > 0 is a hard failure
regardless of metrics (the soak did not run cleanly).

Usage:

    scripts/soak.sh | scripts/soak.py \\
        --rss-ceiling 262144 --p99-drift 0.50

Absolute RSS and latency are machine- and load-dependent; the ceilings
are operational bars, not regression baselines (the macro regression
gate in scripts/bench-regression.py handles like-for-like comparison).
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterator


def parse_sample_lines(stream) -> list[dict]:
    """Collect `SAMPLE: {...}` lines into a list of metric dicts."""
    out: list[dict] = []
    for line in stream:
        line = line.strip()
        if not line.startswith("SAMPLE:"):
            continue
        payload = line[len("SAMPLE:"):].strip()
        rec: dict = {}
        for tok in payload.split():
            if "=" not in tok:
                continue
            k, v = tok.split("=", 1)
            rec[k] = v
        if not rec:
            continue
        try:
            out.append({
                "t": float(rec.get("t", 0)),
                "rss_kb": int(rec.get("rss_kb", 0)),
                "p99_ns": int(rec.get("p99_ns", 0)),
                "rps": float(rec.get("rps", 0.0)),
                "errors": int(rec.get("errors", 0)),
                "requests": int(rec.get("requests", 0)),
            })
        except ValueError:
            print(f"soak: skipping malformed SAMPLE line: {payload!r}",
                  file=sys.stderr)
            continue
    return out


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--rss-ceiling", type=int, default=262144,
                    help="max gateway RSS in KB (default 262144 = 256MB)")
    ap.add_argument("--p99-drift", type=float, default=0.50,
                    help="max fractional p99 drift from early to late "
                         "windows (default 0.50)")
    args = ap.parse_args()

    samples = parse_sample_lines(sys.stdin)
    if not samples:
        print("soak: no SAMPLE lines parsed on stdin "
              "(did the harness emit any windows?)", file=sys.stderr)
        return 2

    n = len(samples)
    # Early baseline = first quarter of windows; late tail = last quarter.
    # At least one window per side so a short soak still produces a drift
    # signal (a 2-window smoke run compares window 1 to window 2).
    quarter = max(1, n // 4)
    early_p99 = _mean([s["p99_ns"] for s in samples[:quarter]])
    late_p99 = _mean([s["p99_ns"] for s in samples[-quarter:]])
    if early_p99 > 0:
        drift = (late_p99 - early_p99) / early_p99
    else:
        drift = 0.0

    max_rss = max(s["rss_kb"] for s in samples)
    total_errors = sum(s["errors"] for s in samples)
    total_requests = sum(s["requests"] for s in samples)
    mean_rps = _mean([s["rps"] for s in samples])

    failures: list[str] = []

    # A window with errors is a hard failure regardless of metrics: the
    # soak did not run cleanly, so RSS/latency numbers are not trustworthy.
    if total_errors > 0:
        failures.append(f"errors: {total_errors} across the soak "
                        f"(windows did not complete cleanly)")

    if max_rss > args.rss_ceiling:
        failures.append(
            f"rss: max {max_rss} KB > ceiling {args.rss_ceiling} KB "
            f"(+{max_rss - args.rss_ceiling} KB)"
        )

    if drift > args.p99_drift:
        failures.append(
            f"p99 drift: {drift * 100:+.1f}% > {args.p99_drift * 100:.0f}% "
            f"(early {early_p99:.0f} ns -> late {late_p99:.0f} ns)"
        )

    # Summary table.
    print(f"\n{'soak summary':^48s}")
    print("-" * 48)
    print(f"  windows              {n}")
    print(f"  total requests       {total_requests}")
    print(f"  mean rps             {mean_rps:.0f}")
    print(f"  total errors         {total_errors}")
    print(f"  max rss (KB)         {max_rss}")
    print(f"  rss ceiling (KB)     {args.rss_ceiling}")
    print(f"  early p99 (ns)       {early_p99:.0f}")
    print(f"  late p99 (ns)        {late_p99:.0f}")
    print(f"  p99 drift            {drift * 100:+.1f}%")
    print(f"  p99 drift ceiling    {args.p99_drift * 100:.0f}%")
    print("-" * 48)

    if failures:
        print(f"\nsoak: FAIL ({len(failures)} assertion(s)):", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("\nsoak: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
