#!/usr/bin/env python3
"""Tests for scripts/soak.py (REL-03 #174 soak assertion gate).

Standalone assert-based tests (no pytest dependency): run with
`python3 scripts/test-soak.py`. Exits 0 on success, 1 on the first failing
assertion. Covers SAMPLE: line parsing and the full `main()` gate:
RSS-ceiling pass/fail, p99-drift pass/fail, error-window hard failure,
empty/single-sample edge cases, all-zero RSS, negative drift
(improvement), and the --rss-ceiling / --p99-drift CLI args.

These pin the contract the nightly CI gate (`.github/workflows/soak.yml`)
and humans rely on; the gate's exit codes are a consumed contract
(0 = pass, 1 = assertion failure, 2 = no samples / harness error).
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "soak.py")

# The script's filename has a hyphen-free name but import it via importlib
# for parity with the sibling test script. The module's
# `if __name__ == "__main__"` guard keeps `main()` from firing on import.
_spec = importlib.util.spec_from_file_location("soak", TARGET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

parse_sample_lines = mod.parse_sample_lines
main = mod.main

PASS = 0
FAIL = 1
USAGE = 2


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def run_main(stdin_text: str, argv: list[str]) -> tuple[int, str, str]:
    """Invoke main() with controlled stdin/argv and captured streams."""
    out = io.StringIO()
    err = io.StringIO()
    saved_argv = sys.argv
    saved_stdin = sys.stdin
    sys.argv = ["soak.py", *argv]
    sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main()
    finally:
        sys.argv = saved_argv
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


def sline(t: int = 0, rss_kb: int = 100_000, p99_ns: int = 100_000,
          rps: float = 1000.0, errors: int = 0, requests: int = 30_000) -> str:
    """Build one SAMPLE: line in the format soak.sh emits."""
    return (f"SAMPLE: t={t} rss_kb={rss_kb} p99_ns={p99_ns} "
            f"rps={rps} errors={errors} requests={requests}")


def windows(n: int, rss_kb: int = 100_000, p99_ns: int = 100_000,
            errors: int = 0) -> str:
    """Build n identical SAMPLE: lines, one per 30s window."""
    return "\n".join(sline(t=i * 30, rss_kb=rss_kb, p99_ns=p99_ns,
                           errors=errors) for i in range(n)) + "\n"


# --------------------------------------------------------------------------
# parse_sample_lines
# --------------------------------------------------------------------------

def test_parse_sample_lines_collects_all_sample_lines() -> None:
    stream = io.StringIO(
        sline(t=0, rss_kb=100, p99_ns=1000, rps=10.0, errors=0, requests=300)
        + "\n" + sline(t=30, rss_kb=110, p99_ns=1100, rps=11.0, errors=1,
                       requests=330)
        + "\n" + "some human progress line\n"
    )
    out = parse_sample_lines(stream)
    check(len(out) == 2, f"two SAMPLE lines, got {len(out)}")
    check(out[0]["rss_kb"] == 100, f"first rss: {out[0]}")
    check(out[1]["errors"] == 1, f"second errors: {out[1]}")
    check(out[1]["requests"] == 330, f"second requests: {out[1]}")


def test_parse_sample_lines_ignores_non_sample_lines() -> None:
    stream = io.StringIO("requests=10 errors=0\nRESULT: rps=1.0\nplain text\n")
    check(parse_sample_lines(stream) == [], "non-SAMPLE lines must be ignored")


def test_parse_sample_lines_skips_malformed_values() -> None:
    # rss_kb is not an integer -> ValueError -> line skipped.
    stream = io.StringIO(
        "SAMPLE: t=0 rss_kb=abc p99_ns=1 rps=1.0 errors=0 requests=1\n"
        + sline(t=30, rss_kb=100, p99_ns=1) + "\n"
    )
    out = parse_sample_lines(stream)
    check(len(out) == 1, f"malformed skipped, got {len(out)}")
    check(out[0]["rss_kb"] == 100, f"surviving line: {out[0]}")


def test_parse_sample_lines_skips_tokens_without_equals() -> None:
    # Tokens without `=` are dropped; the rest still parses.
    stream = io.StringIO(
        "SAMPLE: t=0 rss_kb=100 foo bar p99_ns=1 rps=1.0 errors=0 requests=1\n"
    )
    out = parse_sample_lines(stream)
    check(len(out) == 1, f"one line, got {len(out)}")
    check(out[0]["rss_kb"] == 100, f"rss parsed around junk: {out[0]}")


def test_parse_sample_lines_skips_empty_payload() -> None:
    # A SAMPLE: line with no key=value tokens -> empty rec -> skipped.
    stream = io.StringIO("SAMPLE: no tokens here\n" + sline() + "\n")
    out = parse_sample_lines(stream)
    check(len(out) == 1, f"empty-payload skipped, got {len(out)}")


def test_parse_sample_lines_defaults_missing_fields() -> None:
    # Missing fields default to 0 (t, rss_kb, p99_ns, rps, errors, requests).
    stream = io.StringIO("SAMPLE: rss_kb=100\n")
    out = parse_sample_lines(stream)
    check(len(out) == 1, f"one line, got {len(out)}")
    check(out[0]["rss_kb"] == 100, f"rss: {out[0]}")
    check(out[0]["t"] == 0.0, f"t default: {out[0]}")
    check(out[0]["p99_ns"] == 0, f"p99 default: {out[0]}")
    check(out[0]["errors"] == 0, f"errors default: {out[0]}")


def test_parse_sample_lines_empty_stream_yields_empty_list() -> None:
    check(parse_sample_lines(io.StringIO("")) == [], "empty stream -> empty list")


# --------------------------------------------------------------------------
# main() gate semantics
# --------------------------------------------------------------------------

def test_main_passes_when_within_both_ceilings() -> None:
    # 8 windows, flat p99, RSS well under the default 256MB ceiling.
    code, out, err = run_main(windows(8), [])
    check(code == PASS, f"flat soak must PASS, got {code}: {err}")
    check("PASS" in out, f"PASS banner present: {out!r}")


def test_main_fails_on_rss_ceiling_breach() -> None:
    # RSS above the default 262144 KB ceiling.
    stdin = windows(8, rss_kb=300_000)
    code, out, err = run_main(stdin, [])
    check(code == FAIL, f"RSS over ceiling must FAIL, got {code}: {err}")
    check("rss" in err, f"rss failure reported: {err}")


def test_main_fails_on_p99_drift_breach() -> None:
    # 8 windows: first quarter p99=100000, last quarter p99=300000
    # -> drift = 2.0 (200%) > default 0.50 -> FAIL. RSS stays flat.
    lines = []
    for i in range(8):
        p99 = 100_000 if i < 2 else 300_000
        lines.append(sline(t=i * 30, rss_kb=100_000, p99_ns=p99))
    code, out, err = run_main("\n".join(lines) + "\n", [])
    check(code == FAIL, f"p99 drift over ceiling must FAIL, got {code}: {err}")
    check("p99 drift" in err, f"p99 drift failure reported: {err}")


def test_main_hard_fails_on_errors_regardless_of_metrics() -> None:
    # RSS and p99 are flat/fine, but one window has errors > 0 -> hard FAIL.
    lines = [sline(t=0, rss_kb=100_000, p99_ns=100_000, errors=0)]
    for i in range(1, 8):
        lines.append(sline(t=i * 30, rss_kb=100_000, p99_ns=100_000,
                           errors=1 if i == 4 else 0))
    code, out, err = run_main("\n".join(lines) + "\n", [])
    check(code == FAIL, f"errors>0 must FAIL, got {code}: {err}")
    check("errors" in err, f"error failure reported: {err}")


def test_main_empty_stdin_exits_usage() -> None:
    code, out, err = run_main("", [])
    check(code == USAGE, f"no SAMPLE lines must exit 2, got {code}: {err}")
    check("no SAMPLE" in err, f"no-sample message: {err}")


def test_main_only_non_sample_lines_exits_usage() -> None:
    code, out, err = run_main("just human noise\nRESULT: x=1\n", [])
    check(code == USAGE, f"no parseable SAMPLE lines must exit 2, got {code}: {err}")


def test_main_single_sample_passes_with_zero_drift() -> None:
    # n=1: quarter = max(1, 0) = 1, early == late (same window), drift = 0.
    code, out, err = run_main(sline(t=0, rss_kb=100_000, p99_ns=100_000) + "\n", [])
    check(code == PASS, f"single sample must PASS, got {code}: {err}")


def test_main_two_samples_compare_first_to_last() -> None:
    # n=2: quarter = 1, early = window[0], late = window[1].
    # p99 doubling -> drift = 1.0 > 0.50 -> FAIL.
    stdin = (sline(t=0, p99_ns=100_000) + "\n"
             + sline(t=30, p99_ns=200_000) + "\n")
    code, out, err = run_main(stdin, [])
    check(code == FAIL, f"two-window drift must FAIL, got {code}: {err}")


def test_main_all_zero_rss_passes_rss_ceiling() -> None:
    # max_rss = 0, which is never > ceiling; p99 = 0 -> drift = 0.0.
    code, out, err = run_main(windows(8, rss_kb=0, p99_ns=0), [])
    check(code == PASS, f"all-zero RSS must PASS, got {code}: {err}")


def test_main_negative_drift_improvement_passes() -> None:
    # Late p99 LOWER than early -> negative drift -> never > ceiling -> PASS.
    lines = []
    for i in range(8):
        p99 = 200_000 if i < 2 else 100_000
        lines.append(sline(t=i * 30, rss_kb=100_000, p99_ns=p99))
    code, out, err = run_main("\n".join(lines) + "\n", [])
    check(code == PASS, f"improvement (negative drift) must PASS, got {code}: {err}")


def test_main_rss_ceiling_arg_widens_and_tightens() -> None:
    # rss=150_000 KB: passes at --rss-ceiling 200000, fails at 100000.
    stdin = windows(8, rss_kb=150_000)
    code_wide, _, _ = run_main(stdin, ["--rss-ceiling", "200000"])
    code_tight, _, err = run_main(stdin, ["--rss-ceiling", "100000"])
    check(code_wide == PASS, "150k RSS must PASS at 200k ceiling")
    check(code_tight == FAIL, f"150k RSS must FAIL at 100k ceiling: {err}")


def test_main_p99_drift_arg_widens_and_tightens() -> None:
    # 8 windows, drift = 0.2 (early 100k -> late 120k).
    lines = []
    for i in range(8):
        p99 = 100_000 if i < 2 else 120_000
        lines.append(sline(t=i * 30, rss_kb=100_000, p99_ns=p99))
    stdin = "\n".join(lines) + "\n"
    code_tight, _, _ = run_main(stdin, ["--p99-drift", "0.10"])
    code_wide, _, _ = run_main(stdin, ["--p99-drift", "0.30"])
    check(code_tight == FAIL, "20% drift must FAIL at 10% ceiling")
    check(code_wide == PASS, "20% drift must PASS at 30% ceiling")


def test_main_default_ceilings_match_doc() -> None:
    # Defaults: --rss-ceiling 262144, --p99-drift 0.50. RSS just under the
    # default ceiling and drift just under 50% must PASS with no args.
    lines = []
    for i in range(8):
        p99 = 100_000 if i < 2 else 140_000  # drift = 0.40 < 0.50
        lines.append(sline(t=i * 30, rss_kb=260_000, p99_ns=p99))
    code, out, err = run_main("\n".join(lines) + "\n", [])
    check(code == PASS, f"just-under-default must PASS, got {code}: {err}")


def test_main_prints_summary_table() -> None:
    code, out, err = run_main(windows(4), [])
    check(code == PASS, f"setup: {err}")
    check("soak summary" in out, f"summary header present: {out!r}")
    for label in ("windows", "max rss (KB)", "p99 drift", "total errors"):
        check(label in out, f"summary row {label!r} present: {out!r}")


def test_main_reports_all_failures_at_once() -> None:
    # Both RSS and p99 drift breach + errors: all three failures reported.
    lines = []
    for i in range(8):
        p99 = 100_000 if i < 2 else 400_000  # drift = 3.0
        lines.append(sline(t=i * 30, rss_kb=300_000, p99_ns=p99, errors=1))
    code, out, err = run_main("\n".join(lines) + "\n", [])
    check(code == FAIL, f"triple breach must FAIL, got {code}: {err}")
    check("errors" in err, f"errors reported: {err}")
    check("rss" in err, f"rss reported: {err}")
    check("p99 drift" in err, f"p99 drift reported: {err}")


TESTS = [
    test_parse_sample_lines_collects_all_sample_lines,
    test_parse_sample_lines_ignores_non_sample_lines,
    test_parse_sample_lines_skips_malformed_values,
    test_parse_sample_lines_skips_tokens_without_equals,
    test_parse_sample_lines_skips_empty_payload,
    test_parse_sample_lines_defaults_missing_fields,
    test_parse_sample_lines_empty_stream_yields_empty_list,
    test_main_passes_when_within_both_ceilings,
    test_main_fails_on_rss_ceiling_breach,
    test_main_fails_on_p99_drift_breach,
    test_main_hard_fails_on_errors_regardless_of_metrics,
    test_main_empty_stdin_exits_usage,
    test_main_only_non_sample_lines_exits_usage,
    test_main_single_sample_passes_with_zero_drift,
    test_main_two_samples_compare_first_to_last,
    test_main_all_zero_rss_passes_rss_ceiling,
    test_main_negative_drift_improvement_passes,
    test_main_rss_ceiling_arg_widens_and_tightens,
    test_main_p99_drift_arg_widens_and_tightens,
    test_main_default_ceilings_match_doc,
    test_main_prints_summary_table,
    test_main_reports_all_failures_at_once,
]


def main_test() -> int:
    passed = 0
    for t in TESTS:
        try:
            t()
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
            return 1
        except Exception as e:  # noqa: BLE001 - surface any unexpected error
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
            return 1
        passed += 1
        print(f"ok   {t.__name__}")
    print(f"\n{passed}/{len(TESTS)} soak tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main_test())
