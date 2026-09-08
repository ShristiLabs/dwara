#!/usr/bin/env python3
"""Tests for scripts/bench-regression.py (PERF-06 #171 regression gate).

Standalone assert-based tests (no pytest dependency): run with
`python3 scripts/test-bench-regression.py`. Exits 0 on success, 1 on the
first failing assertion. Covers JSON-line parsing, the metric-change
helper, and the full `main()` gate: pass/regression/errors/missing
cases, baseline file edge cases, the --write guards, and the
--expect-machine fail-open skip.

These pin the contract the nightly CI gate (`.github/workflows/bench-
nightly.yml`) and humans rely on; the gate's exit codes are a consumed
contract (0 = pass, 1 = regression, 2 = usage/harness error).
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "bench-regression.py")

# The script's filename has a hyphen, so import it via importlib. The
# module's `if __name__ == "__main__"` guard keeps `main()` from firing
# on import.
_spec = importlib.util.spec_from_file_location("bench_regression", TARGET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

parse_json_lines = mod.parse_json_lines
_metric_change = mod._metric_change
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
    sys.argv = ["bench-regression.py", *argv]
    sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main()
    finally:
        sys.argv = saved_argv
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


def write_baseline(path: str, workloads: dict, meta: dict | None = None) -> None:
    payload = {"meta": meta or {}, "workloads": workloads}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
        f.write("\n")


def jline(protocol: str, workload: str, **overrides) -> str:
    base = {
        "protocol": protocol,
        "workload": workload,
        "connections": 10,
        "duration_s": 3,
        "rate": 0,
        "requests": 1000,
        "errors": 0,
        "rps": 1000.0,
        "p50_ns": 100_000,
        "p90_ns": 150_000,
        "p99_ns": 200_000,
        "p999_ns": 250_000,
        "err_p99_ns": 0,
    }
    base.update(overrides)
    return "JSON: " + json.dumps(base)


# --------------------------------------------------------------------------
# parse_json_lines
# --------------------------------------------------------------------------

def test_parse_json_lines_collects_by_protocol_workload() -> None:
    stream = io.StringIO(
        jline("h1", "throughput", rps=100.0)
        + "\n" + jline("h2", "pool-reuse", rps=50.0)
        + "\n" + "some human line\n"
    )
    out = parse_json_lines(stream)
    check(set(out.keys()) == {"h1/throughput", "h2/pool-reuse"},
          f"keys={set(out.keys())}")
    check(out["h1/throughput"]["rps"] == 100.0, "h1 rps")
    check(out["h2/pool-reuse"]["rps"] == 50.0, "h2 rps")


def test_parse_json_lines_ignores_non_json_lines() -> None:
    stream = io.StringIO("requests=10 errors=0\nRESULT: rps=1.0\nplain text\n")
    check(parse_json_lines(stream) == {}, "non-JSON lines must be ignored")


def test_parse_json_lines_skips_malformed_json() -> None:
    stream = io.StringIO("JSON: {not valid json\n" + jline("h1", "throughput") + "\n")
    out = parse_json_lines(stream)
    check(set(out.keys()) == {"h1/throughput"}, f"malformed skipped, got {set(out.keys())}")


def test_parse_json_lines_skips_missing_protocol_or_workload() -> None:
    stream = io.StringIO(
        'JSON: {"protocol":"h1","rps":1.0}\n'
        'JSON: {"workload":"throughput","rps":1.0}\n'
        'JSON: {"rps":1.0}\n'
        + jline("h1", "throughput") + "\n"
    )
    out = parse_json_lines(stream)
    check(set(out.keys()) == {"h1/throughput"},
          f"missing-label lines skipped, got {set(out.keys())}")


def test_parse_json_lines_empty_stream_yields_empty_dict() -> None:
    check(parse_json_lines(io.StringIO("")) == {}, "empty stream -> empty dict")


# --------------------------------------------------------------------------
# _metric_change
# --------------------------------------------------------------------------

def test_metric_change_higher_is_worse_positive_when_cur_above_base() -> None:
    check(abs(_metric_change(100.0, 120.0, True) - 0.2) < 1e-12, "h2w +20%")


def test_metric_change_higher_is_worse_negative_when_cur_below_base() -> None:
    # Lower cur is an improvement (negative change), not a regression.
    check(abs(_metric_change(100.0, 80.0, True) - (-0.2)) < 1e-12, "h2w -20%")


def test_metric_change_lower_is_worse_positive_when_cur_below_base() -> None:
    check(abs(_metric_change(100.0, 80.0, False) - 0.2) < 1e-12, "rps drop 20%")


def test_metric_change_lower_is_worse_negative_when_cur_above_base() -> None:
    check(abs(_metric_change(100.0, 120.0, False) - (-0.2)) < 1e-12, "rps gain 20%")


def test_metric_change_zero_base_is_never_a_regression() -> None:
    # A baseline of 0 cannot define a regression; the helper returns 0.
    check(_metric_change(0.0, 1000.0, True) == 0.0, "zero base h2w")
    check(_metric_change(0.0, 0.0, False) == 0.0, "zero base rps")


# --------------------------------------------------------------------------
# main() gate semantics
# --------------------------------------------------------------------------

def test_main_passes_when_within_tolerance() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {
            "h1/throughput": {"rps": 1000.0, "p99_ns": 200_000},
        })
        stdin = jline("h1", "throughput", rps=950.0, p99_ns=210_000) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base])
        check(code == PASS, f"within-10% must PASS, got {code}: {err}")
        check("PASS" in out, f"PASS banner present: {out!r}")


def test_main_fails_on_rps_regression() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {
            "h1/throughput": {"rps": 1000.0, "p99_ns": 200_000},
        })
        # rps dropped 30% (> 10% tolerance) -> regression.
        stdin = jline("h1", "throughput", rps=700.0, p99_ns=200_000) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base])
        check(code == FAIL, f"rps -30% must FAIL, got {code}: {err}")
        check("rps" in err and "REGRESSION" in out, f"regression reported: {err}|{out}")


def test_main_fails_on_p99_regression() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {
            "h2/throughput": {"rps": 1000.0, "p99_ns": 200_000},
        })
        # p99 grew 50% (> 10% tolerance) -> regression; rps unchanged.
        stdin = jline("h2", "throughput", rps=1000.0, p99_ns=300_000) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base])
        check(code == FAIL, f"p99 +50% must FAIL, got {code}: {err}")
        check("p99_ns" in err, f"p99 regression reported: {err}")


def test_main_hard_fails_on_errors_regardless_of_metrics() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {
            "h1/throughput": {"rps": 1000.0, "p99_ns": 200_000},
        })
        # rps and p99 are fine, but errors > 0 -> hard failure.
        stdin = jline("h1", "throughput", rps=1000.0, p99_ns=200_000, errors=5) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base])
        check(code == FAIL, f"errors>0 must FAIL, got {code}: {err}")
        check("errors" in err, f"error failure reported: {err}")


def test_main_fails_when_workload_missing_from_current_run() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {
            "h1/throughput": {"rps": 1000.0, "p99_ns": 200_000},
            "h1/pool-reuse": {"rps": 800.0, "p99_ns": 200_000},
        })
        # Only one of the two baseline workloads ran.
        stdin = jline("h1", "throughput", rps=1000.0, p99_ns=200_000) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base])
        check(code == FAIL, f"missing workload must FAIL, got {code}: {err}")
        check("pool-reuse" in err, f"missing workload named: {err}")


def test_main_passes_when_current_has_new_workload_absent_from_baseline() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {
            "h1/throughput": {"rps": 1000.0, "p99_ns": 200_000},
        })
        # Baseline lacks h2/throughput; a new workload is not a regression.
        stdin = (
            jline("h1", "throughput", rps=1000.0, p99_ns=200_000) + "\n"
            + jline("h2", "throughput", rps=500.0, p99_ns=400_000) + "\n"
        )
        code, out, err = run_main(stdin, ["--baseline", base])
        check(code == PASS, f"new workload must not FAIL, got {code}: {err}")


def test_main_missing_baseline_file_exits_usage() -> None:
    stdin = jline("h1", "throughput") + "\n"
    code, out, err = run_main(stdin, ["--baseline", "/nonexistent/baseline.json"])
    check(code == USAGE, f"missing baseline must exit 2, got {code}: {err}")
    check("not found" in err, f"not-found message: {err}")


def test_main_malformed_baseline_exits_usage() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        with open(base, "w", encoding="utf-8") as f:
            f.write("{not valid json")
        stdin = jline("h1", "throughput") + "\n"
        code, out, err = run_main(stdin, ["--baseline", base])
        check(code == USAGE, f"malformed baseline must exit 2, got {code}: {err}")
        check("not valid JSON" in err, f"malformed message: {err}")


def test_main_empty_stdin_exits_usage() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {"h1/throughput": {"rps": 1000.0, "p99_ns": 200_000}})
        code, out, err = run_main("", ["--baseline", base])
        check(code == USAGE, f"no JSON lines must exit 2, got {code}: {err}")
        check("no JSON" in err, f"no-json message: {err}")


def test_main_write_requires_force() -> None:
    with tempfile.TemporaryDirectory() as d:
        out_path = os.path.join(d, "new-baseline.json")
        code, out, err = run_main(jline("h1", "throughput") + "\n",
                                  ["--write", out_path, "--machine", "x"])
        check(code == USAGE, f"--write without --force must exit 2, got {code}: {err}")
        check("--force" in err, f"force hint: {err}")
        check(not os.path.exists(out_path), "must not write without --force")


def test_main_write_requires_machine() -> None:
    with tempfile.TemporaryDirectory() as d:
        out_path = os.path.join(d, "new-baseline.json")
        code, out, err = run_main(jline("h1", "throughput") + "\n",
                                  ["--write", out_path, "--force"])
        check(code == USAGE, f"--write without --machine must exit 2, got {code}: {err}")
        check("--machine" in err, f"machine hint: {err}")
        check(not os.path.exists(out_path), "must not write without --machine")


def test_main_write_produces_baseline_with_meta() -> None:
    with tempfile.TemporaryDirectory() as d:
        out_path = os.path.join(d, "new-baseline.json")
        stdin = (
            jline("h1", "throughput", rps=123.0) + "\n"
            + jline("h2", "pool-reuse", rps=456.0) + "\n"
        )
        code, out, err = run_main(stdin, ["--write", out_path, "--force",
                                          "--machine", "ci-runner-1"])
        check(code == PASS, f"--write must succeed, got {code}: {err}")
        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
        check(data["meta"]["machine"] == "ci-runner-1", f"meta.machine: {data['meta']}")
        check(set(data["workloads"].keys()) == {"h1/throughput", "h2/pool-reuse"},
              f"workloads: {set(data['workloads'].keys())}")


def test_main_expect_machine_mismatch_skips_fail_open() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {"h1/throughput": {"rps": 1000.0, "p99_ns": 200_000}},
                       meta={"machine": "dev-local"})
        # Catastrophic regression, but machine mismatch -> skip (exit 0).
        stdin = jline("h1", "throughput", rps=1.0, p99_ns=10_000_000) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base,
                                          "--expect-machine", "ci-runner-1"])
        check(code == PASS, f"machine mismatch must SKIP (exit 0), got {code}: {err}")
        check("SKIP" in out, f"skip banner: {out}")


def test_main_expect_machine_match_runs_comparison() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {"h1/throughput": {"rps": 1000.0, "p99_ns": 200_000}},
                       meta={"machine": "ci-runner-1"})
        # Same machine -> comparison runs; a 30% rps drop is a regression.
        stdin = jline("h1", "throughput", rps=700.0, p99_ns=200_000) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base,
                                          "--expect-machine", "ci-runner-1"])
        check(code == FAIL, f"matching machine must compare, got {code}: {err}")


def test_main_custom_tolerance_widens_the_gate() -> None:
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {"h1/throughput": {"rps": 1000.0, "p99_ns": 200_000}})
        # 20% rps drop: fails at 10% tolerance, passes at 30%.
        stdin = jline("h1", "throughput", rps=800.0, p99_ns=200_000) + "\n"
        code_strict, _, _ = run_main(stdin, ["--baseline", base, "--tolerance", "0.10"])
        code_wide, _, _ = run_main(stdin, ["--baseline", base, "--tolerance", "0.30"])
        check(code_strict == FAIL, "20% drop must FAIL at 10% tolerance")
        check(code_wide == PASS, "20% drop must PASS at 30% tolerance")


def test_main_baseline_without_meta_machine_skips_with_empty_label() -> None:
    # A baseline with no meta.machine at all: --expect-machine with any
    # label must still skip (None != label), never crash.
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "baseline.json")
        write_baseline(base, {"h1/throughput": {"rps": 1000.0, "p99_ns": 200_000}})
        stdin = jline("h1", "throughput", rps=1.0) + "\n"
        code, out, err = run_main(stdin, ["--baseline", base,
                                          "--expect-machine", "any-runner"])
        check(code == PASS, f"missing meta.machine must skip, got {code}: {err}")


TESTS = [
    test_parse_json_lines_collects_by_protocol_workload,
    test_parse_json_lines_ignores_non_json_lines,
    test_parse_json_lines_skips_malformed_json,
    test_parse_json_lines_skips_missing_protocol_or_workload,
    test_parse_json_lines_empty_stream_yields_empty_dict,
    test_metric_change_higher_is_worse_positive_when_cur_above_base,
    test_metric_change_higher_is_worse_negative_when_cur_below_base,
    test_metric_change_lower_is_worse_positive_when_cur_below_base,
    test_metric_change_lower_is_worse_negative_when_cur_above_base,
    test_metric_change_zero_base_is_never_a_regression,
    test_main_passes_when_within_tolerance,
    test_main_fails_on_rps_regression,
    test_main_fails_on_p99_regression,
    test_main_hard_fails_on_errors_regardless_of_metrics,
    test_main_fails_when_workload_missing_from_current_run,
    test_main_passes_when_current_has_new_workload_absent_from_baseline,
    test_main_missing_baseline_file_exits_usage,
    test_main_malformed_baseline_exits_usage,
    test_main_empty_stdin_exits_usage,
    test_main_write_requires_force,
    test_main_write_requires_machine,
    test_main_write_produces_baseline_with_meta,
    test_main_expect_machine_mismatch_skips_fail_open,
    test_main_expect_machine_match_runs_comparison,
    test_main_custom_tolerance_widens_the_gate,
    test_main_baseline_without_meta_machine_skips_with_empty_label,
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
    print(f"\n{passed}/{len(TESTS)} bench-regression tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main_test())
