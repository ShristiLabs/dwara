# CLI

Source: `crates/dwara-cli/src/{lib,main,loadgen}.rs` (DW-022, DW-024).
Tests: `cli`, `loadgen_e2e`, `loadgen_unit` (dwara-cli).

The end-user-facing material (each subcommand's behavior and exit
codes) is already written at
[docs-site: CLI](../../docs-site/guide/cli.md) — this page focuses on
implementation: why the CLI is structured as a thin binary over a
library, and how each subcommand reuses the same pipeline the gateway
itself runs.

## Library-shaped by design

`dwara-cli`'s logic lives in its `lib.rs`, kept as "the pure halves of
the subcommands" specifically so tests (and any future caller — the
admin API, a future TUI) exercise exactly what the binary runs, rather
than a reimplementation. `main.rs` is thin argument parsing and I/O
around that library. This is the same principle behind
`dwara-core`'s split of `snapshot::validate`/`compile` (pure) from
`compile_and_publish` (effectful) — see
[Architecture: the config lifecycle](../architecture.md#the-config-lifecycle)
— applied one layer up, at the CLI boundary.

## One pipeline, four consumers

`validate`, `fmt`, `diff`, and `lint` are all different views over the
*same* `snapshot::validate`/`compile` pipeline the gateway runs at
startup, on reload, and via the admin API's `PATCH /config`:

```mermaid
flowchart TD
    Y[YAML file(s)] --> P[parse_gateway]
    P --> V[snapshot::validate]
    V --> C[snapshot::compile]
    C --> Validate[validate: print all issues,\nexit 0/1]
    C --> Fmt[fmt: re-serialize\nstable order, exit 0/1]
    C --> Diff[diff: per-entity content hash,\n+/-/~ deltas]
    C --> Lint[lint: advisory rules over\nthe COMPILED Snapshot]
    C --> Schema[schema: JSON Schema\nof the Gateway type]
```

This is the same design intent as `PATCH /config` reusing the
dataplane's pipeline (see
[Admin API](./admin-api.md#patch-config-dry-run-then-atomic-write-reusing-one-pipeline)):
a config that `dwara-cli validate` accepts is *guaranteed* to be a
config the gateway would accept at startup, because it's not a
separate reimplementation that could drift — it's a call into the same
code.

## Exit-code contract is load-bearing

`validate`'s and `lint`'s exit codes are documented as a stable
contract because scripts depend on them:

- `validate`: 0 = valid; 1 = any schema/parse/validation/compile
  issue. All issues print, never fail-fast on the first one — an
  operator fixing a config wants the whole list in one pass, not a
  whack-a-mole loop of "fix one, rerun, find the next."
- `lint`: 0 = clean; **2** = advisory warnings found; 1 = the file
  couldn't even be parsed/validated. The distinct `2` (rather than
  reusing `1`) exists so a CI script can tell "your config is broken"
  apart from "your config works but smells" — `if dwara-cli lint
  config.yaml; then ...` behaves differently for warnings vs. hard
  failures only because these are different exit codes.

## `run` spawns the binary, it doesn't embed it

`run` shells out to the `dwara` binary on `PATH` with arguments and
environment passed straight through, rather than embedding the
gateway server inside the CLI process. This keeps `dwara-cli`'s own
dependency tree — and its release binary size — decoupled from
`dwara-bin`'s: the CLI doesn't need `hyper`'s server feature, TLS
material handling, or any of the listener/reload machinery just to
offer a `run` convenience wrapper, and a change to the gateway's
startup internals can never accidentally change what `dwara-cli run`
does (it's just an exec).

## `diff`: content hash, not structural YAML diff

`diff` compiles both configs and compares by the same per-entity
content hash described in
[Architecture: the config lifecycle](../architecture.md#the-config-lifecycle)
(a `SipHash-1-3` over the normalized serialization) rather than
diffing the raw YAML text or a generic structural diff of the parsed
value. This is what makes reordering keys in a source file a
non-event: two configs that mean the same thing byte-for-byte after
normalization hash identically, so `diff` reports "no differences"
even if a human reformatted the file, while a real semantic change
(different endpoint weight, different timeout) always shows up as a
`~` delta regardless of where in the file it happens to sit.

## `lint`: advisory rules over the compiled snapshot, not the raw YAML

Lint rules (`prefix-duplicate`, `regex-shadowed-by-exact`,
`consumer-unused`, `policy-unused`, `upstream-unreferenced`) run
against the already-*compiled* `Snapshot`, not the source YAML —
because several of them (shadowed routes, unreferenced upstreams) are
only knowable once route tables and references are actually resolved,
the same information the gateway itself uses at request time. This is
why `lint` requires a config that parses and validates first (exit 1
if it doesn't): linting an unvalidated config would mean guessing at
structure that validation would otherwise guarantee exists, and "your
config is invalid" noise would drown out the advisory findings that
are actually useful.

## The load generator rig

`dwara_cli::loadgen` (behind the thin `dwara-loadgen` binary) is a
dependency-free load generator — no `wrk`/`k6` dependency — used by
`scripts/bench-macro.sh`, `scripts/bench-regression.sh`, and the
`bench*.yml` workflows to measure gateway throughput and latency
end-to-end (PERF-06, #171). It drives three wire protocols and three
macro workloads, selected with `--protocol` and `--workload`:

- **Protocols:** `h1` (default; one worker per persistent HTTP/1.1
  connection, no pool), `h2` (h2c prior-knowledge over cleartext, one
  persistent HTTP/2 connection per worker with multiplexed streams),
  and `h3` (QUIC + h3, one QUIC connection per worker, one
  bidirectional stream per request). `h3` is feature-gated behind the
  default-off `h3` cargo feature on `dwara-cli` and has no in-process
  echo upstream — `--echo` is rejected with `--protocol h3`, so it must
  point at a real h3 listener (a gateway `protocol: h3` listener);
  `--insecure` skips certificate verification for loopback targets.
- **Workloads:** `throughput` (default; owned persistent connection,
  back-to-back requests against a fixed-body echo, raw max throughput),
  `pool-reuse` (a shared pooled client — hyper-util legacy for h1/h2,
  one shared QUIC connection for h3 — exercises client-side
  connection/stream reuse and the gateway's upstream pool), and
  `streaming` (owned persistent connection against a chunked echo that
  emits `--stream-chunks` chunks of `--stream-chunk-bytes` bytes with
  `--stream-chunk-delay-ms` between chunks; the client drains the full
  body, so latency includes body completion).

Latency is recorded into a hand-rolled sorted-`Vec` histogram rather
than pulling in `hdrhistogram` — percentiles at these sample counts are
a cheap sort away, and the vector is subsampled once it reaches a cap so
memory stays bounded for long runs. `--rate 0` (default) is unbounded,
each connection goes as fast as it can; a positive rate is a global
target dispensed as tokens by a pacing task, shared fairly-but-not-exactly
across workers. `--echo PORT` can start a minimal echo server in the
same process, so the rig needs no external upstream to smoke-test
itself. Output ends with a machine-parseable `RESULT:` line so CI can
assert `errors=0` without scraping human-formatted text; with `--json`,
an additional `JSON:` line carries the same metrics plus the
protocol/workload labels, consumed by the regression gate
(`scripts/bench-regression.py`).

## The macro regression harness

`scripts/bench-regression.sh` boots the real `dwara` gateway against an
in-process echo upstream (`dwara-loadgen --echo-only`) and drives the
full client -> gateway -> upstream -> gateway -> client path across the
h1/h2 protocols and the throughput/pool-reuse/streaming workloads,
emitting one `JSON:` line per workload on stdout (the human table goes
to stderr so stdout stays a clean stream for the gate). h3 is opt-in via
`DWARA_BENCH_H3_URL` because h3 is feature-gated and needs a TLS/QUIC
listener the plain rig does not provision. `scripts/bench-regression.py`
compares the JSON output against a checked-in macro baseline
(`scripts/bench-macro-baseline.json`) at a 10% default tolerance and
fails-open across machine classes (mirroring the micro-benchmark gate):
the checked-in baseline is a dev-machine reference, so the gate SKIPs
with a notice until a CI-runner baseline is captured once via the
`baseline-refresh` dispatch. `.github/workflows/bench-nightly.yml` runs
the macro gate nightly (best-of-3 runs to shed a single noisy sample,
30% tolerance for CI noise) plus an `h3-compile` job that guards
feature rot on the default-off h3 feature; h3 throughput is not in the
nightly macro-gate (no TLS/QUIC listener rig). `scripts/bench-macro.sh`
gains `BENCH_PROTOCOL`/`BENCH_WORKLOAD`/`BENCH_JSON` passthrough vars
for single-workload runs.

## The soak harness

`scripts/soak.sh` (#174, REL-03) is the sustained-load counterpart to
the macro regression harness: it boots the real `dwara` gateway against
an in-process echo upstream (`dwara-loadgen --echo-only`) using the same
spawn/readiness pattern as `scripts/bench-regression.sh` (one cleartext
listener that speaks both HTTP/1.1 and h2c, one route to the echo
upstream, `/healthz` readiness probe), then drives SUSTAINED load in
fixed-width windows rather than a single timed run. After each window
it samples the gateway's RSS (KB, via `ps -o rss=`) and records the
window's p99 from the loadgen `JSON:` line, emitting one `SAMPLE:`
line per window on stdout (human progress goes to stderr, keeping
stdout a clean stream for the gate).

`scripts/soak.py` is the assertion gate: it reads the `SAMPLE:` stream
and fails (exit 1) when either ceiling is breached:

- **RSS ceiling** — max sampled RSS > `SOAK_RSS_CEILING_KB` (default
  262144 = 256MB), the memory-leak bar.
- **p99 drift** — the late-window p99 grew beyond `SOAK_P99_DRIFT`
  (default 0.50 = 50%) relative to the early-window baseline. Drift is
  the fractional growth from the EARLY baseline (mean p99 of the first
  quarter of windows) to the LATE tail (mean p99 of the last quarter);
  the windowed mean sheds single-sample noise and the 50% default is
  generous for shared CI runners but catches the steady growth a leak
  causes.
- **Errors** — a window with `errors > 0` is a hard failure regardless
  of metrics (the soak did not run cleanly, so RSS/latency numbers are
  not trustworthy).

Absolute RSS and latency are machine- and load-dependent; the ceilings
are operational bars, not regression baselines — the like-for-like
comparison is the macro regression gate's job
(`scripts/bench-regression.py`). Everything is configurable via env
vars: `SOAK_DURATION` (total seconds, default 600), `SOAK_RATE` (target
rps, 0 = unbounded, default 1000), `SOAK_CONNECTIONS` (default 50),
`SOAK_SAMPLE_SECS` (per-window seconds, default 30),
`SOAK_RSS_CEILING_KB`, `SOAK_P99_DRIFT`, plus `SOAK_GATEWAY_PORT`,
`SOAK_ECHO_PORT`, `SOAK_PROTOCOL` (h1|h2), and `SOAK_WORKLOAD`
(throughput|pool-reuse|streaming).

### CI posture

The soak runs in a SEPARATE CI job
(`.github/workflows/soak.yml`) that is scheduled nightly (06:13 UTC)
and manually dispatchable only — no push/pull_request triggers, because
sustained load for several minutes is slower and noisier than the
per-PR gate (`ci.yml`) and the macro regression gate
(`bench-nightly.yml`): a slow memory leak or latency drift only shows
under sustained load. The schedule is offset from `bench-nightly`
(04:17 UTC) and `chaos` (Wed 05:11 UTC) so the three never contend for
runners. The nightly CI duration stays short (10 min) to bound runner
cost; the 24h soak referenced in the issue runs on DEDICATED HOSTS via
dispatch with `SOAK_DURATION=86400` (and a raised workflow timeout and
RSS ceiling) ahead of a release — the assertions are the same either
way. This is the ASSERTING soak, complementary to `bench.yml`'s
separate manual-only 24h soak (#127, which runs
`scripts/bench-macro.sh 86400 100` with NO assertions) and distinct
from the chaos suite (#173).
