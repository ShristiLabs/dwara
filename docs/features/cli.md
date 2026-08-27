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
dependency-free HTTP/1.1 load generator — no `wrk`/`k6` dependency —
used by `scripts/bench-macro.sh` and `bench.yml`'s macro job to measure
gateway throughput and latency end-to-end. One worker task owns one
persistent `hyper` connection (no pool) and issues back-to-back
requests, recording latency into a hand-rolled sorted-`Vec` histogram
rather than pulling in `hdrhistogram` — percentiles at these sample
counts are a cheap sort away, so the extra dependency wasn't worth it
for a benchmarking-only tool. `--rate 0` (default) is unbounded, each
connection goes as fast as it can; a positive rate is a global target
dispensed as tokens by a pacing task, shared fairly-but-not-exactly
across workers. `--echo PORT` can start a minimal echo server in the
same process, so the rig needs no external upstream to smoke-test
itself. Output ends with a machine-parseable `RESULT:` line so CI can
assert `errors=0` without scraping human-formatted text.
