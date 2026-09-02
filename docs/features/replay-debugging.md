# Replay debugging (DW-102)

> Implements issue DW-102 (M2, `edition/oss`, effort M) over the
> decision-path observability surface. Sources:
> `crates/dwara-core/src/dataplane/replay.rs` (the pure-decide
> replayer, the simulated rate-limit counter, the diff logic -- its
> module docs carry the full contract), `crates/dwara-cli/src/replay.rs`
> (the CLI library half: recording parsing, the replay runner, the
> report renderer, the exit-code contract), validation in
> `snapshot/mod.rs`. Tests:
> `crates/dwara-core/tests/replay.rs` (route matching, authz verdicts,
> rate-limit simulation, transform summaries, upstream picks, diff
> detection across two config generations, the simulated counter's
> window-reset and key-independence behavior). Operator docs:
> [docs-site CLI guide](../../docs-site/guide/cli.md).

The gateway's request path (`dataplane::proxy`) weaves together route
matching, authorization, rate limiting, transforms, and endpoint
selection with live I/O (upstream dials, live GCRA counters, breaker
state). Replay inverts that: given a captured request and a
`Snapshot` (a compiled config generation), it re-runs the SAME decision
logic with NO side effects -- no network, no live counters, no breaker
state -- so an operator can ask "what would this recorded request do
under THIS config?" and diff the answer across two generations. The
result is a time-travel debugging tool and a CI gate for config
changes.

## The pure-decide replayer

`decide` is the pure core: it reads only its inputs (`&Snapshot`,
`&ReplayRequest`) and a caller-supplied `SimulatedCounter` for the
rate-limit simulation. It never touches the network, the filesystem,
the live rate limiter, or any shared mutable gateway state. The five
stages mirror the live proxy's decision path:

1. **Route matching** -- the snapshot's `RouteTable.find_full` returns
   the route index and path params (same precedence as `proxy.rs`:
   exact, regex, longest prefix). A miss returns a decision with every
   stage as `None` (the live proxy would answer 404).
2. **Authorization** -- `evaluate_authz` builds a minimal `Identity`
   from the captured auth identity and the config consumer record
   (groups come from config; replay has no store-managed consumers).
   The effective IP is the loopback (replay has no real peer; IP ACLs
   are reported against 127.0.0.1, the honest "no network" stand-in).
   The chain is consumer, route, service, global (listener-level is
   transparent, no listener context).
3. **Rate-limit simulation** -- `evaluate_rate_limit` resolves the
   applicable policies (consumer, route, service, global) and
   simulates each rule's windows against the `SimulatedCounter`. A
   request is admitted only if EVERY window of EVERY applicable rule
   allows it (the live AND-composition). Dry-run bundles report `true`
   (they never enforce).
4. **Transform resolution** -- `summarize_transforms` reports counts of
   header/query/body ops (not full op lists, to keep the diff output
   stable across unrelated key-order changes).
5. **Upstream pick** -- `pick_upstream` resolves the upstream's first
   endpoint (deterministic; replay has no live health state, so
   load-balancer selection is reported as the resolved upstream name
   plus its first endpoint) and the path-rewrite label.

Stages after a miss are still reported when they can be computed
without side effects -- an operator diffing two configs wants to see
"authz now denies" even when the live proxy would have stopped there,
so the diff surfaces the full picture.

## Request capture

The request detail (method, path, redacted headers, auth identity) is
captured by the analytics raw table (DW-043, extended in DW-102 with
optional `request_headers_redacted` and `auth_identity` columns). The
capture is opt-in and redacted via the existing PII redaction patterns
(`ai::redaction`); replay never sees raw secrets. The replay CLI reads
those rows (or an exported recording) and feeds them to `decide`.

## The CLI replay command

The `dwara replay` subcommand is the operator surface. Its library half
lives in `crates/dwara-cli/src/replay.rs` (kept library-shaped so tests
exercise exactly what the binary runs). A recording is a JSON document
exported from the analytics store (or authored by hand for test
fixtures):

```json
{
  "baseline_config": "<baseline YAML string>",
  "requests": [
    {
      "method": "GET",
      "path": "/api/foo",
      "headers": [["x-plan", "pro"]],
      "auth_identity": "alice",
      "timestamp_ms": 1700000000000
    }
  ]
}
```

The `baseline_config` is the config the requests were captured under;
`--config` is the candidate (new) config. `run_replay` loads the
recording, compiles both configs into snapshots, runs `decide` for each
request under both, and diffs. Each request gets its OWN simulated
counter: replay answers "what would THIS request do under THIS config?"
not "what would a burst of these do?" -- the per-request decision
boundary is what a diff cares about, and sharing a counter across
requests would make the rate-limit verdict depend on recording order.

The exit-code contract is deliberate:

- **0** = no decision diffs (the candidate config behaves identically
  to the baseline for every recorded request).
- **1** = diffs found (useful as a CI gate: a config change that
  alters routing, authz, rate-limit, transform, or upstream decisions
  for recorded traffic is surfaced before deploy).
- **2** = the recording or a config could not be loaded (operator
  error, distinct from a clean diff).

## Diffing

`DecisionDiff::compare` reports which stages changed between two
`ReplayDecision`s: `route_changed`, `authz_changed`,
`rate_limit_changed`, `transform_changed`, `upstream_changed`. `any()`
is the CI-gate signal; `summary()` is the one-line human-readable
report the CLI emits per request. The diff is the unit a CI gate exits
non-zero on.

The [analytics](./analytics.md) page covers the raw capture table this
feature reads from; the [CLI](./cli.md) page covers the operator
commands.
