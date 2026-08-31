# Resilience: health, retries, circuit breaking, load shedding

Source: `crates/dwara-core/src/resilience/{health,retries,breaker}.rs`
(DW-012, DW-014, DW-015), `dataplane/balance.rs` (DW-011, load
shedding lives on the gateway-cap path documented in
[Architecture](../architecture.md)). Tests: `passive_health`,
`active_health`, `retries_timeouts`, `breaker_caps`, `load_shedding`
(dwara-core).

Three layers gate traffic to a struggling upstream, at three different
granularities, and it's the composition — not any one layer — that
matters most to understand:

```mermaid
flowchart TD
    subgraph Endpoint layer
        H[Passive health\nper-endpoint ejection]
        AH[Active health\nsynthetic probes]
    end
    subgraph Upstream layer
        B[Circuit breaker\nper-upstream, all-or-nothing]
    end
    R[Retry loop] --> H
    B -->|closed: proceed| R
    B -->|open: fail fast, no pick| X1[503 immediately]
    H -->|endpoint ejected| H2[balancer skips it]
    H -->|all ejected| FO[fail-open: pick anyway]
```

A breaker-open period short-circuits **before** the balancer is
consulted at all, so it ejects nothing at the endpoint layer (passive
health never even sees the traffic it isn't sending). Conversely,
endpoint ejections never open the breaker on their own — the breaker
only reacts to the aggregate outcome stream flowing through it. The
two layers observe overlapping signals but never consume each other's
state.

## Passive health / outlier detection

Passive health watches **real traffic outcomes** — there is no
synthetic probing while an endpoint is serving. Every dispatched
request's outcome is classified when its response headers resolve (or
on a transport error) and reported to the picked endpoint's tracker.
The load balancer consults that tracker on every pick (lock-free,
atomics only) and skips ejected endpoints.

**Outcome classification:** transport errors (connect timeout,
refused, reset, client framing errors) and HTTP status ≥ 500 are
failures; everything 1xx–4xx is a success. Notably, **429 and 408 are
successes** — they describe caller or queueing pressure, not the
endpoint's own health, and ejecting an endpoint for returning 429 would
remove capacity at exactly the moment backpressure is needed.

**Ejection triggers on either:**

- `consecutive_failures` (default 5) failures in a row, regardless of
  volume, or
- a rolling `window_ms` (default 60s) failure ratio ≥ `failure_ratio`
  (default 0.5), gated by a minimum `failure_min_volume` (default 20)
  observations — the volume gate exists specifically so a 2-of-3 blip
  on low traffic can't eject an endpoint that's actually fine.

**Recovery is half-open:** after `eject_ms` (default 30s), the next
pick admits `half_open_probes` (default 1) trial requests; a success
restores health and clears failure history (so old failures can't
immediately re-eject it); a failure re-ejects for another full
`eject_ms`.

**Fail-open:** if every endpoint of an upstream is ejected, picks fall
back to the full set rather than blackholing traffic — a deliberate
choice, because a gateway that returns 503 for a fully-ejected pool has
converted an upstream brownout into a guaranteed outage. The balancer
counts these fallback picks (`upstream_fail_open_picks` metric) so the
degraded state is still visible.

## Active health

Active probes report through the same tracker via a separate entry
point (`report_probe`) that drives the same ejection/recovery state
machine **without** inserting an observation into the rolling window —
synthetic probe outcomes never mix into the real-traffic failure
ratio. This keeps "how often is this endpoint actually failing real
requests" and "did the last synthetic probe succeed" as two inputs to
one state machine rather than one blended, harder-to-reason-about
signal.

## Retries

All retry knobs live on the **upstream** (`upstreams[].retries`) — v1
has no per-route override, keeping "how much should we retry against
this backend" a property of the backend, not of every route that
happens to target it.

**Retry budget:** each upstream owns a rolling 10-second window of
`(timestamp, is_retry)` events. A retry is permitted only while
`(retries + 1) * 100 <= percent * totals` holds, checked and reserved
atomically under one lock so the invariant is never transiently
violated by concurrent requests. Charging the retry **before** it
happens is a deliberately conservative bias: a fresh window with low
volume grants few or no retries rather than allowing a burst — the
budget exists to protect an upstream that's already struggling, so it
errs toward under- rather than over-granting.

**Backoff:** nominal delay before retry *n* is
`min(base * 2^(n-1), cap)`; the actual sleep applies **full jitter**
(AWS-style — a uniform random draw from `[0, nominal]`), which avoids
the thundering-herd resynchronization that decorrelated jitter can
produce while still bounding the worst case by the nominal delay.

**No cross-attempt deadline in v1:** worst case, a retry loop adds up
to `attempts * (read_ms + backoff_cap_ms)` to one request's total
latency — there is no overall budget that trims a chain of retries
short of exhausting all of them.

## Request hedging (DW-063)

Hedging sends a **speculative duplicate** request to a different
endpoint after a tail-latency threshold, racing the primary and the
hedge copy; the first response (headers resolved) wins and the loser is
cancelled. This cuts p99 latency at the cost of bounded extra upstream
load — the hedge only fires when the primary is already slower than
expected, and at most `hedge_max` copies (default 1) are sent per
request.

```yaml
upstreams:
  - name: up
    endpoints:
      - address: 127.0.0.1
        port: 8080
      - address: 127.0.0.1
        port: 8081
    retries:
      buffer_max_bytes: 65536
      hedge:
        hedge_after_ms: 50
        hedge_max: 1
```

**How it works:**

1. The primary request is sent to the load balancer's pick.
2. A timer fires after `hedge_after_ms`. If the primary has already
   resolved (success or error), no hedge is sent.
3. If the timer fires first, up to `hedge_max` hedge copies are spawned
   (each to an independently-picked endpoint) and raced against the
   primary in a `JoinSet`.
4. The first `Ok` (headers resolved) wins; the remaining tasks are
   aborted. If all hedges error, the primary is awaited directly.

**Requirements and constraints:**

- **Replayable body:** hedging requires `buffer_max_bytes > 0` so the
  request body can be replayed to the hedge copy. Over-cap bodies that
  can't be buffered disable hedging for that request (the primary
  streams normally, no hedge).
- **Idempotent methods only:** GET, HEAD, OPTIONS, TRACE, PUT are
  hedged unconditionally; POST is hedged only when `retry_post` is also
  true (the same semantics as retries — a hedge is a replay, and
  replaying a non-idempotent side-effecting request is unsafe).
- **Not charged against the retry budget:** the budget prevents retry
  storms after failures; hedging is a proactive performance
  optimization that runs on every slow request. The `hedge_max` config
  alone bounds the amplification factor.
- **First attempt only:** hedging runs on the initial attempt
  (`done_tries == 0`). Retried attempts (after a failure) do not hedge
  — a retry is already a second chance, and hedging a retry would
  compound the amplification.

**Validation:**

- `hedge_after_ms` must be in `[1, MAX_HEDGE_AFTER_MS]` (default upper
  bound 60000ms).
- `hedge_max` must be in `[1, MAX_HEDGE_COPIES]` (default upper bound 4).
- A `hedge` block with `buffer_max_bytes == 0` is rejected — hedging
  requires a replayable body.

**Metric:** `dwara_hedge_sent_total{upstream}` counts every hedge copy
sent (not every hedged request) — use it to monitor the extra load
hedging generates.

## Circuit breaking

The breaker gates an **entire upstream** (not one endpoint) when it's
failing as a whole:

- **Closed** (healthy): failures are counted two ways at once — a
  consecutive-failure streak and a rolling 60s error ratio. Either trip
  condition (streak ≥ `consecutive_failures`, default 5; or window
  holds ≥ `error_volume` observations, default 20, with
  `failures/observations >= error_ratio`, default 0.5) opens the
  breaker.
- **Open**: every request to the upstream fails fast with `503` and a
  `Retry-After` header (whole seconds until half-open, minimum 1) — no
  endpoint pick, no retries, nothing reaches the network. Requests
  already in flight when the breaker opened are left to complete
  normally.
- **Half-open**: after `open_ms` (default 30000ms) the next request(s)
  (up to `half_open_probes`, default 1, concurrently) are admitted as
  trial probes. One success closes the breaker (all counters and the
  window reset); a failure re-opens it for another `open_ms`. A
  retried request consumes one probe slot **per attempt** — each
  attempt is its own trial.

Failure classification for the breaker is deliberately identical to
passive health's (transport errors and ≥500 are failures; 1xx–4xx are
successes) specifically so operators reason about one notion of
"failure" across both layers instead of two subtly different ones. A
mid-body abort after headers already resolved does not open the
breaker — the exchange was already classified at header time (though
it's still reported to endpoint health, closing the same gap discussed
in [dataplane-proxy](./dataplane-proxy.md#upstream-error-classification)).

Breaker timing is wall-clock (`SystemTime`), so an NTP step can
lengthen or shorten an Open period in principle — a documented, not
"fixed," tradeoff.

## Load shedding

The gateway-wide `max_concurrent_requests` cap (see
[Configuration: global settings](../../docs-site/guide/configuration.md#global-settings))
is priority-aware: a route's `priority` (0–10, default 5) determines
which requests get shed first once the cap is under pressure. This
runs in the request pipeline **after** rate limiting and **before**
the circuit breaker — see the docs-site
[architecture overview](../../docs-site/architecture/overview.md#request-pipeline) for
exactly where it sits relative to every other stage.

`gateway.load_shed_dry_run` (DW-041) previews the cap before
enforcing it: a would-shed is admitted over the cap and reported
(`dwara_policy_dry_run_total{phase="load_shed"}` plus a
`dwara::policy` warn event) instead of 503'd — the shed counters stay
untouched, since the request was admitted, not shed. See
[maintenance mode and policy dry-run](./maintenance-dry-run.md).

## Config reload semantics

Breaker state (current state, failure streak, rolling window) and the
retry budget both survive a config reload, keyed by upstream name —
exactly like the load balancer's own endpoint state (see
[load balancing](./load-balancing.md)). The intent across all three is
the same: a reload changes *policy* (what the rules are) without
resetting *observed reality* (what's actually been happening to this
upstream), so a reload can never be used to "launder" a struggling
upstream back to a clean slate.

## Mirroring and fault injection (DW-062)

Two route-scoped features for traffic testing that sit at the start of
the proxy action, before any upstream contact:

### Shadow traffic mirroring (`routes[].mirror`)

Fire-and-forget duplicate requests to a named mirror upstream. The
mirror response is discarded and the task is detached — it never
impacts the primary request's latency. A percentage controls sampling
(0 = never, 100 = always).

```yaml
routes:
  - name: api
    service: svc
    match: { path: { type: prefix, value: /api } }
    action: { type: proxy }
    mirror:
      upstream: shadow-upstream
      percentage: 10   # 10% of requests are mirrored
```

For v1, the mirror carries the request shape (method, path, headers)
but an empty body — this avoids body buffering entirely and has truly
zero latency impact. The mirror upstream must exist in the `upstreams`
list. The `dwara_mirror_sent_total{upstream}` counter tracks mirror
copies sent.

### Fault injection (`routes[].fault_injection`)

Percentage-based delays and aborts for chaos testing:

```yaml
routes:
  - name: api
    service: svc
    match: { path: { type: prefix, value: /api } }
    action: { type: proxy }
    fault_injection:
      abort:
        percentage: 5
        status: 503       # 5% of requests get a 503
      delay:
        percentage: 10
        fixed_ms: 500     # 10% of requests get a 500ms delay
```

- **Abort** short-circuits with the configured HTTP status (100-599)
  without contacting the upstream. The abort is evaluated first; if it
  does not fire, the delay is applied.
- **Delay** injects a fixed latency (1-300000ms) before the request is
  forwarded. The request still succeeds (the delay is not an abort).
- Both are sampled by percentage (a random draw per request).
- An aborted request is never mirrored (the abort runs before the
  mirror spawn).
- An empty `fault_injection` block (no `abort` and no `delay`) is
  rejected by validation — omit the block instead.
