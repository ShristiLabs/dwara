# Traffic splitting and sticky sessions (DW-040)

> Implements issue DW-040 (M2, `edition/oss`, effort M) over the
> load-balancing foundation shipped by DW-011. Sources:
> `crates/dwara-core/src/dataplane/split.rs` (the stateless weighted
> pick, the cookie reader, the affinity-handle minter — its module
> docs carry the full contract), the dispatch arm in
> `dataplane/proxy.rs` (sticky-key resolution BEFORE the pick, the
> `dispatch_hash_key` rule that threads the cookie value into the
> branch's balancer, the `Set-Cookie` append on the success path),
> the compiled split accessor in `dataplane/upstream.rs`
> (`UpstreamRegistry::split_for`), validation in `snapshot/mod.rs`
> (the exactly-one-of `upstream`/`split` rule, the 2..=8 target and
> weight bounds, the cookie-name token check), and the config types
> in `config/mod.rs` (`Service::split`, `Service::sticky`,
> `ServiceSplit`, `SplitTarget`, `StickyAffinity`). Tests:
> `crates/dwara-core/tests/canary.rs` (end to end: 60/40 over 2000
> requests within a +-3pp band, sticky pinning across 40 requests
> AND a reload, cookie minted on first response with `Max-Age` and
> never re-set, blue-green 100/0 -> 0/100 by republish moving all
> traffic with no restart) and `crates/dwara-core/tests/unit/split.rs`
> (cookie reader, mint uniqueness, the validation matrix, pick
> stability, zero-weight parking, distribution over 5000 keys via
> the public registry). Operator docs:
> [docs-site Traffic splitting guide](../../docs-site/guide/traffic-splitting.md).

DW-011 gave every upstream its own balancer (four algorithms over one
endpoint set). DW-040 adds the layer ABOVE that: a service can dispatch
across several upstreams by a weighted pick, and a session can be pinned
to its branch (and, when the branch runs `ip_hash`, to one endpoint
inside it) by a gateway-set cookie. The two together cover canary
releases, blue-green switches, and sticky sessions — all stateless on
the gateway side, all live-reloadable, zero new dependencies.

## The split is at the service level

A service targets exactly one of `upstream` (single pool, the
pre-DW-040 shape) or `split` (a weighted list of upstreams). A split
target is a whole upstream — its own endpoints, protocol, health
checks, and balancer — so a canary pool is isolated from the stable
one by construction: endpoint weights inside one upstream conflate two
pools, while two upstreams in a split keep them separate. Validation
rejects both-set (ambiguous routing) and neither-set (a service that
serves nothing).

## The pick is a stateless weighted hash

Each request dispatched through a split service lands on one target
upstream by a deterministic weighted pick over the SAME FNV-1a hash
the balancer's consistent-hash ring uses (`balance::key_hash` — chosen
for the same reason: toolchain-stable hashing, so a sticky session's
branch placement survives a Rust upgrade). The slot is
`hash % total_weight`, walked over the targets' cumulative bounds.

The hash KEY depends on stickiness:

- with `sticky` configured AND the request carrying the cookie, the
  key is the cookie's VALUE — a session lands on the same branch for
  every request while the weights are unchanged;
- otherwise the key is the request id — per-request distribution whose
  realized ratios converge on the configured weights statistically
  (the issue's acceptance shape: "split ratios verified
  statistically").

The pick carries NO runtime state — no counters, no locks, no
per-service bookkeeping. That is what makes the blue-green switch
instant: a re-publish rebuilds the compiled split for the new
generation, and the very next request dispatches by the new weights,
with no restart and no drain.

### Displacement is bounded by an invariant total

When a weight change KEEPS the total constant, only the changed share
of hash space moves: `95/5 -> 90/10` moves exactly the 5% that became
canary, and the blue-green flip `100/0 -> 0/100` (total still 100)
moves exactly the stable side. A change that ALTERS the total changes
the modulus and therefore reshuffles (wholesale) every key — so ramp a
canary by RE-BALANCING the pair (`95/5 -> 90/10`), never by growing
the canary alone (`95/5 -> 95/10` reshuffles all sessions). The
operator ramp rule is stated in both the module docs and the
`Service::split` config doc.

## Stickiness is layered

The cookie guarantees BRANCH affinity (which upstream). Endpoint
affinity within a branch comes from the branch upstream's own
balancer: when it runs `ip_hash`, the sticky value becomes the ring
key (the proxy passes it as the dispatch hash key), so the session
pins one endpoint through the same ketama machinery that pins client
IPs. With other balancers the branch pick is the affinity guarantee
and the endpoint is free to float — documented, not hidden:
ring-based endpoint pinning and round-robin spreading are different
tools and the operator picks per branch. A split service without
`sticky` hashes per request id (no session pinning); a single-target
non-sticky service keeps the client-IP key (the `ip_hash` contract,
unchanged).

The cookie value is an opaque affinity handle generated by the
gateway (`hex(unix_ms) hex(counter)` — 24 printable hex characters):
NOT a secret, carrying no identity, never trusted as one. Reusing a
present cookie is safe precisely because its only power is choosing
among upstreams the operator already configured — a client "forging"
one can only pick a branch it could have landed on anyway. The cookie
is minted BEFORE the pick, so the first response's branch IS the
cookie-pinned branch; `Set-Cookie` is appended on the success path
(never replacing an upstream's own cookies, never re-set when the
cookie was already presented).

One documented edge: a session whose FIRST request is a response
cache HIT is served without a dispatch, so no cookie is minted until
its first cache MISS — while hits last there is nothing to pin (no
upstream was contacted), and the miss mints exactly as the uncached
path would.

## Blue-green by weight flip

A weight of `0` parks a target: it is compiled and validated (its
handle exists, its slots are empty) but serves no traffic — the parked
side of a blue-green pair. The switch is a republish that flips the
weights (`100/0 -> 0/100`); because the total is unchanged, the
displacement is exactly the stable side, and because the pick is
stateless, the next request after the republish dispatches by the new
generation. No restart, no drain, no in-flight disruption beyond the
generation swap.

## Configuration and metrics

```yaml
services:
  - name: api
    # exactly one of upstream / split:
    split:
      targets:
        - { upstream: api-stable, weight: 95 }
        - { upstream: api-canary, weight: 5 }   # ramp by re-balancing: 95/5 -> 90/10
    sticky:
      cookie: dwara_affinity        # RFC 6265 token; the gateway reads and sets it
      ttl_s: 3600                   # default 3600; 1..=2592000 (30 days)
    base_path: /v1
```

Validation:

- `split.targets`: 2..=8 targets, each naming an existing upstream,
  no duplicates, total weight positive and at most 100000 (individual
  zeros are the parked blue-green side; an all-zero split routes
  nowhere).
- `sticky.cookie`: a valid RFC 6265 cookie-name token (the RFC 2616
  `token` grammar — no separators, spaces, or controls), because the
  name rides a hand-serialized `Set-Cookie` header.
- `sticky.ttl_s`: 1..=2592000 (30 days); default 3600.

The `cli lint` subcommand treats an upstream referenced only by a
split target as referenced (not "unreferenced").

Decisions land in two metrics, both config-bounded in label
cardinality:

- `dwara_split_picks_total{service,upstream}` — one per request
  dispatched through a weighted split; both labels are config-declared
  names, so the canary share is directly readable as the `upstream`
  share within a `service`.
- `dwara_sticky_sessions_total` — affinity cookies set on a first
  response (a plain counter, no label space).

The [load balancing](./load-balancing.md) page covers the per-upstream
algorithms this feature layers over (the `ip_hash` ring the sticky
value reuses); the [dataplane and proxy](./dataplane-proxy.md) page
covers the dispatch path the split plugs into.

## Auto-canary analysis (DW-091)

DW-040 gave the operator manual weight-ramp control. DW-091 adds the
automated layer: a `canary_analysis` block on a service split (exactly
2 targets: baseline + canary) or an AI model alias arms a background
controller that compares the canary side against the baseline on
`error_rate` or `latency_p99` and adjusts the canary weight
automatically.

### How it works

1. **Recording**: every response through a canary-shaped split calls
   `CanaryController::record_outcome(group, is_canary, status,
   latency_ms)`. The controller maintains per-version sliding windows
   (1000-sample cap) with error counts and latency samples.

2. **Evaluation**: a background `CanaryRunner` polls every 5 seconds.
   For each canary group, it checks whether both sides have at least
   `min_requests` observations and the `cooldown_seconds` window has
   elapsed since the last adjustment. If so, it computes the canary
   metric (error rate or p99 latency) and compares it against the
   promote and rollback thresholds.

3. **Actions**:
   - **Promote**: canary metric BELOW the promote threshold (good) ->
     canary weight increases by `step` (baseline decreases by `step`,
     total stays constant).
   - **Rollback**: canary metric ABOVE the rollback threshold (bad) ->
     canary weight decreases by `step`.
   - **Severe regression**: canary metric ABOVE 2x the rollback
     threshold -> canary weight goes to 0 immediately (no step
     decrement).
   - **Neutral**: canary metric between the two thresholds -> no
     action.

4. **Application**: the runner calls `apply_service_split_weights` or
   `apply_ai_canary_weights` on the DataPlane, which builds a new
   `Generation` with the adjusted weights and swaps it in via ArcSwap.
   The weight change is TRANSIENT — it reverts on the next config
   reload.

### Configuration

```yaml
services:
  - name: api
    split:
      targets:
        - { upstream: api-stable, weight: 90 }
        - { upstream: api-canary, weight: 10 }
      canary_analysis:
        enabled: true              # default true; set false to pause
        window_seconds: 60         # intended look-back period (>= 1)
        step: 5                    # weight delta per adjustment (>= 1)
        min_requests: 10           # minimum samples before acting (>= 1)
        cooldown_seconds: 30       # gap between adjustments (>= 1)
        promote:
          metric: error_rate       # or latency_p99
          threshold: 0.01          # canary error < 1% -> promote
        rollback:
          metric: error_rate
          threshold: 0.05          # canary error > 5% -> rollback
```

The same block is available on AI model aliases:

```yaml
ai:
  models:
    gpt-4:
      canary_analysis:
        enabled: true
        # ... same fields as above
```

### Validation

- `canary_analysis` requires exactly 2 split targets (baseline +
  canary). A 3-target split with `canary_analysis` is rejected.
- `window_seconds >= 1`, `step >= 1`, `min_requests >= 1`,
  `cooldown_seconds >= 1`.
- `error_rate` thresholds must be in `[0.0, 1.0]`.
- `latency_p99` thresholds must be `> 0`.

### Events and metrics

- `canary_promoted` / `canary_rolled_back` events on the event bus
  (carrying the group name, action, new weight, and metric value).
- `dwara_canary_promotions_total` — counter of promote actions.
- `dwara_canary_rollbacks_total` — counter of rollback actions.
- `dwara_canary_weight{group}` — the current canary weight per group.

### Invariants preserved

- **Total weight constant**: the baseline absorbs the canary's delta,
  preserving the DW-040 hash-distribution invariant (no session
  reshuffle beyond the changed share).
- **Transient**: weight changes are Generation swaps, not config
  edits. A config reload reverts to the configured weights.
- **No new dependencies**: the controller uses `Mutex<HashMap>` for
  the sliding windows and `AtomicU64` for counters.
