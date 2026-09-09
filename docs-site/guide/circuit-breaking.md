# Circuit breaking

The circuit breaker fail-fasts traffic to an upstream that is
actively failing, instead of letting every request pay the full
timeout-and-retry cost just to discover the upstream is down. It is
per-upstream (it gates the whole upstream, not individual
endpoints -- that is [health checks](./health-checks) job) and trips
on either a consecutive failure streak or a windowed error ratio,
whichever fires first.

The breaker is configured per upstream in the `breaker` block:

```yaml
upstreams:
  - name: api
    endpoints:
      - { address: 10.0.0.1, port: 8080 }
      - { address: 10.0.0.2, port: 8080 }
    breaker:
      consecutive_failures: 5
      error_ratio: 0.5
      error_volume: 20
      open_ms: 30000
      half_open_probes: 1
```

## When to use this

Enable the breaker on upstreams whose failure mode is correlated --
a hard-down dependency, a restarting service, a saturating database.
While the breaker is open, requests are rejected immediately with
`503` "upstream circuit open" plus a `Retry-After` of the seconds
until half-open, so well-behaved clients back off without you
burning timeouts on a corpse.

If failures are independent and rare, retries alone
([Retries](./retries)) may be enough; the breaker earns its keep when
the whole upstream is in trouble and the fastest correct answer is
"no".

## Fields

| Field | Default | Description |
|---|---|---|
| `consecutive_failures` | `5` | Consecutive failures (5xx + transport) that open the breaker. |
| `error_ratio` | `0.5` | In-window error ratio in (0, 1] that opens the breaker once `error_volume` observations exist. |
| `error_volume` | `20` | Minimum observations in the 60 s window before the ratio is evaluated. |
| `open_ms` | `30000` | Cooling-off period in milliseconds before a half-open probe is admitted. |
| `half_open_probes` | `1` | Concurrent trial requests admitted in half-open. A successful probe closes the breaker; a failed one re-opens it. |

## How it works

The breaker is a three-state machine per upstream:

- **Closed** -- requests flow. Failures are counted toward both the
  streak and the 60 s window.
- **Open** -- requests are rejected with `503` "upstream circuit
  open" and a `Retry-After` of the seconds remaining until half-open.
  In-flight requests complete normally. In-flight failure reports
  while open do not change the state -- the breaker stays open until
  `open_ms` elapses.
- **Half-open** -- after `open_ms`, up to `half_open_probes` trial
  requests are admitted. Success closes the breaker (counters and
  window reset); failure re-opens it for another `open_ms`.

The breaker is checked BEFORE the endpoint pick and before every
(re)attempt of a request, so a retry cannot sneak through an open
breaker. It is a layer ABOVE endpoint ejection: a fail-open endpoint
pick still flows through the breaker, and a breaker-open period
ejects nothing -- health sees no traffic while the breaker holds it.

What counts as a failure is the same classification the breaker
shares with passive health: transport errors and HTTP `>= 500` are
failures; `1xx`-`4xx` (including `429`) are successes -- they
describe the caller, not the upstream.

## Observability

The `dwara_breaker_state` gauge exposes `0 = closed, 1 = open,
2 = half-open` per upstream for alerting, and every transition emits
a `breaker_opened` / `breaker_closed` event on the gateway event bus
(see [Alert and event webhooks](./webhooks)).

## See also

- [Health checks](./health-checks) -- the per-endpoint counterpart:
  ejection of individual failing endpoints.
- [Timeouts](./timeouts) and [Retries](./retries) -- the layers the
  breaker sits above.
- [Resilience architecture](../architecture/resilience) -- the state
  machine and layering in depth.
