# Retries

Retries recover a request from a transient upstream failure -- a
connection reset, a `503` mid-rollout, a read timeout on one bad
replica -- without pushing amplification onto the upstream. Dwara's
retry loop is bounded three ways: an attempt cap, a rolling budget on
retries as a share of traffic, and an optional cross-attempt
wall-clock deadline. Backoff between attempts is full-jitter
exponential, so a fleet of gateways never retries in lockstep.

Retries are configured per upstream in the `retries` block. A block
with no keys is retries-off (all fields default), which keeps the
default proxy path fully streaming.

```yaml
upstreams:
  - name: api
    endpoints:
      - { address: 10.0.0.1, port: 8080 }
      - { address: 10.0.0.2, port: 8080 }
    retries:
      attempts: 2
      buffer_max_bytes: 16384
      total_deadline_ms: 10000
```

## When to use this

Enable retries on upstreams where failures are transient and the
request is replayable. Two properties make a retry safe:

- **Replayable body** -- only requests whose body was fully buffered
  within `buffer_max_bytes` may be retried; an over-cap body streams
  without retry (the default `0` buffers only empty bodies).
- **Idempotent method** -- `POST` is never retried unless you set
  `retry_post: true`, accepting that the upstream may see a partially
  processed body twice.

## Fields

| Field | Default | Description |
|---|---|---|
| `attempts` | `0` (off) | Maximum retries beyond the first attempt. Validation caps it at 10. |
| `retry_post` | `false` | Retry non-idempotent `POST` requests. A retried POST may replay a body the upstream already partially processed. |
| `backoff_base_ms` | `25` | Exponential backoff base: the nominal delay before retry *n* is `min(base * 2^(n-1), backoff_cap_ms)`. |
| `backoff_cap_ms` | `250` | Backoff ceiling. Must be >= `backoff_base_ms`. |
| `retry_statuses` | `[502, 503, 504]` | Upstream response statuses that trigger a retry. Each entry must be a valid 4xx/5xx; an empty list disables status-based retries. |
| `retry_transport` | `true` | Retry transport errors (connect timeout/refusal/reset/framing) and per-attempt read timeouts. |
| `budget_percent` | `10` | Maximum share of requests to this upstream, in a rolling window, that may be retries. Must be in (0, 100]. |
| `buffer_max_bytes` | `0` (no buffering) | Bodies buffered within this cap become replayable; larger bodies stream and are never retried. |
| `total_deadline_ms` | unbounded | Cross-attempt wall-clock cap from first to last attempt, INCLUDING backoff delays. Max 600000; a present `0` is rejected -- omit the field for unbounded. |
| `hedge` | off | Speculative duplicates on slowness; see [Request hedging](./request-hedging). |

## How it works

1. An attempt fails. The classifier decides whether the outcome is
   retryable at all:

   | Outcome | Retryable? |
   |---|---|
   | Status in `retry_statuses` (default 502/503/504) | Yes |
   | `429` from upstream | Yes, and the backoff honors a seconds-form `Retry-After` |
   | Connect error / TLS error / read timeout | Yes (when `retry_transport`) |
   | Mid-stream body error | No -- the response already started; the failure is reported to [passive health](./health-checks) instead |
   | Other 4xx | No |

2. The retry budget is checked: a retry is allowed only while
   `(retries + 1) * 100 <= budget_percent * requests` over the
   upstream's rolling window. The budget is shared across all
   in-flight requests for the upstream, so a burst of retries from
   one client cannot starve another. When the budget is exhausted,
   failing requests fail through to the client.
3. Backoff is computed as `min(base * 2^(n-1), cap)`, then full
   jitter: the actual sleep is a uniform random value in
   `[0, nominal]`. Full jitter avoids the thundering herd where many
   clients retry in lockstep after a downstream recovers.
4. If `total_deadline_ms` is set and the next backoff would cross the
   deadline, the retry is aborted and the last response (or error) is
   returned to the client. The sleep is clamped to the remaining
   budget so a retry never sleeps past the deadline. A
   deadline-aborted retry is not charged against the retry budget.

Retries happen strictly BEFORE response headers arrive on the final
attempt -- a response body that dies mid-stream is never retried.
This is what keeps the retry path compatible with zero-buffer
streaming: nothing waits for a body it might have to replay.

## Interaction with timeouts

The per-attempt `read_ms` [timeout](./timeouts) bounds each attempt;
`total_deadline_ms` bounds the whole chain. A common pairing:

```yaml
retries:
  attempts: 2
  total_deadline_ms: 10000   # whole chain <= 10 s
```

with `timeouts.read_ms: 3000` means at most three 3-second attempts
(including backoff) inside a 10-second envelope.

## Runnable demo

Watch a retry recover a request: `demos/03-resilience/` (test
script: `test-04-retries.sh`) in the repository retries against a
50%-flaky pool until the healthy echo endpoint answers 200. The
category README covers prerequisites and teardown.

## See also

- [Timeouts](./timeouts) -- the per-attempt bounds.
- [Request hedging](./request-hedging) -- orthogonal: hedging fires
  on slowness, retries fire on errors.
- [Circuit breaking](./circuit-breaking) -- when retries stop helping.
- [Resilience architecture](../architecture/resilience) -- the state
  machines behind this loop.
