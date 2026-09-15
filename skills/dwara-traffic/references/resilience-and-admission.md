# Retries, hedging, breakers, admission control, chaos

## Retries (upstream-level)

```yaml
    retries:
      attempts: 3
      backoff_base_ms: 25
      backoff_cap_ms: 250
      budget_percent: 10        # retry budget as % of live traffic -
                                # prevents retry storms amplifying an outage
      retry_statuses: [502, 503, 504]
      retry_transport: true     # also retry transport-level errors
      total_deadline_ms: 10000  # bounds the WHOLE chain incl. backoff
                                # (<= 600000; 0 rejected if present)
      buffer_max_bytes: 1048576 # body replay buffer; REQUIRED for hedging
```

- Retries happen only **before response headers** arrive.
- `429` retries honor the upstream `Retry-After`.
- Deadline-aborted attempts are not charged to the retry budget.

## Hedging (speculative execution against slowness)

```yaml
    retries:
      hedge:
        hedge_after_ms: 200     # 0 = off
        hedge_max: 1            # extra copies in flight
        retry_post: false       # default false; idempotent set =
                                # GET/HEAD/OPTIONS/TRACE/PUT
```

- Requires `buffer_max_bytes > 0` (the body must be replayable).
- Each hedge goes to a **different endpoint**; first response wins, losers
  are cancelled.
- Orthogonal to retries: retries chase *errors*, hedges chase *slowness*; a
  timed-out hedge can still be retried.

## Circuit breaker

```yaml
    breaker:
      consecutive_failures: 5
      error_ratio: 0.5
      error_volume: 20
      open_ms: 30000            # open duration before half-open probing
      half_open_probes: 1
```

State is exported as `breaker_state` (0 closed / 1 open / 2 half-open) and
transitions fire `breaker_opened` / `breaker_half_open` / `breaker_closed`
webhook events.

## Gateway-wide admission control

```yaml
max_concurrent_requests: 10000

admission_queue:
  enabled: true            # requires max_concurrent_requests
  max_queue_size: 1000     # 1..10000; queue-full -> immediate 503
  queue_timeout_ms: 5000   # waited-too-long -> 503 + Retry-After
  per_priority: true       # priority 8-10 (high) gets the full queue;
                           # lower priorities may occupy only half

load_shed_dry_run: false   # true = log-and-admit over cap instead of
                           # shedding; composes with the queue (request
                           # still waits, then admits over cap)
```

Per-request priority comes from route `priority` (0-10, 8+ = high) or
consumer `priority`. Metrics: `dwara_admission_queued_total{outcome}`,
`dwara_admission_queue_depth`, shed totals by priority.

## Mirroring (shadow traffic)

```yaml
    # route-level
    mirror:
      upstream: mirror-upstream
      percentage: 10          # required; per-request random draw, 0-100
      timeout_ms: 2000
```

Fire-and-forget; responses are discarded. The mirrored request carries an
**empty body unless the route buffers the request body** - plan mirroring
of POST endpoints accordingly (or set the route's body-buffering).

## Fault injection (chaos testing)

```yaml
    fault_injection:
      abort:  { percentage: 1, status: 503 }
      delay:  { percentage: 5, fixed_ms: 100 }   # fixed duration only
```

Abort is checked first (a request drawn for both is aborted). Combine with
mirroring to rehearse incident response against production-shaped traffic.

## Maintenance mode

```yaml
    maintenance:
      retry_after_secs: 120
      message: "This endpoint is under maintenance"
```

Route answers 503 + `Retry-After` without dialing the upstream. Prefer this
over deleting the route when the outage is intentional - clients get a
correct signal instead of a 404.
