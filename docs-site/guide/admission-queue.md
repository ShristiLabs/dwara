# Admission queues and backpressure

When the gateway concurrency cap (`max_concurrent_requests`) is
saturated, the default behavior is to shed the next request
immediately with 503. Under a load spike this produces a cliff:
throughput is at the cap one moment, then every request over the cap
is shed the next. An admission queue makes the cap degrade
gracefully — requests wait for a permit up to a timeout, so latency
rises before shedding begins.

## Enabling the queue

Add an `admission_queue` block under `gateway`:

```yaml
gateway:
  max_concurrent_requests: 100
  admission_queue:
    enabled: true           # default false; requires max_concurrent_requests
    max_queue_size: 200     # total queued requests; 1..=10000
    queue_timeout_ms: 50    # max wait for a permit; 1..=10000
    per_priority: true      # split capacity across priority classes (default true)
```

The queue is opt-in (`enabled: false` by default). It requires
`max_concurrent_requests` — an uncapped gateway has nothing to queue
for, so validation rejects an enabled queue without a cap.

## What happens when the cap is full

1. The request tries to acquire a permit immediately (same as
   DW-016).
2. If the cap is full and the queue is enabled, the request checks
   the queue depth. If the queue is at capacity, the request is shed
   immediately with 503 (no waiting).
3. Otherwise, the request waits for a permit up to `queue_timeout_ms`.
   If a permit becomes available (an in-flight request completes),
   the request is admitted.
4. If the timeout expires, the request is shed with 503 and a
   `Retry-After` header.

The effect: as load increases past the cap, the queue absorbs the
excess (latency rises by up to `queue_timeout_ms`) before shedding
begins. The degradation curve is graceful, not a cliff.

## Per-priority splitting

When `per_priority: true` (the default), half the queue capacity is
reserved for high-priority requests (routes or consumers with
priority 8-10). Low-priority requests may only occupy up to half the
queue; high-priority requests may use the full queue. This prevents a
flood of low-priority traffic from filling the queue and starving
high-priority requests.

Set `per_priority: false` for a single shared pool
(first-come-first-served) with no priority reservation.

## Choosing values

| Knob | Trade |
| --- | --- |
| `max_queue_size` | Larger = more requests absorb into latency before shedding. But each queued request holds a connection, so memory and file-descriptor usage scale with the queue depth. |
| `queue_timeout_ms` | Longer = more chance a queued request gets a permit (fewer sheds). But the client is waiting the whole time, so latency rises. Shorter = sheds sooner, lower latency for shed requests. |
| `per_priority` | `true` (default) protects high-priority traffic from low-priority queue fill. `false` is simpler (FIFO) but high-priority can be starved. |

A common starting point: `max_queue_size` at 2x the cap,
`queue_timeout_ms` at 50-100ms (short enough that a shed request's
client can retry promptly, long enough that a quick upstream
completion admits the queued request).

## Metrics

Watch these on `/metrics` to see the degradation curve:

- `dwara_admission_queued_total{outcome}` — counter with outcomes
  `admitted` (got a permit after queueing), `timeout` (shed due to
  timeout), `queue_full` (shed because the queue was at capacity).
- `dwara_admission_queue_depth` — gauge: current number of requests
  waiting in the queue.
- `shed_total{priority}` — the existing DW-016 counter; still counts
  every shed, including queue-timeout and queue-full sheds.

Rising `admitted` means the queue is absorbing load. Rising `timeout`
means the queue is saturating (requests wait too long). Rising
`queue_full` means the queue itself is overflowing — consider
increasing `max_queue_size`.

## Dry-run

`load_shed_dry_run: true` + `admission_queue.enabled: true` compose:
when a request would be shed (timeout or queue full), the dry-run flag
admits it over the cap instead. The request still waits up to
`queue_timeout_ms` in the queue, but no 503 is sent. This lets you
observe what enforcement would shed (and at which priorities) before
turning it on. See [Maintenance and dry-run](./maintenance#dry-run).
