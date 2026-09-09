# Traffic policy and resilience

How Dwara keeps traffic flowing when upstreams degrade, and how it
protects them when clients misbehave. Resilience is layered, and each
layer owns one concern: timeouts bound every stage of an upstream
call, retries recover transient failures without amplifying them,
circuit breaking and health checks stop traffic from hammering a
dying upstream, and rate limiting with admission control keeps load
predictable under stress.

Every lever is opt-in -- per upstream, per policy, or per route --
and they compose: an open circuit breaker fail-fasts before a timeout
can fire, a request that exhausts its retry budget fails through to
the client instead of piling on, and an endpoint ejected by health
checks simply never receives the retry.

These build on the core routing model in [Configuration](./configuration)
and the operational reload flow in [Operations](./operations) -- every
lever here is applied by reloading config, with no restart.

## In this section

- [Timeouts](./timeouts) - bound the dial, the headers, and the body
  idle gap of every upstream call.
- [Retries](./retries) - bounded attempts with full-jitter backoff,
  a rolling retry budget, and an optional cross-attempt deadline.
- [Circuit breaking](./circuit-breaking) - fail fast while a whole
  upstream is failing; half-open probes test recovery.
- [Health checks](./health-checks) - passive outlier detection from
  real traffic plus optional active probes; eject and recover
  endpoints.
- [Rate limiting](./rate-limiting) - stacked-window GCRA limits at
  five scopes, keyed by IP, credential, or route.
- [Admission queues](./admission-queue) - let requests wait for a
  concurrency permit up to a timeout so latency rises before
  shedding.
- [Request hedging](./request-hedging) - race a speculative
  duplicate against a slow request to cut tail latency.
- [Consumer quotas](./quotas) - per-consumer daily/monthly request
  budgets over the durable state store, distinct from rate limits.
- [WAF-lite filtering](./waf-lite) - heuristic SQLi/XSS/path-traversal
  pattern matching with a dry-run mode for safe rollout.
- [Maintenance mode and dry-run](./maintenance) - answer a route with
  503 + Retry-After, and evaluate any policy in report-only mode.
- [Mirroring](./mirroring) - shadow a share of live traffic to a test
  upstream.
- [Fault injection](./fault-injection) - aborts and delays, for
  testing the rest of this page.

For the runtime view -- the state machines, the layering, and how the
pieces compose -- see
[Resilience architecture](../architecture/resilience).

## Runnable demo

The `demos/03-resilience/` directory in the repository runs a live
stack -- a gateway against deliberately flaky, slow, and healthy
upstreams -- for the resilience features in this section; its README
covers prerequisites, test scripts, and teardown.
