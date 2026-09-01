# Traffic policy and resilience

The levers that protect your upstreams and shape traffic under load:
taking routes down safely, absorbing load spikes instead of shedding
cliffs, and filtering obvious attack payloads at the edge. Each is
per-route opt-in and applied in the request path before any upstream
contact.

These build on the core routing model in [Configuration](./configuration)
and the operational reload flow in [Operations](./operations) - the
maintenance and dry-run levers are both applied by reloading config,
with no restart.

## In this section

- [Maintenance mode and dry-run](./maintenance) - answer a route with
  503 + Retry-After, and evaluate any policy in report-only mode.
- [Admission queues](./admission-queue) - let requests wait for a
  concurrency permit up to a timeout so latency rises before shedding.
- [WAF-lite filtering](./waf-lite) - heuristic SQLi/XSS/path-traversal
  pattern matching with a dry-run mode for safe rollout.
- [Consumer quotas](./quotas) - per-consumer daily/monthly request
  budgets over the durable state store, distinct from rate limits.
