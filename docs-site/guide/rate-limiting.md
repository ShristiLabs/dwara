# Rate limiting

Rate limiting caps how fast requests are admitted, per key you
choose -- client IP, authenticated consumer, route, or a combination
-- using GCRA cells stacked over one or more time windows. A request
is admitted only if EVERY window of EVERY applicable rule allows it;
denials answer `429` with `Retry-After` and `X-RateLimit-*` headers
that name the binding (denying) window.

Rules live in named policy bundles and attach at five scopes:

```yaml
policies:
  - name: public-api-limits
    rate_limits:
      - name: per-ip
        selector: [ip]
        requests_per: { s: 10, minute: 600 }
        burst: 20
      - name: per-route-flood
        selector: [ip, route]
        requests_per: { minute: 2000 }

routes:
  - name: public
    service: api-svc
    match:
      path: { type: prefix, value: /v1 }
    policies: [public-api-limits]
```

## When to use this

Rate limits are your first line of defense for anything internet
facing: scrapers, retry storms, credential-stuffing floods, and your
own clients' bugs. They compose with the other shedding layers --
[admission queues](./admission-queue) smooth bursts by waiting, rate
limits bound the rate itself, and [consumer quotas](./quotas) cap
daily/monthly totals rather than rates.

## Fields

Each entry in `policies[].rate_limits` is one rule:

| Field | Default | Description |
|---|---|---|
| `name` | -- | Optional label (documentation only; not part of the key). |
| `selector` | -- | Key components: `ip`, `credential`, and/or `route` (at least one; order does not matter). All listed attributes join into ONE key, so `[ip, route]` limits each (client IP, route) pair independently. |
| `requests_per` | -- | Sustained rates per window: `s`, `minute`, and/or `hour` (at least one, each > 0). Each set field becomes one stacked window; a request must satisfy ALL of them. |
| `burst` | the window's request count | Bucket size (burst capacity). Must be >= 1. |

The `credential` selector falls back to the client IP until
authentication identifies the consumer, so a rule works identically
before and after you add authn.

## Scopes

A policy bundle can be attached at five levels -- `consumer`,
`route`, `service`, `listener`, and `global` (via
`gateway.global_policies`) -- and every level with an attachment
APPLIES: all applicable rules AND together, with the precedence
chain `consumer > route > service > listener > global` deciding
which rule's headers bind a denial.

Two consequences worth internalizing:

- **Layering is additive.** A global 100 req/s plus a per-route
  10 req/s means a route is limited at 10 while every route
  together is limited at 100.
- **Unrouted traffic is not exempt.** Listener and global rules
  apply to requests that match no route before the `404` is
  answered, so 404 floods cannot bypass the limiter. The reserved
  paths (`/healthz`, `/readyz`, `/metrics`) stay exempt.

## Denial and admission responses

A denied request answers `429` with:

- `Retry-After` -- seconds until the binding window replenishes
  (rounded up, minimum 1). When several rules deny at once, this is
  the MAXIMUM wait across denying rules.
- `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Reset` -- from the first denying rule. `Reset` is
  Unix epoch seconds of that window's estimated full replenishment.

Admitted requests whose policies matched carry the same three
`X-RateLimit-*` headers on their final response (only when a policy
actually applied). The gateway is the source of truth for these
headers: any upstream values are silently replaced.

## Legacy single-window form

Older configs use `policies[].rate_limit` with `requests` and
`window_seconds` -- one window, no stacking. It still applies when
set; use `rate_limits` for new configs.

## Enterprise: distributed limits

The local limiter's counters are per-instance. The enterprise
edition adds a Redis-backed limiter that shares GCRA buckets across
a fleet, plus an adaptive controller that scales the limit factor
down when an upstream signals overload (EWMA latency/error tracking
and `Retry-After`-driven backoff). See
[Distributed Redis rate limiter](./redis-rate-limiter).

## Runnable demo

Hit the limit on a live gateway: `demos/04-security-auth/` (test
script: `test-11-rate-limiting.sh`) in the repository fires rapid
requests at a rate-limited route and asserts the sixth answers 429.
The category README covers prerequisites and teardown.

## See also

- [Consumer quotas](./quotas) -- daily/monthly budgets, not rates.
- [Admission queues](./admission-queue) -- wait instead of shed.
- [WAF-lite filtering](./waf-lite) -- content-based filtering to
  pair with rate limits.
- [Maintenance mode and dry-run](./maintenance) -- evaluate rate
  limits in monitor mode before enforcing.
