# Maintenance mode and policy dry-run

Two operational levers, both configured in YAML and both applied by
[reloading config](./operations#reload) — no restart,
no separate API.

## When to use this

Maintenance mode takes a route down gracefully — during a database
migration or a backend deploy — without removing it from the config, so
the route's shape and policies stay intact and you bring it back by
deleting one block and reloading. Dry-run lets you observe what a policy
would reject (rate limits, size limits, authz, load shedding) before you
enforce it, so you can size thresholds against real traffic instead of
guessing. Both are applied by reloading config, with no restart.

## Taking a route down for maintenance

Add a `maintenance` block to a route and every matched request is
answered by the gateway itself with `503`, a [`Retry-After`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After) header,
and the standard JSON error envelope (`code: "maintenance"`):

```yaml
routes:
  - name: api
    service: api-service
    maintenance:
      retry_after_secs: 300   # optional, default 60
      message: "api is down for a database migration"  # optional
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
```

Behavior details worth knowing before you rely on it:

- **Nothing else runs.** The route's action (proxy, redirect, or
  fixed respond) never executes and the upstream is never
  contacted; the route's size limits and authentication are not
  evaluated either — a request in maintenance is told "we're down,"
  not "your headers are too big."
- **CORS preflights** ([a browser's pre-flight OPTIONS check](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests)) still answer 204 on CORS-configured routes.
  A preflight is a browser protocol handshake about cross-origin
  policy, not a real request; failing it would show up in browsers
  as an opaque CORS error. The actual request gets the 503 — and it
  carries the route's CORS headers, so browser scripts can read the
  maintenance message.
- **Health endpoints keep working.** `/healthz`, `/readyz`, and
  `/metrics` are served before routing and stay live through
  maintenance, so orchestrators and scrapers are unaffected.
- **Other routes are untouched**, and traffic that matches no route
  still gets a 404.
- `maintenance: {}` (empty block) is the minimal spelling.
  `retry_after_secs: 0` is rejected by validation — it would tell
  every client to retry immediately against a route you just took
  down.

To bring the route back, remove the block and reload.

## Dry-run: preview a policy before enforcing it

Every policy phase that can reject supports a `dry_run` flag: the
policy still evaluates, but instead of rejecting the request the
gateway logs what it WOULD have done and lets the request through.
Turn the flag off (and reload) once the numbers look safe.

| Policy | Flag | Would have answered |
| --- | --- | --- |
| Route size limits | `limits.dry_run` on the route | 413 / 431 |
| Authorization rules | `dry_run` on any `authorization` block | 401 / 403 |
| Rate limiting | `dry_run` on the named policy bundle | 429 |
| Load shedding | `load_shed_dry_run` at the gateway level | 503 |

```yaml
policies:
  - name: tight
    dry_run: true          # evaluate, report, do not 429
    rate_limits:
      - selector: [credential]
        requests_per: { minute: 100 }
routes:
  - name: api
    service: api-service
    policies: [tight]
    limits:
      max_body_bytes: 1048576
      dry_run: true        # evaluate, report, do not 413/431
    # ...
```

Guarantees:

- **A live rule is never muted by a dry one.** If two policies apply
  to the same request and only one is dry-run, the live one still
  rejects. Dry-run can only ever ADD visibility, never remove
  enforcement.
- **Dry rate limits change nothing about responses** — no 429, and
  no `X-RateLimit-*` headers from the dry bundle (its counters still
  advance internally, so what you observe is what enforcement would
  do).
- **Dry load shedding admits over the cap** — that is the point
  (seeing what a cap would shed before enforcing it), so expect the
  gateway to exceed `max_concurrent_requests` while the flag is on.
- **Authentication is never dry-run.** Invalid or missing
  credentials and `auth_required` always enforce; monitor mode is
  for policy, not for auth.
- One documented blind spot: a dry-run body limit cannot observe
  streaming (unknown-length) bodies — only requests that declare
  their size up front are reported.

## Reading the dry-run report

The report is the metrics plus the logs — there is no separate
endpoint:

- Metric: `dwara_policy_dry_run_total{phase,route}` on `/metrics`.
  A non-zero rate means "this policy would be rejecting traffic
  right now." `phase` is one of `route_limits`, `authz`,
  `rate_limit`, `load_shed`.
- Logs: every would-have-rejected request emits one structured
  `dwara::policy` warn event with `phase`, `would_be_status`,
  `route`, `consumer`, `request_id`, and a human `detail` (which
  limit crossed, the denial reason, the retry-after that would have
  been sent). Correlate with the request's access log line via
  `request_id` — the access line shows the real (allowed) outcome,
  the policy event shows what WOULD have happened.
