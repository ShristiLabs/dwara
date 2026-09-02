# API lifecycle management

Dwara tracks an API's full lifecycle -- from the developer portal where a
route is first published, through the environment profiles that carry it from
dev to staging to prod, to the journey recorder that captures how real
clients traverse the published surface. The lifecycle block is the
operator-facing layer on top of the routing config: it does not change how
traffic is proxied, it records what the API is and who used it.

## When to use this

Use the lifecycle block when you are running the gateway as the front door
for a portfolio of APIs and you need more than "it proxies" -- a developer
portal that publishes the route catalog, environment profiles so the same
config carries per-environment upstreams and policies, and a journey recorder
that captures the sequence of calls a real client makes so you can document
the happy path and detect drift. A gateway without the block proxies traffic
unchanged; the lifecycle layer is purely additive metadata and tooling.

## Configuration

Add a `lifecycle` block under `gateway`. It is optional and off by default.

```yaml
gateway:
  lifecycle:
    portal:
      enabled: true
      base_url: https://portal.example.com
      auth:
        oidc:
          issuer: https://idp.example.com
          client_id: dwara-portal
    environments:
      - name: dev
        upstream_suffix: .dev.internal
        policy_overrides:
          rate_limit:
            routes:
              - name: api
                rps: 1000
      - name: staging
        upstream_suffix: .staging.internal
      - name: prod
        upstream_suffix: .prod.internal
        policy_overrides:
          security_headers:
            hsts_max_age_secs: 31536000
    journey_recorder:
      enabled: true
      sampling_pct: 5
      retention_days: 30
```

## Developer portal

With `portal.enabled: true`, the gateway exposes a catalog endpoint that
lists every published route -- its path, methods, auth requirements, and any
OpenAPI document attached via [config import](./config-import). The portal
fetches this catalog and renders it for API consumers. `base_url` is where
consumers reach the rendered portal; the gateway redirects catalog hits to it
when a browser asks.

Portal access is gated by the `auth` block, which takes the same OIDC
configuration as a route's [OIDC authn](./oidc). A consumer must authenticate
to see the catalog; the gateway passes the consumer's identity to the portal
so the portal can show only the APIs that consumer is entitled to.

## Environment profiles

The `environments` list names the environments a config is published into.
Each profile carries an `upstream_suffix` appended to every upstream host in
the config, so the same `config.yaml` resolves to `api.dev.internal`,
`api.staging.internal`, or `api.prod.internal` depending on which profile the
gateway is running. The active profile is selected at startup
(`--environment prod`); the gateway refuses to start if the named profile is
not in the config.

`policy_overrides` lets a profile tighten or loosen policy per environment
without forking the config: prod can enforce stricter rate limits and
security headers, dev can relax them. Overrides are additive -- a field in
`policy_overrides` replaces the base value; a field not named falls through
to the base config. Validation runs on the merged config, so an override that
produces an invalid config is rejected at publish, not at request time.

## Journey recorder

With `journey_recorder.enabled: true`, the gateway samples a percentage of
authenticated client sessions and records the ordered sequence of routes each
sampled session hits -- a "journey" through the API surface. The recorder is
for documentation and drift detection: a journey that matches the documented
happy path confirms the API is used as designed; a journey that diverges
flags a client doing something unexpected (or a doc that is out of date).

`sampling_pct` caps the recording rate to keep the store bounded; the
default is 1 percent. `retention_days` bounds how long journeys are kept; the
default is 30 days. Journeys are stored in the analytics SQLite file and
surface in the [analytics](./analytics) views alongside the per-route
metrics. A journey is attributed to the authenticated consumer, so the
recorder respects the same redaction rules as the access log -- sensitive
headers and bodies are never recorded, only the route sequence and timing.

## Notes

- The lifecycle block does not change proxying. A gateway with the block and
  one without proxy the same traffic the same way; the block adds metadata,
  tooling, and observability on top.
- Environment profiles compose with [config import](./config-import): import
  the base config, then apply the profile's overrides at publish.
- The developer portal catalog is read-only; publishing a route still happens
  via the config pipeline. The portal reflects what is published, it does not
  publish.
