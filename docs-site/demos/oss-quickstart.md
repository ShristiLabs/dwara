# OSS quickstart demo

A comprehensive, feature-complete demonstration of every OSS capability
in a single runnable gateway. One `docker compose up` brings up a
TLS-terminating reverse proxy with the full OSS feature set: routing,
load balancing, authn/authz, rate limiting, resilience, observability,
analytics, AI gateway, and the mTLS admin API.

The demo lives at [`quickstart/oss/`](https://github.com/shristilabs/dwara/tree/main/quickstart/oss)
in the repository. It runs on Docker and needs no cargo build -- the
compose file builds the gateway image from `Dockerfile.scratch`.

::: tip Which quickstart should I run?
Run this one to tour the complete OSS feature set in a single
`docker compose up` -- no license and no private repositories needed.
If you are evaluating the enterprise fleet topology (controller +
edge data planes) instead, see the
[Enterprise quickstart demo](./enterprise-quickstart); it runs without
a license too, except the Redis-backed features.
:::

## What it demonstrates

The `dwara.yaml` config is a single file that demonstrates every OSS
feature. Each section is commented with the feature's design number
and a brief explanation. The features are grouped by category:

### Core gateway (proxying and routing)

- TLS termination with multi-SNI certificates and mTLS client auth
- Plaintext HTTP listener for local dev and health checks
- Routing: exact, prefix, and regex path matching, plus host, method,
  header, query, and cookie criteria
- Route actions: `proxy` (with `strip_prefix` rewrite), `redirect`
  (301), `respond` (direct 200), `mock` (synthetic response with
  delay), and `ai` (provider translation)
- PROXY protocol v1/v2 header acceptance

### Traffic policy and resilience

- Load balancing: `round_robin`, `least_requests`, `random`, `ip_hash`,
  and `peak_ewma` (latency-aware, Finagle-style)
- Passive health checks / outlier detection with half-open recovery
- Active health checks with HTTP/TCP probes and jitter
- Retries with exponential backoff, retry budgets, and retry on
  transport errors + specific statuses
- Request hedging: speculative hedge copies after a latency threshold
- Circuit breaking: consecutive-failure + error-ratio breaker
- Connection caps and max-pending
- Slow start: gradual endpoint ramp-up
- Load shedding with priority classes
- Admission queues with backpressure and per-priority splitting
- Rate limiting: single-window GCRA and stacked per-second/per-minute
  windows with burst capacity
- Adaptive rate limiting: EWMA-driven tuning
- Anomaly scoring: statistical detection of abusive request patterns
- Traffic splitting / canary: weighted split with auto-canary analysis
- Sticky sessions: cookie affinity
- Shadow traffic mirroring: fire-and-forget duplicate requests
- Fault injection: percentage-based delays and aborts
- DNS-based dynamic upstream discovery
- Happy eyeballs (RFC 8305) for dual-stack endpoints

### Security and authentication

- API key authentication
- JWT via JWKS with issuer/audience validation and key refresh
- HMAC request signing with clock-skew window
- mTLS client-certificate authentication (fingerprint and subject-CN)
- mTLS consumer mapping: certificate-to-consumer table by subject CN
- mTLS forward headers: `X-Client-Cert-*` headers to upstream
- OIDC providers: token introspection (RFC 7662)
- OAuth2 client-credentials proxying
- Authorization chain: consumer > route > service > listener > global
- IP ACL: allow/deny lists with default policy
- WAF-lite heuristic filtering: SQLi/XSS/path-traversal
- Request validation: JSON-schema body validation
- Response field masking: fail-closed redaction by JSON pointer
- Security headers: HSTS, nosniff, CSP, X-Frame-Options
- WebSocket policy: origin allowlisting and frame-rate policing
- Secrets via `${...}` references: env, file, and redacted-placeholder
- Agent principals: `agent` consumer type with tool allowlists

### Config management and operations

- mTLS admin API: `GET/PATCH /config`, `/health`, `/stats`
- Hot reload (file watch / SIGHUP)
- Global policies applying to every request
- Listener-level policies and authorization
- Trusted proxies: X-Forwarded-For chain preservation
- Maintenance mode: 503 + Retry-After

### Observability and analytics

- Embedded analytics: SQLite store with raw records and rollups
- Custom analytics dimensions: header-sourced and claim-sourced tags
- Live in-process sketches: sub-second-freshness per-route windows
- ML traffic insights: EWMA capacity forecasting and anomaly detection
- Scheduled usage-report exports: CSV/JSON dumps
- Replay capture: time-travel debugging
- Analytics stream: NDJSON firehose to a webhook sink
- Alert/event webhooks: breaker transitions, endpoint ejection, config
- SLO: availability and latency objectives per route
- API deprecation signals: Deprecation and Sunset headers

### Request/response processing

- Request/response transforms: header set/add/remove, query manipulation
- CORS: preflight handling and actual-response headers
- Compression: gzip/brotli/zstd negotiation with content-type filtering
- Response caching: TTL + stale-while-revalidate + vary + coalescing
- Request size limits: body, header bytes, header count
- Per-route method allowlist: 405 + Allow header

### AI gateway

- AI provider adapters: OpenAI, Anthropic
- Model alias table: client `model` values mapped to provider + model
- Failover chains: ordered fallback on 429/5xx
- Weighted canary: traffic split across model versions
- Routing policies: `fallback_chain` and `latency_cost`
- Pricing table: per-model micro-USD pricing for cost attribution
- Model governance: per-team model allowlists + shadow audit
- Guardrails: prompt-injection, PII, banned-content checks
- Prompt/response logging: opt-in capture with PII redaction
- Prompt experimentation: prompt versioning, A/B tests, regression evals
- MCP gateway: MCP server routing tool calls to upstreams
- Token budgets: per-consumer and per-policy token + cost caps

## Run it

```sh
cd quickstart/oss
../gen-certs.sh          # self-signed localhost cert + client CA + client cert
docker compose up        # builds the gateway image (../../Dockerfile.scratch)
curl --cacert ../certs/server.crt https://localhost:8443/
```

Linux hosts need `../certs/` readable by the container user: if
`gen-certs.sh` was not run with sudo, also run
`sudo chown -R 65532:65532 ../certs`
(macOS/Docker Desktop needs nothing extra).

The curl prints the demo page from the nginx upstream, having
negotiated TLS with the gateway, which routed `/` to the upstream and
proxied the response back.

### Admin API

The mTLS-only admin API is on port 2019. It requires a client
certificate signed by the client CA (generated by `gen-certs.sh`):

```sh
curl --cert ../certs/client.crt --key ../certs/client.key \
  --cacert ../certs/server.crt https://localhost:2019/health
curl --cert ../certs/client.crt --key ../certs/client.key \
  --cacert ../certs/server.crt https://localhost:2019/stats
curl --cert ../certs/client.crt --key ../certs/client.key \
  --cacert ../certs/server.crt https://localhost:2019/config
```

### Plaintext HTTP

Port 8080 serves plaintext HTTP (the `edge-http` listener), useful for
local development and health checks:

```sh
curl http://localhost:8080/healthz
```

## What is running

- `dwara` -- the gateway image built from `../../Dockerfile.scratch`:
  a static musl binary on `FROM scratch` (no shell, no libc, no CA
  bundle; upstream TLS roots are compiled in via webpki-roots). It
  terminates TLS on :8443, serves plaintext HTTP on :8080, and exposes
  the mTLS admin API on :2019. The analytics SQLite database is
  persisted in a named volume (`dwara-analytics`).
- `upstream` -- `nginx:alpine` serving the static page in
  `../upstream`.

## Config structure

The `dwara.yaml` is organized top-down:

1. **Listeners** -- bind addresses, TLS, listener-level authz/policies
2. **Routes** -- match rules, actions, per-route features (transforms,
   security headers, CORS, compression, caching, WAF, masking, etc.)
3. **Services** -- logical APIs, traffic splits, sticky sessions
4. **Upstreams** -- endpoint pools, load balancing, health checks,
   retries, timeouts, circuit breakers, discovery
5. **Consumers** -- authentication identities (API key, JWT, mTLS,
   HMAC), groups, quotas, token budgets
6. **Policies** -- reusable rule bundles (rate limit, retry, timeout,
   anomaly, adaptive, token budget)
7. **Gateway-level blocks** -- JWT/OIDC providers, HMAC auth, mTLS
   mapping, admin API, analytics, webhooks, AI, global settings

## Teardown

```sh
docker compose down
```

The `dwara-analytics` named volume persists the analytics database
across restarts. To remove it: `docker compose down -v`.

## Related guides

- [Getting started](../guide/getting-started) -- a first config from
  scratch
- [Configuration](../guide/configuration) -- the YAML shape and the
  config pipeline
- [Concepts and taxonomy](../guide/concepts) -- the vocabulary
- [Deployment](../guide/deployment) -- binaries, Docker, systemd
- [Admin API](../guide/admin-api) -- the mTLS admin surface
- [AI gateway](../guide/ai-gateway) -- provider adapters and aliases
- [Observability](../guide/observability) -- logs, metrics, traces
- [Analytics](../guide/analytics) -- the embedded analytics store
