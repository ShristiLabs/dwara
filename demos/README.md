# Dwara demos

Runnable, self-contained demos of every gateway capability, organized
by **category**. Each category directory carries its own
`dwara.yaml`, a `docker-compose.yml` (the gateway plus the upstreams
that category needs), and numbered `test-*.sh` scripts that exercise
one feature each and assert the expected behavior.

The docs site walks the same demos with commentary:
[oss-quickstart](../docs-site/demos/oss-quickstart.md) for the
all-in-one quickstart, and each guide page's "Runnable demo" section
points at the category and test script that covers it.

## Categories

| Directory | Category | What it exercises |
|---|---|---|
| `01-routing/` | Core gateway & routing | Every match type and action: exact/prefix/regex paths, host, method, rewrites, redirects, direct and mock responses, API deprecation headers |
| `02-load-balancing/` | Load balancing & upstream management | The LB strategies (round-robin, least-requests, random, IP-hash, peak-EWMA), traffic splitting, sticky sessions, dynamic DNS discovery |
| `03-resilience/` | Traffic policy & resilience | Retries, circuit breaking, passive/active health, timeouts, hedging, admission queues against deliberately flaky and slow upstreams |
| `04-security-auth/` | Security & authentication | API keys, Basic, JWT, HMAC, mTLS, the authorization chain, IP ACLs, WAF-lite, masking |
| `05-request-response/` | Request/response processing | Header/query/JSON transforms, security headers, CORS, compression, response caching, request limits, WebSockets |
| `06-observability/` | Observability & analytics | `/metrics`, request IDs, structured logs, the analytics store and stream, alert webhooks |
| `07-ai-gateway/` | AI gateway | Provider adapters, model aliasing, failover, canary, pricing/budgets, guardrails, governance, MCP, streaming |
| `08-extensibility/` | Extensibility | Native plugin filters, Proxy-Wasm, CEL expressions, nano-services |
| `09-operations/` | Operations & config management | Hot reload, the mTLS admin API, config validation, secret references, CLI tooling |
| `10-tls-transport/` | TLS & transport | TLS termination, multi-SNI, SNI passthrough, HTTP/2 and HTTP/3 listeners |
| `11-enterprise/` | Enterprise features | The enterprise surface and the OSS-equivalent behavior shipped today (Redis, PostgreSQL, Vault topologies) |
| `12-protocol-translation/` | Protocol translation | gRPC proxying, gRPC-Web transcoding, REST<->gRPC bridging, OpenAPI-driven mocks |

## Shared infrastructure

`_shared/` holds everything the categories reuse:

- `gen-certs.sh` — wrapper around `quickstart/gen-certs.sh`; generates
  the localhost certificates every TLS-touching demo needs.
- `helpers.sh` — the PASS/FAIL assertion helpers every test script sources.
- `upstreams/` — small purpose-built services, built once and shared:
  - **echo** — reflects the request (method, path, headers, body) as JSON
  - **flaky** — returns 500 on a configurable share of requests (`/flaky/30` = 30%)
  - **slow** — delays responses by a configurable amount (`/slow/500` = 500 ms)
  - **static** — nginx serving static files
  - **ws-echo** — WebSocket echo server
  - **grpc / grpc-echo** — gRPC servers with unary and streaming methods
  - **ai-mock** — OpenAI-compatible mock provider (canned models, SSE streaming, rate-limit and error models for failover tests)
  - **idp-mock** — mock identity provider for OIDC flows
  - **webhook-receiver** — captures webhook events and analytics batches for assertions

## Build & run

One-time setup, then each category runs independently:

```sh
# One-time, from the repository root: generate certs
(cd demos/_shared && ./gen-certs.sh)

# One-time: build the shared upstream images
docker compose -f demos/_shared/docker-compose.yml build

# Run a category
cd demos/01-routing
docker compose up -d
./test-01-exact-match.sh     # any individual test
docker compose down
```

Every `test-*.sh` script follows the same contract: it waits for the
gateway to be healthy (`/healthz`), sends the test request(s),
asserts the expected status/headers/body, and prints PASS or FAIL
with a one-line description. A category's `README.md` covers its
prerequisites (env vars, secrets) and the full script list.

## Related

- `quickstart/oss/` and `quickstart/enterprise/` — single-gateway and
  CP/DP fleet quickstarts (a complement to these per-category demos).
- `docs-site/` — the published docs; every guide page links the demo
  that exercises it.
