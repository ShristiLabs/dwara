# dwara developer documentation

In-depth documentation for dwara contributors: how features work
internally, the rationale behind non-obvious design choices, and
diagrams of the moving parts. This is distinct from
[`/docs-site`](../docs-site), the published end-user (operator) site —
if you're writing about how to *configure* or *operate* a feature, it
belongs there; if you're writing about *how the code implements it and
why*, it belongs here.

Start with [`AGENTS.md`](../AGENTS.md) at the repo root for the
practical contributor rules (build/test commands, code organization,
conventions) — this directory goes deeper on specific subsystems than
AGENTS.md's index-level summaries.

## Status of this directory

Feature areas written up so far (M1-M4 complete):

- [Architecture](./architecture.md) — bounded-context layout, the
  config pipeline, dependency direction, and the request/reload
  lifecycles.
- [AI provider adapters](./features/ai-provider-adapters.md) — the
  DW-075 translation layer: OpenAI facade in, OpenAI/Anthropic/Gemini
  adapters out, providers-as-upstreams, the pure `ProviderAdapter`
  seam DW-076+ compose on. Now also covers DW-076 routing/failover,
  DW-077 streaming, DW-078 token budgets, DW-079 cost attribution,
  DW-080 credential pools, DW-081 prompt logging, DW-082 guardrails,
  DW-083 semantic caching, DW-084 model governance, DW-085 routing
  policies, DW-086 prompt experimentation, DW-087 MCP gateway,
  DW-113 agent principals.
- [TLS](./features/tls.md) — termination (multi-SNI), passthrough, hot
  reload, outbound trust.
- [Dataplane and proxy](./features/dataplane-proxy.md) — routing,
  matching precedence, rewrites, streaming proxy semantics. Now also
  covers DW-088 HTTP/3 ingress and DW-089 adaptive + origin-driven
  limits.
- [Load balancing](./features/load-balancing.md) — the four
  algorithms, lock-free picks, slow start. Now also covers DW-090
  anomaly scoring + latency-aware load balancing.
- [Admission queues and backpressure](./features/admission-queue.md)
  — bounded admission queues that make the gateway concurrency cap
  degrade gracefully (latency rises before shedding begins) instead
  of the DW-016 cliff; per-priority queue splitting, queue-timeout
  and queue-full sheds with Retry-After (DW-053).
- [WAF-lite heuristic filtering](./features/waf-lite.md) — per-route
  pattern matching for SQLi/XSS/path-traversal signatures on the path,
  query, headers, and body; dry-run (audit-log-only) mode; the
  request-path position and false-positive posture (DW-051).
- [Traffic splitting and sticky sessions](./features/canary-split.md)
  — service-level weighted splits across upstreams (canary releases,
  blue-green switches) with a stateless weighted-hash pick, and the
  gateway-set sticky cookie that pins a session to its branch (and to
  one endpoint when the branch runs ip_hash), layered over the
  per-upstream balancer (DW-040). Now also covers DW-091 auto-canary
  analysis.
- [Resilience](./features/resilience.md) — passive/active health,
  retries, circuit breaking, load shedding, and how the layers compose.
- [Rate limiting](./features/rate-limiting.md) — GCRA, stacked
  windows, bounded key-space eviction.
- [Quotas and metering](./features/quotas.md) — per-consumer daily
  and monthly request budgets over durable state-store counters
  (distinct from rate limiting), the 429 contract, and the four
  metering surfaces: admin usage query, metrics, analytics,
  near-limit events (DW-033).
- [Route edge policies](./features/edge-policies.md) — CORS,
  response compression, per-route request limits (DW-027).
- [Request/response transforms and security
  headers](./features/transforms.md) — header/query manipulation,
  size-capped JSON-pointer body transforms (the one buffering
  transform), and edge security-header injection (DW-028).
- [Response field masking](./features/masking.md) — fail-closed
  per-consumer-group redaction of response JSON fields (the inverted
  DW-028 gates: encoded/non-JSON/over-cap/pointer-miss all 502), the
  union-only group rule, and the audit trail (DW-029).
- [Response caching](./features/caching.md) — the local cache behind
  the `CacheStore` seam: per-consumer keys with Vary folding, TTL +
  stale-while-revalidate + ETag revalidation, epoch invalidation
  (purge/config-change), and the zero-buffering bounds (DW-037).
- [Maintenance mode and policy dry-run](./features/maintenance-dry-run.md)
  — the per-route 503 + Retry-After availability short-circuit and
  the per-attachment monitor flags on every rejecting policy phase,
  with the metric/log report (DW-041).
- [Alert and event webhooks](./features/alerting.md) — the in-process
  event bus, the emission sites (breaker/health/config publish), and
  the budget-bounded webhook deliverer (DW-044).
- [Usage reports and exports](./features/usage-reports.md) — scheduled
  per-consumer usage statements off the analytics store as
  deterministic CSV/JSON files: the reconcile-with-the-query-API
  contract, the backfilling scheduler, quota column alignment, and the
  `export_runs` ledger (DW-120).
- [Embedded analytics](./features/analytics.md) — the analytics store
  behind the admin `/analytics/*` endpoints: the fire-and-forget write
  path, the rollup cascade, bounded disk, and the query surface
  (DW-043). Now also covers DW-092 ML insights, DW-093 business
  metrics dimensions, and DW-095 federated analytics.
- [Real-time analytics stream](./features/analytics-stream.md) — the
  opt-in access-record firehose: every completed request's record to
  an external sink as ordered NDJSON batches (one webhook delivery per
  batch through the DW-044 engine), the `RecordSink` seam with the
  Kafka slot documented, and the never-blocks-the-dataplane contract
  (DW-121).
- [gRPC and WebSocket polish](./features/grpc-websocket.md) — gRPC
  over H2 (TE forwarded, grpc-timeout enforced as the RPC's total
  budget across forward and body, 504 + grpc-status 4 on expiry,
  trailers through) and the managed WebSocket tunnel (origin
  allowlist at the handshake, post-upgrade frame-rate policing with
  the 1008 close), hand-rolled with zero new dependencies (DW-039).
- [API versioning](./features/versioning.md) — the version routing
  patterns (path segment / header / query / Accept media type), the
  `match.accept` criterion, Deprecation/Sunset header automation
  (DW-048).
- [Authentication and authorization](./features/authn-authz.md) — the
  five credential families (API key, Basic, JWT, mTLS, HMAC request
  signing), the authz precedence chain, IP ACLs.
- [Secrets](./features/secrets.md) — `${...}` secret references in
  config, compile-time resolution, typed redaction of config echoes
  (DW-045).
- [State store](./features/state-store.md) — SQLite store, migrations,
  cache coherence model.
- [Observability](./features/observability.md) — spans, logs, metrics,
  the OTLP feature gate, redaction. Now also covers DW-097
  tokio-console integration.
- [Admin API](./features/admin-api.md) — mTLS-only auth, the
  `PATCH /config` pipeline, why a separate crate.
- [CLI](./features/cli.md) — the library-shaped subcommands, exit-code
  contract, the load generator rig.
- [Protocol hardening](./features/protocol-hardening.md) — parser
  bounds, the body-inactivity gap, how they compose.
- [Extension points](./features/extension-points.md) — the five
  swappable traits and how to implement a new backend.
- [OpenAPI import and mock mode](./features/openapi-import.md) —
  scaffolding configs from OpenAPI 3.x specs, mock responses without
  an upstream, and request-body validation against a JSON-Schema subset.
- [OAuth2 client-credentials and mTLS consumer mapping](./features/oauth2-mtls.md)
  — the gateway obtaining an access token from an external token
  endpoint and forwarding it as Bearer to the upstream (replacing the
  client's Authorization), gateway-level mTLS certificate-to-consumer
  mapping by fingerprint or subject CN (independent of the per-consumer
  mtls credential), and X-Client-Cert-* identity-forwarding headers
  with inbound spoofing prevention (DW-035).
- [Enterprise licensing gate](./features/licensing.md) — the
  `LicenseGate` runtime value that holds an optional verified license
  and gates enterprise features behind feature-claim flags; the `ent`
  cargo feature, offline Ed25519 verification, the grace-period
  degradation curve, and the `dwara_license_status` metric (DW-032).
- [CP/DP split](./features/cp-dp-split.md) — the control-plane /
  data-plane split architecture: controller-to-edge gRPC config
  distribution, HA controller, edge-survives-outage caching (DW-066).
  Now also covers DW-094 global load balancing + data residency and
  DW-098 fleet operations.
- [Web Console](./features/web-console-v1.md) — the static SPA served
  from the mTLS admin listener: read-only diagnostic views (DW-117)
  and the v2 full-CRUD + fleet/workspace views (DW-118).

When a feature changes materially, update its page in the same
change — follow the established pattern: what the feature does, why
it's built that way (cite the `DW-xxx`/`#nnn` markers and module-level
`//!` doc comments — they carry most of the rationale already), a
mermaid diagram if it clarifies a flow or state machine, and links to
the owning source files and test suites.
