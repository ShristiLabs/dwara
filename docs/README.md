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

Feature areas written up so far (M1 complete; M2 in progress):

- [Architecture](./architecture.md) — bounded-context layout, the
  config pipeline, dependency direction, and the request/reload
  lifecycles.
- [TLS](./features/tls.md) — termination (multi-SNI), passthrough, hot
  reload, outbound trust.
- [Dataplane and proxy](./features/dataplane-proxy.md) — routing,
  matching precedence, rewrites, streaming proxy semantics.
- [Load balancing](./features/load-balancing.md) — the four
  algorithms, lock-free picks, slow start.
- [Resilience](./features/resilience.md) — passive/active health,
  retries, circuit breaking, load shedding, and how the layers compose.
- [Rate limiting](./features/rate-limiting.md) — GCRA, stacked
  windows, bounded key-space eviction.
- [Route edge policies](./features/edge-policies.md) — CORS,
  response compression, per-route request limits (DW-027).
- [Request/response transforms and security
  headers](./features/transforms.md) — header/query manipulation,
  size-capped JSON-pointer body transforms (the one buffering
  transform), and edge security-header injection (DW-028).
- [Maintenance mode and policy dry-run](./features/maintenance-dry-run.md)
  — the per-route 503 + Retry-After availability short-circuit and
  the per-attachment monitor flags on every rejecting policy phase,
  with the metric/log report (DW-041).
- [Alert and event webhooks](./features/alerting.md) — the in-process
  event bus, the emission sites (breaker/health/config publish), and
  the budget-bounded webhook deliverer (DW-044).
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
  the OTLP feature gate, redaction.
- [Admin API](./features/admin-api.md) — mTLS-only auth, the
  `PATCH /config` pipeline, why a separate crate.
- [CLI](./features/cli.md) — the library-shaped subcommands, exit-code
  contract, the load generator rig.
- [Protocol hardening](./features/protocol-hardening.md) — parser
  bounds, the body-inactivity gap, how they compose.
- [Extension points](./features/extension-points.md) — the five
  swappable traits and how to implement a new backend.

When a feature changes materially, update its page in the same
change — follow the established pattern: what the feature does, why
it's built that way (cite the `DW-xxx`/`#nnn` markers and module-level
`//!` doc comments — they carry most of the rationale already), a
mermaid diagram if it clarifies a flow or state machine, and links to
the owning source files and test suites.
