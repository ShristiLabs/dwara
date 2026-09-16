# Extension use cases and recipes

Concrete recipes that map real problems to the right extension
surface. Every recipe states what works **today** and what is
forward-looking; code samples use only hostcalls from the
[supported set](./plugin-sdk#hostcall-support-matrix) unless clearly
marked otherwise.

Status legend: **works today** · **needs callouts** (blocked on the
`proxy_http_call` stub) · **embedding** (requires a build that embeds
dwara-core).

---

## Use case 1: user-subset migration to a new API version

### The problem

An API ships `/v1/user`. Enhancements land as a **new endpoint**
`/v2/user` — the old one stays untouched. Only a **subset of users**
(entitlements decided by a separate microservice) should be forwarded
to `/v2/user`; everyone else keeps hitting `/v1/user`. The gateway
must consult that decision and rewrite the target per request.

### Why the built-ins are not enough (and where they are)

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| [Traffic splitting](./traffic-splitting) (`services[].split`) | Weighted/canary split across upstreams | Percentage-based, not user-based; splits upstreams, not paths |
| Route `match.headers` + `rewrite` | Header-gated rewrite to `/v2/...` | Match criteria are static config — the decision lives in the microservice |
| [Authorization](./authorization) `allowed_consumers`/`required_claims` | Gate WHO may call a route | Gates access; cannot rewrite the target path |

If the entitlement can be **materialized as a header or JWT claim**
upstream of the gateway (your IdP adds `api_version: v2`), the whole
recipe collapses to config: one route matching `headers:
{ x-api-version: "2" }` with `rewrite: replace_prefix` — no extension
at all. Check that first.

### Options, with tradeoffs

| Option | How | Latency | Freshness of the decision | Works today? |
| --- | --- | --- | --- | --- |
| **A. Entitlement-snapshot plugin** (recommended) | The microservice publishes the allow-list; it lands in the plugin's `config:` block; the plugin rewrites `:path` per request | Zero added (local lookup) | Per config reload (publisher-triggered; seconds) | ✅ works today |
| B. Per-request callout plugin | Plugin calls the microservice (`proxy_http_call`), caches the verdict, rewrites | One hop on cache miss | Per request | ❌ `proxy_http_call` is a [stub](./plugin-sdk#hostcall-support-matrix) — the hostcall returns an error to the plugin today |
| C. Auth-layer header | IdP / edge auth sets a version header; config-only rewrite | Zero | Per token/session | ✅ works today (no extension) |

**Why A over B even when B lands:** a per-request hop adds tail
latency and a new failure domain at the edge. An entitlement list
rarely needs sub-second freshness — publish-on-change plus dwara's
hot reload gives you a tight loop with **no per-request dependency**
on the microservice. Keep B for genuinely dynamic verdicts (real-time
quotas, experiments).

### Implementation (Option A)

The plugin runs at the `request_headers` phase (after route
resolution, before authn), reads the user identity, looks it up in
its config snapshot, and rewrites the path prefix:

```rust
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

struct Migrator {
    /// Config snapshot, refreshed on every gateway reload.
    allowed_users: Vec<String>,
    from: String, // "/v1/"
    to:   String, // "/v2/"
}

impl HttpContext for Migrator {
    fn on_http_request_headers(&mut self, _n: usize, _eos: bool) -> Action {
        let user = self.get_http_request_header("x-user-id").unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();

        if !self.allowed_users.is_empty() && path.starts_with(&self.from) {
            let migrated = self.allowed_users.iter().any(|u| u == &user);
            let new_path = if migrated {
                format!("{}{}", self.to, &path[self.from.len()..])
            } else {
                path.clone()
            };
            // Rewrite the target before authn/authorization sees it.
            self.set_http_request_header(":path", Some(&new_path));
            self.log(LogLevel::Info, &format!("user={} -> {}", user, new_path));
        }
        Action::Continue
    }
}
```

Config wiring — the microservice's publisher writes the list, the
gateway picks it up on reload:

```yaml
plugins:
  - name: v2-migrator
    wasm: ./v2-migrator/target/wasm32-wasip1/release/v2_migrator.wasm
    phases: [request_headers]
    limits: { fuel: 1000000, memory_mb: 32 }
    config: |
      { "from": "/v1/", "to": "/v2/",
        "allowed_users": ["user-42", "user-77", "user-108"] }
routes:
  - name: user-api
    # match BOTH /v1/user and /v2/user (prefix), plugin picks the target
    match: { path: { type: prefix, value: /v1/ } }
    plugins: [v2-migrator]
    action: { type: proxy }
```

Operational notes:

1. **Publishing loop**: have the microservice write the config file
   (or the snippet it includes) and touch the main config; the file
   watcher reloads, the module re-reads `on_configure`, and health is
   preserved (unchanged checksum = no recompile; changed config =
   new generation). A bad JSON blob fails the plugin load loudly —
   routes fail closed with `500 plugin_unavailable`, so gate the
   publisher (validate before writing).
2. **Identity source**: `x-user-id` above; after authn you could
   gate on the consumer instead — but `request_headers` runs BEFORE
   authn by contract, so header/claim-based identity is the right
   input here (or move decisions into `request_body` phase if you
   need post-authz placement).
3. **Blast radius**: other routes are untouched; `/v1/...` routes
   without the plugin take the fast path.
4. **Testing**: unit-test the lookup/rewrite logic as plain Rust;
   integration-test with the harness pattern from
   [plugin-testing](./plugin-testing); use `dwara replay` to prove
   config-change neutrality for users outside the list.

### Option B sketch (when callouts land)

Same phase; instead of the local lookup, `dispatch_http_call` to the
microservice with a short TTL cache keyed by user, a strict timeout,
and an explicit fail-open (default `/v1/`) vs fail-closed (503)
decision made by YOU, not by accident. Track the
[hostcall matrix](./plugin-sdk#hostcall-support-matrix) — this page
will be updated when `proxy_http_call` moves to supported.

### Runnable demo

[`demos/13-extensibility-usecases/01-user-subset-migration/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/01-user-subset-migration)
runs this recipe end to end: the SDK-style plugin above, a mock
entitlement microservice, the publisher writing the generated
plugins-config include, and the hot-reload flip asserted live
(add/remove a user; the next request changes verdict; empty list =
everyone on `/v1`; plugin-less routes unaffected).

---

## More use cases

### Response PII redaction at the edge

- **Problem**: an upstream leaks card numbers / tokens into JSON
  bodies; compliance wants them masked before clients see them.
- **Surface**: proxy-wasm plugin at `response_body` — exactly the
  shipped [`response-body-redact`
  example](https://github.com/shristilabs/dwara/tree/main/plugins/examples/response-body-redact)
  (Luhn-validated card masking, length- and separator-preserving).
- **Tradeoffs**: body phases see **buffered** bodies only — streaming
  (SSE) and content-encoded responses are skipped and logged; the
  route buffers up to `limits.max_body_bytes` (default 1 MiB);
  redaction costs one body copy. Masking at the gateway is a
  seatbelt, not a fix — prefer fixing the upstream.
- **Status**: works today.
- **Runnable demo**: [`demos/13-extensibility-usecases/02-response-pii-redaction/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/02-response-pii-redaction)
  builds the shipped example by path against a mock leaky upstream:
  Luhn-gated keep-last-4 masking, the innocent 16-digit number
  untouched, and the SSE route skipping the phase.

### Custom request authentication

- **Problem**: a proprietary token scheme (not JWT, not API keys)
  must be verified per request.
- **Surface**: proxy-wasm plugin at `request_headers` that validates
  and **short-circuits 401** via `send_http_response` — the shipped
  [`static-auth`
  example](https://github.com/shristilabs/dwara/tree/main/plugins/examples/static-auth)
  is the skeleton (constant-time compare, `WWW-Authenticate`).
- **Tradeoffs**: check the built-ins first — [API
  keys](./authentication-methods), [JWT/JWKS](./authentication-methods#jwt),
  [HMAC signing](./hmac-signing), and [OIDC
  introspection](./oidc) cover the standard schemes with zero code.
  A plugin is for schemes only you speak. Secret rotation = plugin
  config reload; never bake long-lived secrets into the module.
- **Status**: works today.
- **Runnable demo**: [`demos/13-extensibility-usecases/03-custom-auth/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/03-custom-auth)
  builds the shipped `static-auth` example by path: 401 +
  `WWW-Authenticate` on missing/wrong credentials (no upstream dial),
  the correct token forwarded, a sibling unprotected route unaffected.

### Zero-upstream endpoints (feature flags, canned responses)

- **Problem**: a feature-flag endpoint, a health/echo endpoint, or a
  contract mock — logic too dynamic for a `respond`/`mock` action,
  too small for a service.
- **Surface**: [nano-service](./nano-services) — the route's action
  IS a WASM module with the whole response; no upstream hop.
- **Tradeoffs**: a dedicated ABI (not proxy-wasm), no network or
  filesystem inside the sandbox, 1 MiB default body cap, per-call
  timeout. Great for tiny handlers; wrong for anything needing I/O.
  If the response is static, prefer the built-in `respond`/`mock`
  actions; if it needs a decision call, that is use case 1's Option B.
- **Status**: works today.
- **Runnable demo**: [`demos/13-extensibility-usecases/04-feature-flag-nano/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/04-feature-flag-nano)
  serves a hand-written no_std module that answers
  `{"flag":<bool>}` parsed from the request path — no upstream
  configured on the route at all.

### Tenant-aware routing and tagging

- **Problem**: route/tag requests by tenant beyond what static match
  criteria express (tenant encoded in a signed cookie, a custom
  header grammar, path checksums).
- **Surface**: proxy-wasm plugin at `request_headers` — decode the
  tenant, set `x-tenant` for downstream matching/logging, optionally
  rewrite the path; the shipped
  [`request-tagger`](https://github.com/shristilabs/dwara/tree/main/plugins/examples/request-tagger)
  shows the header-stamping halves.
- **Tradeoffs**: keep rewrites at the edge — the rewritten path is
  what the upstream receives (applied to the forwarded request; no
  route re-match); header phases are zero-copy-fast (no body
  buffering).
  If tenant identity arrives as a JWT claim, built-in
  `required_claims` + transforms may suffice — check first.
- **Status**: works today.
- **Runnable demo**: [`demos/13-extensibility-usecases/05-tenant-routing/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/05-tenant-routing)
  decodes the tenant from a header grammar, stamps `x-tenant` on
  request and response, and rewrites `/portal/*` to
  `/tenant/<t>/*` — per-tenant routing and tagging asserted live.

### Your own rate limiting, config, cache, analytics, or secrets backend

- **Problem**: decisions/state must live in YOUR infrastructure
  (shared limiter in your store, config from etcd, analytics into
  your warehouse, secrets from your vault).
- **Surface**: [extension traits](./extension-traits) —
  `RateLimiter`, `ConfigSource`, `CacheStore`, `AnalyticsSink`,
  `SecretSource` — implemented in a binary that embeds dwara-core
  and registers them at startup. Enterprise backends (Redis, Vault)
  are just other implementations of the same seams.
- **Tradeoffs**: build-time integration (no hot loading); you own the
  failure semantics of your backend (fail-open rate limiting at the
  edge is usually wrong — decide explicitly). Per-request HTTP
  callouts from a plugin are NOT the substitute (callout stub), which
  is exactly why these traits exist.
- **Status**: works today (embedding).
- **Runnable demo**: [`demos/13-extensibility-usecases/06-embedding-analytics-sink/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/06-embedding-analytics-sink)
  is a standalone binary embedding dwara-core with a custom
  `AnalyticsSink`: every completed request (200s and 404s alike)
  flows through the registered backend.

### Per-request external decisions (entitlements, experiment buckets, fraud scores)

- **Problem**: the verdict genuinely must be computed per request by
  an external service (use case 1's Option B generalizes: feature
  experiments, real-time fraud, per-user quotas).
- **Surface**: proxy-wasm plugin with `proxy_http_call` + a
  short-TTL cache + explicit timeout policy.
- **Tradeoffs**: added tail latency, a hard dependency at the edge,
  cache-consistency windows; budget the callout under the route's
  timeouts and ALWAYS choose fail-open vs fail-closed deliberately.
- **Status**: **needs callouts** — `proxy_http_call` is stubbed
  today (the hostcall returns a clean error; the plugin must treat it
  as "decision unavailable"). Until it lands, use the
  snapshot-publishing pattern from use case 1 or an auth-layer
  header.
- **Runnable demo**: blocked on the same stub — no demo exists for
  this recipe yet. The snapshot-publishing fallback IS
  [`demos/13-extensibility-usecases/01-user-subset-migration/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/01-user-subset-migration),
  and this page will gain the callout demo when the hostcall lands.
