# Use case: tenant-aware routing and tagging

Route and tag requests by tenant when tenant identity lives in a form
static match criteria cannot express: a signed cookie, a custom
header grammar, a path checksum. The gateway should decode the
tenant once, tag the request for downstream matching and logging,
and steer the forwarded target per tenant.

## Why the built-ins are not enough

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| Route `match.headers` / `match.path` | Static criteria against the raw request | The tenant is ENCODED — a grammar to decode, not a value to equal |
| JWT `required_claims` | Gate on claims when identity is a JWT | The grammar here is not a JWT (cookie, custom header) |
| [Transforms](../transforms) | Header/path rewrites from config | Cannot compute (decode a grammar, derive a prefix) — only rearrange known values |

If tenant identity arrives as a JWT claim, built-in `required_claims`
plus transforms may suffice — check first. A plugin is for the
decoding step only you can write.

## Options, with tradeoffs

| Option | How | Where the tenant lands | Cost | Works today? |
| --- | --- | --- | --- | --- |
| **A. Two-phase plugin** (recommended) | `request_headers` decodes + tags + rewrites `:path`; `response_headers` tags the response | `x-tenant` request/response headers, rewritten path prefix | Header phases: zero-copy fast, no body buffering | Yes |
| B. IdP-normalized header | Edge/IdP decodes the tenant into a plain header; config matches on it | A header your edge sets | Zero at the gateway; moves the problem upstream | Yes (no extension) |
| C. Per-tenant routes with static match | One route per tenant grammar case | Route explosion in config | Config sprawl; still cannot decode | Yes, rarely sensible |

A over B when you own the gateway edge but not the client's token
format; B when an IdP already sits in front and can stamp the header.

## Implementation

The complete plugin from the
[runnable demo](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/05-tenant-routing)
(Rust, proxy-wasm 0.2 SDK, `wasm32-wasip1`). The grammar here is
deliberately simple — `x-org-domain: acme.com` means tenant `acme`
(the first DNS label); a signed-cookie or JWT-claim grammar slots
into the same decode step. Two phases share one per-request instance,
so the tenant decoded at request time survives to the response:

```rust
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

const ORG_HEADER: &str = "x-org-domain";
const TENANT_HEADER: &str = "x-tenant";
const PORTAL_PREFIX: &str = "/portal/";
const TENANT_PREFIX: &str = "/tenant/";
const DEFAULT_TENANT: &str = "public";

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(TenantRoot)
    });
}

struct TenantRoot;

impl Context for TenantRoot {}

impl RootContext for TenantRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(TenantFilter { tenant: None }))
    }
}

/// The per-request filter. `tenant` is decoded at request_headers and
/// reused at response_headers (same instance).
struct TenantFilter {
    tenant: Option<String>,
}

/// The header grammar: the first DNS label of the org domain.
/// Missing or unparsable -> the safe default tenant.
fn tenant_from_org(value: Option<&str>) -> String {
    match value
        .filter(|v| !v.is_empty())
        .and_then(|v| v.split('.').next())
        .filter(|label| !label.is_empty())
    {
        Some(label) => label.to_string(),
        None => DEFAULT_TENANT.to_string(),
    }
}

impl Context for TenantFilter {}

impl HttpContext for TenantFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let tenant = tenant_from_org(self.get_http_request_header(ORG_HEADER).as_deref());
        self.set_http_request_header(TENANT_HEADER, Some(&tenant));

        let path = self.get_http_request_header(":path").unwrap_or_default();
        if let Some(rest) = path.strip_prefix(PORTAL_PREFIX) {
            let rewritten = format!("{TENANT_PREFIX}{tenant}/{rest}");
            // Rewrite at the edge: the gateway applies the changed
            // :path to the FORWARDED request (the final say for the
            // upstream target, after route resolution with no route
            // re-match).
            self.set_http_request_header(":path", Some(&rewritten));
            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!("tenant={tenant} {path} -> {rewritten}"),
            );
        }
        self.tenant = Some(tenant);
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if let Some(tenant) = &self.tenant {
            self.add_http_response_header(TENANT_HEADER, tenant);
        }
        Action::Continue
    }
}
```

Three effects, in order: the request is tagged `x-tenant` (what
downstream matching, logging, and the upstream see); the path
`/portal/<rest>` becomes `/tenant/<tenant>/<rest>` (the prefix IS the
routing decision — per-tenant backends key off it); the response
carries `x-tenant` so the client observes (and can cache) the
verdict.

## Configuration

One route, one upstream — the plugin runs after route resolution, so
the path rewrite selects the per-tenant prefix, not a different
route:

```yaml
listeners:
  - name: tenant-http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: portal
    service: tenants-service
    match: { path: { type: prefix, value: /portal/ } }
    action: { type: proxy }
    plugins: [tenant-router]

services:
  - name: tenants-service
    upstream: tenants-upstream-pool

upstreams:
  - name: tenants-upstream-pool
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: tenant-router
    wasm: ./tenant-router/target/wasm32-wasip1/release/tenant_router.wasm
    phases: [request_headers, response_headers]
```

## Operational notes

1. **The rewrite is REAL**: the rewritten path is what the upstream
   receives — applied to the forwarded request after the route's own
   rewrite, with no route re-match. Route matching and the policy
   phases evaluated the original `/portal/...` target; keep authz
   rules keyed on the original path (or move tenant authz into the
   plugin's verdict).
2. **Header phases are fast**: no body buffering, zero-copy diffs
   (untouched headers keep their original bytes).
3. **Failure behavior**: an unparsable or missing grammar value falls
   back to the safe default tenant (`public` above) rather than
   failing the request — make that choice deliberately per grammar; a
   mis-decoded tenant should probably be an explicit 4xx for signed
   grammars.
4. **Hot reload**: config-side changes to the plugin definition
   reload normally; the module itself needs no config.
5. **Caching interactions**: the response tag (`x-tenant` via
   `response_headers`) is part of the cached response, so per-tenant
   responses cache under their own verdict; a plugin definition
   change bumps the referencing routes' cache epochs.

## Testing

Unit-test `tenant_from_org` as plain Rust (the decode is pure).
Integration-test the wire behavior with the harness from [Plugin
testing](../plugin-testing): tagged request header at the upstream,
rewritten path, tagged response header, safe default on a missing
header. The demo's `test.sh` asserts exactly these.

## Status

Works today, in every build.

## Runnable demo

[`demos/13-extensibility-usecases/05-tenant-routing/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/05-tenant-routing)
decodes the tenant from the header grammar, stamps `x-tenant` on
request and response, and rewrites `/portal/*` to
`/tenant/<t>/*` — per-tenant routing and tagging asserted live
against a per-tenant-prefix mock upstream.
