# Demo 05: tenant-aware routing and tagging

The
[tenant-aware-routing recipe](../../../docs-site/guide/extensibility-use-cases.md):
route/tag requests by tenant beyond what static match criteria
express. Tenant identity arrives in a custom header grammar
(`x-org-domain: acme.com` -> tenant `acme`, the first DNS label); a
signed-cookie or JWT-claim grammar would slot into the same decode
step.

## What runs

- `plugin/` -- the `tenant-router` SDK-style proxy-wasm plugin
  (Rust proxy-wasm 0.2 SDK, wasm32-wasip1), two phases on one
  per-request instance:
  - `request_headers`: decode the tenant, stamp the REQUEST
    `x-tenant` (what downstream matching/logging and the upstream
    see), rewrite `/portal/<rest>` -> `/tenant/<tenant>/<rest>` --
    after route resolution; the gateway applies the rewrite to the
    FORWARDED request (route matching and the policy phases evaluated
    the original `/portal/...` target)
  - `response_headers`: stamp the RESPONSE `x-tenant` so the client
    observes the verdict
- `tenants-upstream.py` -- answers `/tenant/<t>/*` per tenant (the
  rewritten path IS the request path it receives) and echoes the
  `x-tenant` request header it was stamped with (standing in for
  per-tenant upstream pools; the prefix IS the routing decision)

One route, one upstream: the plugin runs after route resolution, so
path rewrites select the per-tenant PREFIX, not a different route.

## What test.sh asserts

1. `x-org-domain: acme.com` -> the upstream serves the rewritten
   `/tenant/acme/...` path and decodes tenant `acme` from it
2. the upstream SAW the stamped `x-tenant` request header
3. the client response carries the stamped `x-tenant` response header
4. `x-org-domain: globex.com` -> tenant `globex` likewise
5. no org header -> the safe default tenant `public`

## Notes

- The `:path` rewrite is REAL: the gateway applies a changed `:path`
  write to the forwarded request (after the route's own rewrite, with
  no route re-match -- the plugin's target is the final say for the
  upstream; see the "Header conventions" note in
  `crates/dwara-core/src/dataplane/plugin_dispatch.rs`). The mock keys
  on the request path alone, exactly like a per-tenant backend would.

## Run

```sh
./test.sh          # builds the plugin, starts the upstream +
                   # gateway, asserts
```

Ports: gateway 18241, tenants upstream 18242.
