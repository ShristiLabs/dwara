# Importer details and post-import checklist

## NGINX

```sh
dwara-cli import nginx nginx.conf --output dwara.yaml
```

Reads `server` + `location` blocks carrying `proxy_pass`, and `upstream`
blocks. Mapping:

| NGINX | Dwara |
| --- | --- |
| `server { listen ... }` | `listeners[]` (protocol/TLS from directives) |
| `location <path> { proxy_pass }` | `routes[]` (`prefix` match from prefix locations; exact/regex where expressible) + `services`/`upstreams` |
| `upstream { server ... }` | `upstreams[].endpoints[]` |

Not converted (warning comments): `if`, `rewrite` (map to route
`rewrite:`/`redirect` actions by hand), `auth_basic` (map to consumers +
credentials - Basic entries are state-store-managed, or switch to API
keys), `limit_req` (map to `policies[].rate_limit` and attach to the
route/consumer), `try_files` (gateway concept: `respond`/`redirect`
actions or upstream behavior).

## Kong (decK declarative YAML or JSON)

```sh
dwara-cli import kong kong.yaml --output dwara.yaml
```

| Kong | Dwara |
| --- | --- |
| `services` | `services[]` + `upstreams[]` |
| `routes` | `routes[]` (paths/methods/hosts translate directly) |
| `consumers` | `consumers[]` |
| `key_auth` credentials | warning - re-issue via admin API (`POST /consumers/{name}/credentials`) |
| ACL groups | warning - set `groups:` on consumers; enforce with `allowed_groups`/`denied_groups` |
| plugins (rate-limiting, etc.) | warning - map per plugin (rate-limiting -> `policies[].rate_limit`; auth plugins -> credential families) |

## Envoy (static config YAML)

```sh
dwara-cli import envoy envoy.yaml --output dwara.yaml
```

| Envoy | Dwara |
| --- | --- |
| `listeners` | `listeners[]` |
| `clusters` | `upstreams[]` (+ balancer hints from LB policy) |
| `routes` | `routes[]` |
| HTTP filters (`ext_authz`, `ratelimit`, RBAC) | warning - map to built-in authz chain / rate-limit policies |
| `tcp_proxy` network filter | warning - see L4 `l4` listener block for the equivalent |
| TLS contexts | warning - fill `tls:` blocks by hand |

## OpenAPI 3.x

```sh
dwara-cli import openapi petstore.yaml --output dwara.yaml          # proxy scaffold
dwara-cli import openapi petstore.yaml --output dwara.yaml --mock   # mock API
```

- One route per **unique path** (methods from operations); placeholder
  upstream `127.0.0.1:9000`.
- Each route carries an `openapi` extension block: `operationId`,
  `summary`, `tags`, `method`, `path` - useful for tooling and reviews.
- `--mock` builds `action.type: mock` routes from response examples:
  `status`, `body` (or `body_file` - read at publish time, zero
  per-request I/O), optional `headers`, `delay_ms` for simulated latency.
- Enforce the contract inbound with
  `request_validation.body_schema` (mismatch -> `400 validation_failed`).
  Note it applies to all methods incl. bodyless GETs - scope it to
  POST/PUT routes.

## Post-import checklist (run in order)

```sh
dwara-cli validate dwara.yaml       # importers guarantee this passes
dwara-cli lint dwara.yaml           # unused entities, shadowed matches
grep -n '# WARNING' dwara.yaml      # the manual worklist
dwara-cli explain --config dwara.yaml --method GET --path /top-path   # spot-checks
dwara-cli diff imported.yaml current.yaml   # if replacing a live config
```

1. Replace placeholder upstreams (`127.0.0.1:9000`) with real endpoint
   pools + health/retries/timeouts (see dwara-traffic).
2. Recreate authn: consumers + credentials (Kong key-auth keys are NOT
   importable - re-issue and rotate).
3. Recreate traffic policy: rate limits, timeouts as named `policies[]`,
   attached at the right level.
4. TLS: fill listener `tls` blocks (Envoy contexts don't carry over).
5. Add security headers/CORS if the source had them at the app layer.
6. Set `DWARA_STATE_DB` if you use quotas (state that importers can't
   carry).
7. Shadow-verify before cutover (`mirror` a slice of traffic, or capture
   + `replay run --diff`).
