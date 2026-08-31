# Config Import (DW-065)

## Overview

dwara can import external gateway/API configs and generate a Dwara
config YAML. This is a switching-cost lever for teams migrating from
NGINX, Kong, or Envoy to Dwara. Each import is a one-shot scaffolding
step: it produces a config the operator edits to add Dwara-specific
features (authn, rate limiting, etc.) that the source system does not
have native equivalents for, or handles via a different mechanism.

## Supported sources

| Source | Command | Format |
|---|---|---|
| NGINX | `dwara import nginx <config>` | NGINX config file |
| Kong | `dwara import kong <config>` | decK YAML or JSON |
| Envoy | `dwara import envoy <config>` | Envoy static config YAML |
| OpenAPI | `dwara import openapi <spec>` | OpenAPI 3.x YAML or JSON |

## NGINX import

See [nginx-import.md](nginx-import.md) for the full reference. The
NGINX importer parses `server` and `location` blocks with `proxy_pass`,
`upstream` blocks with `server` directives, and location match
modifiers (`=`, `~`, `~*`, `^~`). Unsupported constructs (`if`,
`rewrite`, `auth_basic`, `limit_req`, `try_files`, custom modules) are
reported as warnings appended as comments at the end of the generated
YAML.

## Kong import

```
dwara import kong <config> [--output dwara.yaml]
```

The Kong importer reads a Kong declarative config (decK/YAML or JSON
format) and maps:

- Kong `services` -> dwara service + upstream (the service `url` or
  `host`+`port` becomes the upstream endpoint)
- Kong `routes` -> dwara route (Kong `paths`, `methods`, `hosts` map to
  dwara path match, methods, and host)
- Kong `upstreams` with `targets` -> dwara upstream + endpoints
- Kong `consumers` -> dwara consumer (name only)

### Unsupported Kong constructs

The import reports unsupported constructs as warnings (appended as
comments at the end of the generated YAML):

- `plugins` (key-auth, acl, rate-limiting, cors, etc.) -- use Dwara's
  native authn, authz, rate limiting, and CORS systems
- `key-auth-credentials`, `jwt-credentials`, `hmac-auth-credentials`,
  `basic-auth-credentials` -- credentials are not migrated; use Dwara's
  credential config
- `acl_groups` -- use Dwara consumer groups + authorization
- `strip_path: true` -- use Dwara path rewrite (strip_prefix)
- `certificates`, `ca_certificates` -- use Dwara's listener TLS config
- `vaults`, `keys` -- use Dwara's secret references

### Example

Input (`kong.yaml`):

```yaml
services:
  - name: api-service
    url: http://127.0.0.1:9000
routes:
  - name: api-route
    service:
      name: api-service
    paths:
      - /api
    methods:
      - GET
      - POST
    hosts:
      - api.example.com
upstreams:
  - name: backend
    targets:
      - target: 127.0.0.1:9000
        weight: 100
      - target: 127.0.0.1:9001
        weight: 100
```

Output: a Dwara config YAML with one route (`api-route`), one service
(`api-service`), and two upstreams (`api-service-upstream` with the
service URL endpoint, and `backend` with two endpoints).

## Envoy import

```
dwara import envoy <config> [--output dwara.yaml]
```

The Envoy importer reads an Envoy static config (YAML) and maps:

- `static_resources.listeners` -> dwara listener (address + port)
- `static_resources.clusters` -> dwara upstream + endpoints (each
  cluster's `load_assignment` endpoints become dwara endpoints)
- Listener `route_config.virtual_hosts.routes` -> dwara route (route
  match prefix/path -> dwara path match; route action cluster -> dwara
  service + upstream)

### Unsupported Envoy constructs

The import reports unsupported constructs as warnings:

- HTTP filters (`envoy.filters.http.ext_authz`, `ratelimit`, `rbac`,
  `compressor`, `cors`, `jwt_authn`, `wasm`, etc.) -- use Dwara's
  native equivalents
- Network filters (`envoy.filters.network.tcp_proxy`, `redis`, etc.) --
  Dwara is an HTTP gateway; L4 proxying is out of scope for this import
- `tls_context` / `transport_socket` -- use Dwara's listener TLS config
- DNS-based cluster discovery (`STRICT_DNS`, `LOGICAL_DNS`) -- use
  Dwara's `dns_discovery` on the upstream

### Example

Input (`envoy.yaml`):

```yaml
static_resources:
  listeners:
    - name: main
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                route_config:
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: /api
                          route:
                            cluster: backend_cluster
                http_filters:
                  - name: envoy.filters.http.router
  clusters:
    - name: backend_cluster
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9000
```

Output: a Dwara config YAML with one listener (`main` on port 8080),
one route (`backend-route-0` matching `/api`), and one upstream
(`backend_cluster` with endpoint `127.0.0.1:9000`).

## Warning behavior

All importers append unsupported-construct warnings as YAML comments at
the end of the generated config:

```yaml
# --- Import warnings ---
# The following Kong constructs are not supported and were skipped.
# Review and handle them manually in Dwara config.
# - plugin 'key-auth' -- use Dwara's native equivalent (authn, authz, ...)
```

The generated config is always valid (it round-trips through
`dwara validate`); the warnings are advisory, telling the operator what
to review and handle manually.
