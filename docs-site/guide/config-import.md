# Config Import

dwara can import external gateway configs from NGINX, Kong, Envoy, and
OpenAPI specs to scaffold your gateway config. This is a switching-cost
lever for teams migrating to Dwara.

## NGINX import

```sh
dwara-cli import nginx nginx.conf --output dwara.yaml
```

Parses NGINX `server` and `location` blocks with `proxy_pass` and
`upstream` blocks. Unsupported constructs (`if`, `rewrite`,
`auth_basic`, `limit_req`, `try_files`) are reported as warnings in the
generated config.

## Kong import

```sh
dwara-cli import kong kong.yaml --output dwara.yaml
```

Reads a Kong declarative config (decK/YAML or JSON) and maps Kong
services, routes, upstreams, and consumers to Dwara entities.
Unsupported constructs (plugins, key-auth credentials, ACL groups) are
reported as warnings.

### Example

```yaml
# kong.yaml
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
```

## Envoy import

```sh
dwara-cli import envoy envoy.yaml --output dwara.yaml
```

Reads an Envoy static config (YAML) and maps listeners, clusters, and
routes to Dwara entities. Unsupported constructs (HTTP filters like
ext_authz, ratelimit, RBAC; network filters like tcp_proxy; TLS
contexts) are reported as warnings.

### Example

```yaml
# envoy.yaml
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

## OpenAPI import

```sh
dwara-cli import openapi petstore.yaml --output dwara.yaml
```

Reads an OpenAPI 3.x spec and generates a Dwara config with one route
per unique path. See [OpenAPI import and mock mode](./openapi-import)
for details.

## Warnings

All importers append unsupported-construct warnings as YAML comments at
the end of the generated config. The generated config is always valid
(it passes `dwara-cli validate`); the warnings are advisory, telling you
what to review and handle manually.
