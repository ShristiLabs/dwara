# NGINX Config Import (DW-065)

## Overview

dwara can import NGINX configs and generate a Dwara config YAML with
routes derived from the NGINX `location` blocks. This is a switching-
cost lever for teams migrating off NGINX to Dwara.

The import is a one-shot scaffolding step: it produces a config the
operator edits to add Dwara-specific features (authn, rate limiting,
etc.) that NGINX does not have native equivalents for.

## Usage

```sh
dwara import nginx <config> [--output dwara.yaml]
```

## Supported NGINX directives

- `server` blocks with `listen` (port) and `server_name` (host)
- `location` blocks with `proxy_pass` (upstream URL)
- `location` match modifiers:
  - `=` exact match
  - (none) prefix match
  - `~` regex (case-sensitive)
  - `~*` regex (case-insensitive)
  - `^~` prefix match (priority)
- `upstream` blocks with `server` directives (endpoints)

## Unsupported constructs

The import reports unsupported constructs as warnings (appended as
comments at the end of the generated YAML) so the operator knows what
to review manually:

- `if` directives (NGINX's `if` is notoriously unpredictable; use
  Dwara CEL conditions)
- `rewrite` directives (use Dwara path rewrite/regex rewrite)
- `auth_basic` (use Dwara authn: API key / Basic / JWT / mTLS)
- `limit_req` (use Dwara rate limiting)
- `try_files` (Dwara is a proxy, not a file server)
- Custom modules (Lua, Perl, etc.)
- `proxy_set_header`, `proxy_redirect`, `proxy_cache`, etc.
- SSL/TLS directives (use Dwara's listener TLS config)
- Logging directives (use Dwara's observability)
- `gzip` (use Dwara's compression)

## Example

Input (`nginx.conf`):

```nginx
http {
    upstream backend {
        server 127.0.0.1:9000;
        server 127.0.0.1:9001;
    }
    server {
        listen 8080;
        server_name api.example.com;
        location = /health {
            proxy_pass http://127.0.0.1:9000;
        }
        location /api {
            proxy_pass http://backend;
        }
        location ~ ^/v[0-9]+/ {
            proxy_pass http://127.0.0.1:9002;
        }
    }
}
```

Output (`dwara.yaml`):

```yaml
routes:
- name: route-0
  service: route-0-service
  match:
    path:
      type: exact
      value: /health
  action:
    type: proxy
- name: route-1
  service: backend-service
  match:
    path:
      type: prefix
      value: /api
  action:
    type: proxy
# ...
services:
- name: backend-service
  upstream: backend-upstream
# ...
upstreams:
- name: backend-upstream
  load_balancer: round_robin
  protocol: http1
  endpoints:
  - address: 127.0.0.1
    port: 9000
  - address: 127.0.0.1
    port: 9001
```

## Validation

The generated config round-trips through `dwara validate` -- the
importer produces valid Dwara config that can be loaded and served.

## Design

No new dependencies: a minimal NGINX config parser is implemented
inline (NGINX config syntax is simple enough for a line-based parser
to handle the common cases). The parser handles `http`, `upstream`,
`server`, and `location` blocks with `listen`, `server_name`,
`proxy_pass`, and `server` directives.

## Terraform provider

The Terraform provider over the admin API (the other half of DW-065)
is planned as a separate deliverable. The NGINX import is the
switching-cost lever that does not require a running gateway -- it
produces a config file the operator reviews and then applies via
`dwara validate` + `dwara run` or the admin API.
