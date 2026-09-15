# Caching, transforms, CORS, compression, limits

## Response caching (route-level, local)

```yaml
    cache:
      ttl_secs: 60                     # default freshness
      stale_while_revalidate_secs: 300 # serve stale while refreshing
      max_body_bytes: 1048576          # bodies larger than this are not cached
      vary: [accept, accept-encoding]  # extra key dimensions
      coalescing:
        wait_ms: 5000                  # collapse concurrent identical GETs
                                       # (max 256 in-flight keys)
```

Semantics:

- **Key** = route + method + consumer + path + query + `vary` headers.
- Cacheable requests: plain `GET`/`HEAD` only, no request body, no
  `Authorization`/`Cookie`/upgrade requests.
- Storeable responses: 200s without `Set-Cookie`, without
  `no-store`/`private`/`no-cache`, not content-encoded, upstream `Vary`
  only naming keyed dimensions.
- Freshness: upstream `s-maxage` > `max-age` (shared-cache rules) > your
  `ttl_secs`. `stale-if-error` honored unless `must-revalidate`.
- ETag / `If-None-Match` 304 revalidation works in both directions.
- Response marker: `x-cache: hit | stale | miss | revalidated | bypass`.
- Bounds: 64 MiB total, 1 h idle eviction. In-memory - restarts clear it.

Purge (admin API): `POST /cache/purge` with `{"route": name}` |
`{"all": true}` (O(1), restart-durable) | `{"tag": t}` (keys off upstream
`Cache-Tags` response headers) | `{"url": u, "prefix": bool}`. Tag/url
indexes are in-memory and lost on restart.

Two-tier local+Redis distributed cache is **enterprise**
(`cache.redis` block).

## Transforms

```yaml
    transforms:
      request:
        headers:
          set:  { X-Forwarded-By: dwara }    # overwrite
          add:  { X-Gateway-Version: oss }   # add (may duplicate)
          remove: [X-Internal-Token]
        query:
          add:  { source: gateway }
      response:
        headers:
          set:  { X-Served-By: dwara-oss }
```

Runs after authz in the built-in filter chain; transforms are the standard
place to inject correlation/tenancy headers toward upstreams.

## CORS

```yaml
    cors:
      allowed_origins: ["https://app.example.com"]
      allowed_methods: [GET, POST, PUT, DELETE]
      allowed_headers: [Content-Type, Authorization, X-API-Key]
      expose_headers: [X-Request-Id]
      allow_credentials: true
      max_age_secs: 3600
```

Preflight handling + actual-response headers in one block. CORS preflights
are exempt from the "HEAD not implicitly granted by GET" method rule.

## Compression

```yaml
    compression:
      algorithms: [gzip, brotli]       # zstd also available
      min_size: 1024
      content_types: ["text/", application/json]
      excluded_content_types: [text/event-stream]   # never compress SSE
```

## Request limits and validation

```yaml
    limits:
      max_body_bytes: 1048576
      max_header_bytes: 8192
      max_header_count: 50

    request_validation:            # gate before the action runs
      body_schema:                 # JSON Schema; mismatch -> 400
        type: object               # validation_failed. NOTE: applies to ALL
        properties:                # methods incl. bodyless GETs - scope it
          name: { type: string }   # to POST/PUT routes.
        required: [name]

    masking:                       # response field redaction - FAIL-CLOSED:
      max_bytes: 1048576           # any unmaskable condition (non-JSON,
      fields: [/password, /secret] # missing pointer...) = 502, not a leak.
      groups:                      # groups only ADD fields; group names must
        internal: [/internal_debug]  # match consumer groups or config is
                                     # rejected.
```

## WebSocket policy

```yaml
    websocket:
      origins: ["https://app.example.com"]  # empty = all; a request with NO
                                            # Origin header is REJECTED (403)
      max_frames_per_sec: 100       # client->upstream only; burst 1s;
                                    # violation closes 1008
      idle_timeout_s: 600           # 1..86400
      max_frame_size_bytes: 1048576 # 1..16 MiB; over -> close 1009
```

## SSRF filter

Gateway-level `ssrf_filter` blocks the gateway itself from being tricked
into dialing internal ranges (relevant for redirect-following and webhook
targets). Enable when routes can influence gateway-initiated URLs.
