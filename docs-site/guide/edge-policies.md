# CORS, compression, and request limits

Routes accept three optional blocks — `cors`, `compression`, and
`limits` — that control what the gateway does at its edge: answering
browser cross-origin requests, shrinking response bodies, and capping
how large a request may be. All three are off by default, and each is
a plain part of the route (exactly one of each per route), not a
reusable `policies` attachment like retries or rate limiting. For the
exhaustive field list see the
[configuration schema](../reference/configuration-schema).

## CORS

```yaml
routes:
  - name: api
    service: api-service
    match:
      path:
        type: prefix
        value: /api/
      methods: [GET, POST, PUT, DELETE, OPTIONS]
    action:
      type: proxy
    cors:
      allowed_origins:
        - https://app.example.com
      allowed_methods: [GET, POST, PUT, DELETE]
      allowed_headers: [content-type, x-api-key]
      expose_headers: [x-request-id]
      allow_credentials: true
      max_age_secs: 600
```

**Preflight requests need `OPTIONS` in `match.methods`.** The method
list is part of route matching, which runs before any CORS logic — a
route whose method list excludes `OPTIONS` never matches a preflight
and the browser gets a 404.

With a `cors` block on the matched route:

- **Preflights** (`OPTIONS` carrying `Origin` and
  `Access-Control-Request-Method`) are answered by the gateway itself
  with `204` — never forwarded to the upstream, and not subject to
  authentication or rate limiting (browsers send preflights without
  credentials). A preflight the policy rejects — origin, method, or
  requested header not allowed — is still answered `204`, but with no
  CORS headers, which the browser reports as a failed preflight.
- **A plain `OPTIONS`** without the preflight markers is not
  intercepted; it proxies like any other request.
- **Actual responses** on the route carry
  `Access-Control-Allow-Origin` (the echoed request origin, or `*`
  under a wildcard policy), `Access-Control-Allow-Credentials: true`
  when configured, `Access-Control-Expose-Headers` when configured,
  and `Vary: Origin`. Requests whose `Origin` is not allowed get no
  CORS headers — the response passes through unchanged.

Origins match exactly, after normalization: scheme and host are
compared case-insensitively and a default port (`:443` on https,
`:80` on http) may be omitted. `https://APP.Example.com:443` and
`https://app.example.com` are the same origin. Origins with userinfo
(`https://user@example.com`) are rejected — browsers never send
them. Subdomains are NOT
matched implicitly — list each origin. The single entry `*` allows
any origin, but validation rejects combining `*` (origins or
headers) with `allow_credentials: true`, per the Fetch spec.

One debugging note: responses the gateway generates itself before the
route's action runs — a 401 from authentication, a 429 from rate
limiting, a 413/431 from the limits below — do not carry CORS
headers. A browser may then show a generic network/CORS error for
what is really an auth or limit rejection; check the gateway's access
log for the real status.

## Response compression

Compression is opt-in per route. When enabled, the gateway negotiates
against the request's `Accept-Encoding` and compresses the response:

```yaml
    compression:
      algorithms: [gzip, brotli, zstd]   # preference order
      level: 6                           # clamped per algorithm
      min_size: 1024                     # skip small bodies
      content_types: [text/, application/json]
      excluded_content_types: [text/event-stream]
```

- `algorithms` is a **preference order**: the first entry the client
  accepts wins. Clients that accept nothing the route offers (or send
  no `Accept-Encoding` at all) get the body untouched — the gateway
  never errors over compression. Note the config spelling is the
  algorithm name (`brotli`), not the wire token (`br`).
- `level` is one value across all algorithms and is clamped per
  algorithm at encode time (gzip 0-9, brotli 0-11, zstd 0-22).
  Omitted: per-algorithm defaults tuned for a proxy hot path.
- `min_size` (default 1024) skips responses whose known size is below
  it — a declared `Content-Length`, or the exact size of bodies the
  gateway generates itself (`respond` actions, redirects, which carry
  no `Content-Length`). Responses of unknown length (streamed) are
  always candidates.
- `content_types` restricts compression to matching `Content-Type`
  prefixes (empty = every type); `excluded_content_types` is checked
  after it and wins.

Never compressed: responses that already carry a `Content-Encoding`,
body-less statuses (1xx/204/304), zero-length bodies, and `101`
protocol upgrades (WebSocket tunnels). Compression is streaming-safe:
the body is compressed and flushed chunk-by-chunk and never buffered
whole, so Server-Sent Events and slow streams reach the client as
they arrive. Every response on a compression route that is not
already encoded carries `Vary: Accept-Encoding`, compressed or not,
so shared caches key it correctly.

## Request limits

Per-route caps on request size, enforced right after the route
matches — before authentication and before any upstream contact when
the size is declared:

```yaml
    limits:
      max_body_bytes: 10485760      # 10 MiB request bodies
      max_header_count: 50
      max_header_bytes: 16384
```

- `max_body_bytes` — a request declaring a larger `Content-Length` is
  rejected `413` immediately. A body of unknown length (chunked
  uploads) is aborted the moment it crosses the cap.
- `max_header_count` — the number of header fields (a repeated header
  counts each time); over the cap is `431`.
- `max_header_bytes` — the total size of all header names and values;
  over the cap is `431`.

All rejections use the standard JSON error envelope
(`{error:{code,message,request_id}}`) with codes
`request_body_too_large` and `request_headers_too_large`. These are
route-level limits on top of the process-wide parser bounds — see
[protocol hardening](./operations#protocol-hardening), which applies
to every listener regardless of routes.

## Ordering and reload

For a matched request the stages run in a fixed order: route limits,
then CORS preflight handling, then authentication, authorization,
rate limiting, and admission, then the route's action, and finally
the response gains compression and CORS headers. See the
[request pipeline](../architecture/overview#request-pipeline) for the
full picture. All three blocks reload live with the rest of the
config — an atomic snapshot swap, no restart.
