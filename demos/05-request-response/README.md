# Category 05: Request/Response Processing

A demo of dwara's request/response processing capabilities: header & query
transforms, security-header injection, CORS, response compression, response
caching, response field masking, request limits + JSON Schema body
validation, and WebSocket proxying.

## Upstreams

| Service  | Image             | Port | Purpose |
|----------|-------------------|------|---------|
| `echo`   | `dwara-demo/echo` | 8080 | Reflects the incoming request as JSON (method, path, query, headers, body) so test scripts can verify what the gateway forwarded. |
| `static` | `dwara-demo/static` | 80 | nginx serving `index.html` and `api/users.json` / `api/products.json` for compression and caching demos. |
| `ws-echo`| `dwara-demo/ws-echo` | 8080 | WebSocket echo server; echoes back any message received. |

## Routes

| Route | Prefix | Upstream | Feature |
|-------|--------|----------|---------|
| `transforms-route` | `/v1/transforms/` | echo | Header set/add/remove + query add on request; header set on response |
| `security-headers-route` | `/v1/secure/` | echo | HSTS, nosniff, CSP, X-Frame-Options injection |
| `cors-route` | `/v1/cors/` | echo | CORS preflight + actual-response headers |
| `compression-route` | `/v1/compress/` | static | gzip/brotli response compression |
| `cache-route` | `/v1/cache/` | static | TTL + stale-while-revalidate + vary + coalescing |
| `masking-route` | `/v1/mask/` | echo | Response field masking (`/password`, `/secret`) |
| `limits-route` | `/v1/limits/` | echo | Request limits (body/header caps) + JSON Schema body validation |
| `ws-route` | `/ws` | ws-echo | WebSocket proxying with origin check + frame-rate limit |

No authentication is required on any route, so the test scripts can exercise
them with a plain `curl`.

## Running

```sh
# Build the upstream images once (if not already built):
docker compose -f ../_shared/docker-compose.yml build

# Start the demo:
docker compose up -d

# Wait for the gateway to come up, then run the tests:
./test-01-header-transforms.sh
./test-02-query-transforms.sh
./test-04-security-headers.sh
./test-05-cors.sh
./test-06-compression.sh
./test-07-response-caching.sh
./test-08-field-masking.sh
./test-09-websocket.sh
./test-10-request-limits.sh

# Tear down:
docker compose down
```

The gateway listens on `http://localhost:8080`. All test scripts source
`../_shared/helpers.sh` for assertion helpers and print a pass/fail summary.

## Tests

### test-01-header-transforms.sh
Sends `X-Internal-Token: secret` to `/v1/transforms/test`. Asserts the
response carries `X-Served-By: dwara-demo`, the echo body shows the upstream
received `X-Forwarded-By: dwara` and `X-Request-Source: demo`, and that
`X-Internal-Token` was removed before forwarding.

### test-02-query-transforms.sh
Requests `/v1/transforms/test` with no query string. Asserts the echo body
shows the upstream received the added `source=gateway` query param.

### test-04-security-headers.sh
`curl -I /v1/secure/test`. Asserts the response contains
`Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: deny`, and `Content-Security-Policy`.

> NOTE: HSTS is an HTTPS-only directive (RFC 6797). This demo runs a plaintext
> HTTP listener; if the gateway suppresses HSTS on HTTP, the HSTS assertion
> may fail while the other security headers pass.

### test-05-cors.sh
Sends an OPTIONS preflight with `Origin: https://app.example.com` and
`Access-Control-Request-Method: POST`. Asserts `Access-Control-Allow-Origin`
(and related CORS headers) are present.

### test-06-compression.sh
`curl -H 'Accept-Encoding: gzip' -I /v1/compress/api/users.json`. Asserts
`Content-Encoding: gzip` (the JSON file is above the 100-byte min size and
matches the `application/json` content type).

### test-07-response-caching.sh
Requests `/v1/cache/api/users.json` twice. Asserts the second response has an
`Age` header (cache hit) or is served faster than the first.

### test-08-field-masking.sh
Field masking redacts sensitive JSON fields in upstream *responses*. The echo
upstream reflects the request (it does not return `password`/`secret` fields
in its response body), so masking cannot be fully verified against echo. This
test only verifies the masking route responds 200. Full verification requires
a JSON API upstream that returns sensitive fields.

### test-09-websocket.sh
Full WebSocket testing requires `websocat`:

```sh
websocat ws://localhost:8080/ws
# type a message -> ws-echo replies "echo: <message>"
```

This test only verifies the `/ws` route is reachable (a plain GET returns a
non-404 status such as 400/426 upgrade-required).

### test-10-request-limits.sh
Exercises the `limits` and `request_validation` blocks on `/v1/limits/`
(`max_body_bytes: 1024`, `max_header_count: 10`, plus a JSON Schema
requiring `name`, bounding `age` to 0-150, and rejecting unknown
properties). Asserts:

- a conforming body returns 200 and reaches the echo upstream;
- a schema-violating JSON body (missing `name`, out-of-range `age`, or an
  unknown property) returns `400 validation_failed` before the action runs;
- a body declaring more than 1024 bytes returns `413 request_body_too_large`;
- a flood of 15 extra header fields returns `431 request_headers_too_large`.

## Layout

```
05-request-response/
  docker-compose.yml   # gateway + echo + static + ws-echo on one network
  dwara.yaml           # listener, 8 routes, 3 services, 3 upstreams
  test-01-header-transforms.sh
  test-02-query-transforms.sh
  test-04-security-headers.sh
  test-05-cors.sh
  test-06-compression.sh
  test-07-response-caching.sh
  test-08-field-masking.sh
  test-09-websocket.sh
  test-10-request-limits.sh
  README.md
```
