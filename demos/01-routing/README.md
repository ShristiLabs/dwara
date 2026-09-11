# Category 01: Core Gateway & Routing

This demo exercises every routing match type and action the dwara gateway
supports, plus path rewrites, method allowlists, and API deprecation headers.

## What the demo covers

### Match types

| Type | Route | Pattern | Example path |
|------|-------|---------|--------------|
| `exact` | ping | `/ping` | `/ping` |
| `exact` | mock-api | `/v1/mock` | `/v1/mock` |
| `exact` | static-demo | `/` | `/` |
| `prefix` | versioned-api | `/v1/` | `/v1/test` |
| `prefix` | api-v1 | `/v1/` | `/v1/test` (shadowed) |
| `prefix` | method-test | `/v1/methods` | `/v1/methods` |
| `prefix` | legacy-redirect | `/old` | `/old` |
| `regex` | users-by-id | `/v1/users/[^/]+` | `/v1/users/42` |

> **Reserved paths:** `/healthz`, `/readyz`, and `/metrics` are built-in
> gateway endpoints served *before* route resolution. A configured route
> matching any of them is permanently shadowed. The `ping` route uses
> `/ping` (not `/healthz`) so the `respond` action actually executes.

### Actions

| Action | Route | Behavior |
|--------|-------|----------|
| `respond` | ping | Returns 200 `ok` with `Content-Type: text/plain` |
| `proxy` | versioned-api, api-v1, users-by-id, static-demo, method-test | Forwards to an upstream |
| `redirect` | legacy-redirect | 301 redirect to `/v1/` |
| `mock` | mock-api | Returns 200 `{"mock": true}` with a 50ms delay |

### Other features

- **Path rewrite** (`strip_prefix`): `/v1/test` is rewritten to `/test`
  before proxying to the echo upstream.
- **Method allowlist**: `method-test` allows only GET and POST; other
  methods get 405 with an `Allow` header.
- **API deprecation**: `versioned-api` emits `Deprecation` and `Sunset`
  headers (RFC 9745) on every response.

### Route precedence

The gateway resolves a request path to at most one route using this
precedence: **exact** beats **regex** beats **longest prefix**. Equal-length
prefix ties go to the first-declared route.

- `/ping` -> `ping` (exact)
- `/v1/mock` -> `mock-api` (exact beats prefix)
- `/v1/users/42` -> `users-by-id` (regex beats prefix)
- `/v1/methods` -> `method-test` (longer prefix beats `/v1/`)
- `/v1/test` -> `versioned-api` (first-declared `/v1/` prefix wins the tie)
- `/old` -> `legacy-redirect` (prefix)
- `/` -> `static-demo` (exact)

## Prerequisites

1. **Shared images built.** The demo upstream images and the gateway image
   must already exist:
   ```
   docker images | grep -E 'dwara:demo|dwara-demo/(echo|static)'
   ```
   If missing, build them from the `demos/_shared/upstreams/` Dockerfiles
   and the repo-root `Dockerfile.scratch` (tagged `dwara:demo`).

2. **Certs generated.** The shared certs at `demos/_shared/certs/` must
   exist (used for the mount, even though this demo uses plaintext HTTP):
   ```
   ls demos/_shared/certs/server.crt demos/_shared/certs/server.key
   ```

3. **Docker Compose.** Docker and Docker Compose must be installed.

## How to run

### 1. Start the stack

```sh
cd demos/01-routing
docker compose up -d
```

This starts three containers on a shared bridge network:
- `dwara` — the gateway on port 8080 (HTTP)
- `echo` — the echo upstream (reflects requests as JSON)
- `static` — the static upstream (nginx serving demo files)

### 2. Wait for the gateway

```sh
curl -sf http://localhost:8080/healthz
# -> ok
```

This hits the built-in liveness probe (reserved path), not the `ping`
route — see the reserved-paths note above.

### 3. Run the test scripts

Each test script sources `../_shared/helpers.sh`, waits for the gateway,
runs its assertions, and prints a pass/fail summary.

```sh
./test-01-exact-match.sh
./test-02-prefix-match.sh
./test-03-regex-match.sh
./test-04-redirect.sh
./test-05-respond-direct.sh
./test-06-mock-response.sh
./test-07-path-rewrite.sh
./test-08-method-allowlist.sh
./test-09-api-versioning.sh
./test-10-host-header-match.sh
```

Or run them all at once:

```sh
for t in test-*.sh; do echo "--- $t ---"; ./"$t"; done
```

### 4. Tear down

```sh
docker compose down -v
```

## Expected results

| Test | Request | Expected |
|------|---------|----------|
| test-01-exact-match | `GET /ping` | 200, body `ok` |
| test-02-prefix-match | `GET /v1/test` | 200, body contains echo JSON |
| test-03-regex-match | `GET /v1/users/42` | 200, body contains echo JSON |
| test-04-redirect | `GET /old` | 301, `Location: /v1/` |
| test-05-respond-direct | `GET /ping` | 200, `Content-Type: text/plain` |
| test-06-mock-response | `GET /v1/mock` | 200, body contains `mock` |
| test-07-path-rewrite | `GET /v1/test` | echo `parsed_path` is `/test` |
| test-08-method-allowlist | `PATCH /v1/methods` | 405 |
| test-08-method-allowlist | `GET /v1/methods` | 200 |
| test-09-api-versioning | `HEAD /v1/test` | `Deprecation` + `Sunset` headers present |
| test-10-host-header-match | `GET /ping` with custom Host | 200, body `ok` |

All tests should pass with zero failures.

## Files

```
01-routing/
  docker-compose.yml      stack definition (gateway + echo + static)
  dwara.yaml              gateway config (listeners, routes, services, upstreams)
  test-01-exact-match.sh  exact match + respond action
  test-02-prefix-match.sh prefix match + proxy action
  test-03-regex-match.sh  regex match
  test-04-redirect.sh     redirect action (301)
  test-05-respond-direct.sh respond action with headers
  test-06-mock-response.sh mock action with delay
  test-07-path-rewrite.sh strip_prefix rewrite
  test-08-method-allowlist.sh route-level method allowlist (405)
  test-09-api-versioning.sh  deprecation headers
  test-10-host-header-match.sh host header responsiveness
  README.md              this file
```
