# Category 02: Load Balancing & Upstream Management

This demo exercises dwara's upstream load-balancing strategies,
traffic-splitting, and dynamic-discovery capabilities. A single gateway
fronts three echo upstreams (`echo-a`, `echo-b`, `echo-c`), one slow
upstream, and one DNS-discovered echo, wired into five load-balancer
pools, one weighted traffic-split service, and one discovery pool,
each exposed on its own `/lb/<strategy>/` prefix.

## What it covers

| Strategy | Route | Pool | Upstreams |
|---|---|---|---|
| Round-robin | `/lb/rr/` | `rr-pool` | echo-a, echo-b, echo-c (weight 1 each) |
| Least-requests | `/lb/lr/` | `lr-pool` | echo-a, echo-b, echo-c (weight 1 each) |
| IP-hash | `/lb/hash/` | `ip-hash-pool` | echo-a, echo-b, echo-c (weight 1 each) |
| Peak-EWMA | `/lb/ewma/` | `ewma-pool` | echo-a (fast), slow (~200ms delay) |
| Sticky sessions | `/lb/sticky/` | `sticky-pool` | echo-a, echo-b (cookie affinity) |
| Traffic split | `/lb/split/` | `split-service` | 90% rr-pool, 10% lr-pool |
| Dynamic discovery | `/lb/dns/` | `dns-pool` | none static — resolved from DNS (`echo-dns`) |

The echo upstream returns JSON with an `instance` field naming the
backend that handled the request (`echo-a`, `echo-b`, `echo-c`,
`slow`, or `echo-dns`), so test scripts can verify which endpoint was
selected.

## Prerequisites

- Docker and Docker Compose.
- The shared upstream images must be built first:
  ```sh
  docker compose -f demos/_shared/docker-compose.yml build
  ```
  This builds `dwara-demo/echo`, `dwara-demo/slow`, `dwara-demo/flaky`,
  and `dwara-demo/static`.
- The gateway image `dwara:demo` is built from the repo-root
  `Dockerfile.scratch` (the compose file builds it automatically on
  first `up`).
- Shared certs are at `demos/_shared/certs/` (bind-mounted into the
  gateway, though this demo uses plaintext HTTP on port 8080).

## How to run

From the repo root:

```sh
# 1. Build the shared upstream images (one-time).
docker compose -f demos/_shared/docker-compose.yml build

# 2. Start the gateway + upstreams.
docker compose -f demos/02-load-balancing/docker-compose.yml up -d

# 3. Wait for the gateway to be ready, then run the tests.
cd demos/02-load-balancing
./test-01-round-robin.sh
./test-02-least-requests.sh
./test-03-ip-hash.sh
./test-04-peak-ewma.sh
./test-05-sticky-sessions.sh
./test-06-traffic-split.sh
./test-07-dynamic-discovery.sh

# 4. Tear down.
docker compose -f ../02-load-balancing/docker-compose.yml down
```

## Expected results

### test-01-round-robin.sh
10 requests to `/lb/rr/test` are distributed across `echo-a`,
`echo-b`, and `echo-c`. The test asserts at least 2 distinct instances
are observed (with equal weights and 10 requests, all three are
expected).

### test-02-least-requests.sh
5 requests to `/lb/lr/test` all return HTTP 200. The least-requests
balancer picks the endpoint with the fewest in-flight requests.

### test-03-ip-hash.sh
5 requests to `/lb/hash/test` from the same client IP all land on the
same echo instance. IP-hash deterministically maps a client IP to one
endpoint.

### test-04-peak-ewma.sh
5 requests to `/lb/ewma/test` all return HTTP 200. The peak-EWMA
balancer tracks round-trip time and skews traffic toward `echo-a`
(the fast endpoint) over `slow` (which adds ~200ms of delay).

### test-05-sticky-sessions.sh
The first request to `/lb/sticky/test` sets a `dwara-affinity` cookie.
The second request, sent with that cookie, lands on the same instance.
The test asserts both responses name the same `instance`.

### test-06-traffic-split.sh
20 requests to `/lb/split/test` are split 90/10 between `rr-pool` and
`lr-pool`. Both pools draw from the same three echo instances, so the
test asserts at least 2 distinct instances are observed (proving the
split is distributing traffic rather than pinning to one backend).

### test-07-dynamic-discovery.sh
The `dns-pool` upstream has NO static endpoints: a background
discovery task resolves the `echo-dns` compose service name via
docker's embedded DNS (A record) and hot-swaps the resolved addresses
into the balancer's endpoint set, re-resolving every
`refresh_interval_s` (5 s in the demo config; the cadence is
`min(refresh_interval_s, record_ttl)`). A request to `/lb/dns/test`
that returns `200` naming `echo-dns` proves the whole chain — resolve,
endpoint-set swap, route. The test also scrapes the reserved
`/metrics` path and asserts:

- `dwara_dns_discovery_endpoints{upstream="dns-pool"} >= 1` (resolved
  endpoint count),
- `dwara_dns_discovery_refresh_total{upstream="dns-pool"}` advanced
  across one refresh interval (the TTL/refresh cadence is live),
- `dwara_dns_discovery_refresh_failures_total` stayed `0`,
- the `dns_discovery_refreshed` log line fired.

Docker DNS answers a single A record per service here, so the demo
asserts resolve-and-route rather than fan-out; scale `echo-dns`
replicas up to watch the gauge and the balancer update live. On DNS
failure the pool keeps the last resolved set (`fail_open: true`) and
the `min_endpoints: 1` floor prevents shrinking below one endpoint.

## Files

```
02-load-balancing/
  docker-compose.yml      gateway + 3x echo + slow + echo-dns on one network
  dwara.yaml              listeners, routes, services, upstreams
  test-01-round-robin.sh
  test-02-least-requests.sh
  test-03-ip-hash.sh
  test-04-peak-ewma.sh
  test-05-sticky-sessions.sh
  test-06-traffic-split.sh
  test-07-dynamic-discovery.sh
  README.md               this file
```
