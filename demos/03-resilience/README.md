# Category 03: Traffic Policy & Resilience

Demonstrates dwara's resilience mechanisms against deliberately
unreliable upstreams: a **flaky** server (configurable error rate), a
**slow** server (configurable latency), and two healthy **echo**
endpoints. Each mechanism is exercised by a focused `test-*.sh` script.

## Shared infrastructure

This demo reuses the pre-built images from `demos/_shared/`:

- `dwara:demo` - the gateway image
- `dwara-demo/echo` - reflects the request as JSON (`INSTANCE_NAME`
  identifies the instance via the `X-Echo-Instance` header)
- `dwara-demo/flaky` - `/flaky/<pct>` returns 500 on `<pct>`% of requests
- `dwara-demo/slow` - `/slow/<ms>` delays `<ms>` before responding

Build them first if they are missing:

```sh
docker compose -f ../_shared/docker-compose.yml build
```

## Layout

```
03-resilience/
  docker-compose.yml   gateway + echo, echo2, flaky, slow, mirror
  dwara.yaml           one HTTP listener, seven upstream pools, ten routes
  test-01-passive-health.sh
  test-02-active-health.sh
  test-03-circuit-breaker.sh
  test-04-retries.sh
  test-05-hedging.sh
  test-06-timeouts.sh
  test-07-load-shedding.sh
  test-10-fault-injection.sh
  test-11-mirroring.sh
  test-12-maintenance-mode.sh
```

## Running

```sh
docker compose up -d
./test-01-passive-health.sh
./test-02-active-health.sh
# ...or run them all:
for t in test-*.sh; do ./"$t"; done
```

The gateway listens on `http://localhost:8080` (plaintext HTTP). No auth
is required on any route, so every test is a plain `curl`.

## Upstream pools and what they demonstrate

| Pool | Endpoints | Mechanism |
|---|---|---|
| `healthy-pool` | echo, echo2 | round-robin baseline (always 200) |
| `flaky-pool` | flaky, echo | passive health / outlier detection |
| `retry-pool` | flaky, echo | retries on 500/502/503 + transport errors |
| `hedge-pool` | slow, echo | request hedging (speculative copy) |
| `timeout-pool` | slow | read timeout (`read_ms: 500`) |
| `breaker-pool` | flaky | circuit breaker |
| `mirror-pool` | mirror | shadow traffic target |

## Routes

Routes strip their prefix so the path-based control segments reach the
upstreams unchanged:

| Route | Service | Extra |
|---|---|---|
| `/healthy/` | healthy-service | - |
| `/flaky/` | flaky-service | - |
| `/retry/` | retry-service | - |
| `/hedge/` | hedge-service | - |
| `/timeout/` | timeout-service | - |
| `/breaker/` | breaker-service | - |
| `/mirror-test/` | main-service | `mirror: { upstream: mirror-pool, percentage: 100 }` |
| `/fault/` | main-service | `fault_injection: { delay: { percentage: 100, fixed_ms: 100 } }` |
| `/maint/` | main-service | `maintenance: { retry_after_secs: 60, message: "Under maintenance" }` |

For example, `GET /flaky/flaky/80` strips `/flaky/` and forwards
`/flaky/80` to the flaky-pool (80% error rate).

## Gateway-level settings

```yaml
max_concurrent_requests: 10000
admission_queue:
  enabled: true
  max_queue_size: 1000
  queue_timeout_ms: 5000
```

The high cap keeps the normal resilience demos from shedding. To
exercise shedding directly, lower `max_concurrent_requests` (e.g. to
10) and flood the gateway; over-cap requests are shed with 503 or
queued up to `queue_timeout_ms`.

## Test summary

| Test | Asserts |
|---|---|
| 01 passive health | after 5 failing requests the flaky endpoint is ejected; follow-up returns 200 from echo |
| 02 active health | healthy-pool endpoints respond 200 |
| 03 circuit breaker | flooding flaky eventually returns 502/503 (breaker opens) |
| 04 retries | request to 50%-flaky pool returns 200 (retry succeeds on echo) |
| 05 hedging | request to 300ms-slow pool returns 200 in < 300ms (echo hedge wins) |
| 06 timeouts | request to 2000ms-slow pool returns 504 (read_ms 500 exceeded) |
| 07 load shedding | basic requests survive a 50-request burst |
| 10 fault injection | `/fault/` returns 200 with latency >= 100ms (delay injected) |
| 11 mirroring | `/mirror-test/` returns 200 from main-service |
| 12 maintenance mode | `/maint/` returns 503 with `Retry-After: 60` |

## Notes

- The flaky upstream is probabilistic; tests that depend on it
  (`test-01`, `test-03`, `test-04`) issue multiple requests and accept
  the first success/failure that matches the expected behavior, so they
  are robust to random variation.
- State is persisted in the `./data` bind mount (SQLite). On Linux the
  directory must be writable by UID 65532:
  `sudo chown -R 65532:65532 data`.
