# Category 06: Observability & Analytics

A self-contained demo of the dwara gateway's full observability and
analytics stack: the Prometheus `/metrics` endpoint, `X-Request-Id`
propagation, structured access logs, the embedded analytics store
(SQLite with 1m/5m/1h/1d rollups), custom request-header dimensions,
live in-process sketches, ML traffic insights, scheduled exports, the
real-time analytics NDJSON stream, and alert/event webhooks.

## Services

| Service            | Image                       | Host port | Purpose                                   |
|--------------------|-----------------------------|-----------|-------------------------------------------|
| dwara              | dwara:demo                  | 8080      | HTTP gateway (data plane)                 |
| dwara (admin API)  | dwara:demo                  | 2019      | mTLS-only admin API (analytics queries)   |
| echo               | dwara-demo/echo             | -         | Upstream that reflects the request as JSON |
| webhook-receiver   | dwara-demo/webhook-receiver | 8081      | Collects event webhooks + analytics stream |

All four containers share the `obs-net` bridge network so the gateway
can reach `echo:8080` and `webhook-receiver:8080` by service name. The
webhook-receiver is also exposed on host port `8081` so the test
scripts can query its event ledger (`GET /events`).

## Layout

```
06-observability/
  docker-compose.yml      service definitions (dwara, echo, webhook-receiver)
  dwara.yaml              gateway config (listeners, routes, analytics, webhooks)
  data/                   mounted volume for state.db + analytics.db + exports
  test-01-metrics.sh      /metrics endpoint contains the request counter
  test-02-request-id.sh   X-Request-Id is echoed on every response
  test-03-access-logs.sh  generates traffic; access logs go to docker logs
  test-04-analytics-query.sh   mTLS admin /analytics/dashboard returns 200
  test-05-analytics-dimensions.sh  custom dimension (X-API-Version) rollup
  test-09-analytics-stream.sh  analytics NDJSON stream reaches the receiver
  test-10-webhooks.sh     webhook-receiver reachable; events fire on transitions
  test-11-slo.sh          /metrics contains dwara_slo_* gauges
  README.md               this file
```

## Prerequisites

The shared infrastructure must already be built:

- Docker images: `dwara:demo`, `dwara-demo/echo`, `dwara-demo/webhook-receiver`
- Certs at `../_shared/certs/` (`server.crt`, `server.key`, `client-ca.crt`,
  `client.crt`, `client.key`)
- Helper script at `../_shared/helpers.sh`

## Run

```sh
docker compose up -d

# Wait for the gateway to bind, then run the test scripts:
./test-01-metrics.sh
./test-02-request-id.sh
./test-03-access-logs.sh
./test-04-analytics-query.sh
./test-05-analytics-dimensions.sh
./test-09-analytics-stream.sh
./test-10-webhooks.sh
./test-11-slo.sh
```

Stop with `docker compose down` (add `-v` to also remove the data
volume).

## Configuration highlights

- **Listener:** one plaintext HTTP listener on `0.0.0.0:8080`.
- **Routes:**
  - `echo-route` (`/v1/echo/`) proxies to the echo upstream with
    `strip_prefix`.
  - `slo-route` (`/v1/slo/`) proxies to the same upstream but carries
    an SLO (`availability: 99.9`, `latency_ms: 500`, `latency_target: 95`),
    which exports `dwara_slo_burn_rate` / `dwara_slo_target` gauges.
- **Admin API:** mTLS-only on `0.0.0.0:2019` (server cert + client CA).
- **Analytics:** SQLite store at `/var/lib/dwara/analytics.db` with a
  fast `flush_ms: 100` (for quick test turnaround), custom dimensions
  (`X-API-Version` -> `api_version`, `X-Client-Type` -> `client_type`),
  per-granularity retention, live sketches, ML insights, and daily
  csv/json exports.
- **Analytics stream:** NDJSON firehose to
  `http://webhook-receiver:8080/analytics` (`flush_ms: 1000`).
- **Webhooks:** breaker/ejection/recovery + config publish/reject
  events delivered to `http://webhook-receiver:8080/events`.

## Querying the admin API (mTLS)

All admin API requests require a client certificate chained to the
client CA. From the demo directory:

```sh
now_ms=$(($(date +%s) * 1000))
from_ms=$((now_ms - 300000))

# Per-window dashboard series.
curl --cert ../_shared/certs/client.crt \
     --key  ../_shared/certs/client.key \
     --cacert ../_shared/certs/server.crt \
     "https://localhost:2019/analytics/dashboard?from_ms=${from_ms}&to_ms=${now_ms}&gran=0"

# Custom-dimension rollup (POST body).
curl --cert ../_shared/certs/client.crt \
     --key  ../_shared/certs/client.key \
     --cacert ../_shared/certs/server.crt \
     -X POST -H 'Content-Type: application/json' \
     -d "{\"from_ms\":${from_ms},\"to_ms\":${now_ms},\"gran\":0,\"dim\":\"api_version\",\"value\":\"2\"}" \
     https://localhost:2019/analytics/dimensions

# Live in-process sketch snapshot.
curl --cert ../_shared/certs/client.crt \
     --key  ../_shared/certs/client.key \
     --cacert ../_shared/certs/server.crt \
     https://localhost:2019/analytics/live
```

## Notes

- The `/metrics` endpoint emits the request counter as `requests_total`
  (no `dwara_` prefix) in Prometheus text format; the `dwara_` prefix is
  applied only to OTLP-exported metric names. SLO gauges are emitted as
  `dwara_slo_burn_rate` and `dwara_slo_target`.
- The admin analytics series endpoint is `GET /analytics/dashboard`
  (requires `from_ms`/`to_ms` epoch-millisecond bounds).
- Access logs are emitted to the gateway's stdout; inspect with
  `docker compose logs dwara`.
- The webhook-receiver ledger (`GET /events` on port 8081) contains the
  union of event webhooks (POST `/events`) and analytics-stream batches
  (POST `/analytics`).
