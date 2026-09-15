# Observability and analytics

## Environment variables that matter to operators

| Variable | Purpose |
| --- | --- |
| `DWARA_CONFIG` | Config path (default `./dwara.yaml`); the file is watched |
| `DWARA_STATE_DB` | SQLite state store (quotas, MCP sessions) - **required for quota enforcement** |
| `DWARA_LOG` | Log filter (e.g. `dwara=info`, `dwara=debug`) |
| `DWARA_ACCESS_LOG_SAMPLE` | Access-log sampling |
| `DWARA_OTLP_ENDPOINT` | OTLP collector base URL (`/v1/traces`, `/v1/metrics` appended) |
| `DWARA_OTLP_METRICS_INTERVAL_SECS` | OTLP metrics interval (default 15) |
| `DWARA_SHUTDOWN_TIMEOUT_SECS` | Drain bound on SIGTERM (default 10) |
| `DWARA_PID_FILE` | Pidfile for `dwara-cli upgrade` |
| `DWARA_UPGRADE_BINARY` | New binary path for upgrades (default: same path) |
| `DWARA_UPGRADE_READY_TIMEOUT_SECS` | Upgrade readiness wait (default 30) |
| `DWARA_WORKER_THREADS` / `DWARA_MAX_BLOCKING_THREADS` | Runtime sizing |
| `DWARA_ACCEPTORS_PER_LISTENER` / `DWARA_POOL_SHARDS` | Concurrency layout |
| `DWARA_REQUEST_BODY_TIMEOUT_MS` | Body-read timeout |
| `DWARA_HTTP1_MAX_HEADERS`, `DWARA_H2_MAX_CONCURRENT_STREAMS`, ... | Protocol knobs |
| `DWARA_CREDENTIAL_PEPPER` / `_PREVIOUS` | API-key hash pepper (+rotation) |
| `DWARA_ADMIN` | CLI default admin URL |
| `DWARA_ADMIN_DEV` | Plaintext loopback admin (dev only) |

## Metrics that answer real questions

| Question | Metric |
| --- | --- |
| Is config live? did it change? | `config_generation` (jumps on publish) |
| Is anything tripping? | `breaker_state` (0 closed/1 open/2 half-open), `endpoint_health` |
| Are we saturating? | `active_requests`, `dwara_admission_queue_depth`, shed totals |
| Who is being limited? | `rate_limited_total`, `X-RateLimit-*` headers on responses |
| Is a dry-run policy firing? | `dwara_policy_dry_run_total{phase,route}` |
| WAF activity? | `dwara_waf_total{route,filter,outcome}` |
| SLO health? | `dwara_slo_burn_rate`, `dwara_slo_target` |
| Webhook delivery? | `dwara_webhook_events_total` |
| AI specifics | `dwara_ai_*` families; spend via `POST /analytics/spend` |

`/metrics` is Prometheus text on every listener (reserved path, exempt from
policies). A starter Grafana dashboard ships in the repo's `grafana/`
directory.

## Access logs

One structured line per request: `request_id`, outcome flags
(`rate_limited`, `broken`, `shed`), duration. The gateway echoes
`X-Request-Id` to clients - take it from the complaint, grep the log.
Sampled via `DWARA_ACCESS_LOG_SAMPLE`.

## Embedded analytics

```yaml
analytics:
  path: /var/lib/dwara/analytics.db    # separate SQLite from the state store
  flush_ms: 1000
  dimensions:                          # custom analytics dimensions
    - name: api_version
      header: X-API-Version            # sourced from a request header
    - name: team
      claim: team                      # ...or an auth claim
  retention:                           # per-granularity retention (defaults)
    raw_ms: 86400000                   # 24h raw
    m1_ms: 172800000                   # 48h 1-minute rollups
    m5_ms: 604800000                   # 7d  5-minute
    h1_ms: 2592000000                  # 30d 1-hour
    d1_ms: 7776000000                  # 90d 1-day
  live_sketches:
    enabled: true
    freshness_target_ms: 500           # -> GET /analytics/live
  insights:
    forecast: true                     # -> GET /analytics/forecast
    anomaly_baseline: true             # -> GET /analytics/anomalies
    baseline_windows: 1440
  exports:
    directory: /var/lib/dwara/exports
    formats: [csv, json]
    window: daily                      # hourly | daily | monthly
    # files: dwara-usage-{window}-{utc-stamp}.{ext}; idempotent; partial flag
```

Query surface: `/analytics/dashboard`, `/analytics/top`, `POST
/analytics/query` (closed JSON grammar), plus the export endpoints. Crash-
idempotent: the rollup cascade resumes where it left off.

## Analytics stream (firehose)

```yaml
analytics_stream:
  sink:
    type: webhook            # NDJSON application/x-ndjson;
    url: http://receiver:9090/analytics   # <=4096 records / 2 MiB per batch
    timeout_ms: 5000
    max_attempts: 3
    backoff_base_ms: 100
    backoff_cap_ms: 1000
  flush_ms: 1000
  batch_max: 512
  buffer: 8192
```

Fire-and-forget: delivery problems never block the dataplane. Kafka is a
documented planned sink, not shipped - don't configure it.

## Event webhooks

```yaml
webhooks:
  - url: http://receiver:9090/events
    events: [breaker_opened, breaker_half_open, breaker_closed,
             endpoint_ejected, endpoint_recovered,
             config_published, config_rejected]
    headers: { Authorization: Bearer ${WEBHOOK_TOKEN} }
    timeout_ms: 5000
    max_attempts: 3
```

At-least-once delivery backed by an event WAL in the state store.

## Synthetic monitoring

`synthetic.probes[]`: `route_name` (required), `interval_ms` (5000),
`timeout_ms` (2000), `failure_threshold` (1). Probes exercise **routes**
end-to-end (unlike `active_health`, which feeds load balancing) and write
results into analytics with a `synthetic` flag; edge-triggered
`probe_alert`/`probe_recovered` webhooks fire on state change.

## Replay debugging (time travel)

```sh
dwara replay capture --duration 60s --output trace.dwara   # <=10 min ring
                                                            # buffer; secrets
                                                            # redacted unless
                                                            # --include-secrets
dwara replay run --trace trace.dwara [--config candidate.yaml] [--diff]
```

Offline, read-only: replays captured traffic against a config and reports
MATCH/DIVERGENCE per request - the tool for proving a risky change is
behavior-neutral before it ships.
