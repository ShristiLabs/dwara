# OpenTelemetry metrics export

Dwara can export metrics via the OpenTelemetry Protocol (OTLP) to a
collector or backend of your choice. This complements the built-in
Prometheus-style `/metrics` endpoint with a push-based export path
for environments where scraping is impractical.

## When to use this

Use OTLP export when:

- Your observability backend ingests OTLP natively (Honeycomb,
  Datadog, New Relic, Grafana Cloud, etc.).
- You are in an environment where a scrape endpoint is not reachable
  (e.g. a sidecar in a restricted network).
- You want traces and metrics in a single pipeline.

## Enabling

OTLP export is feature-gated. Build with the `otlp` feature:

```sh
cargo build --features otlp
```

Set the `DWARA_OTLP_ENDPOINT` environment variable to enable export.
Without it, the OTLP exporter is inert (the feature compiles but
does nothing).

```sh
export DWARA_OTLP_ENDPOINT=http://otel-collector:4318
```

The endpoint must be an HTTP URL. Both `/v1/metrics` and `/v1/traces`
paths are appended automatically.

## Exported metrics

The OTLP exporter sends the same metric families as the
`/metrics` endpoint:

| Metric | Type | Description |
|---|---|---|
| `dwara_requests_total` | counter | Total requests processed |
| `dwara_request_duration_seconds` | histogram | Request latency distribution |
| `dwara_upstream_errors_total` | counter | Upstream errors by service |
| `dwara_active_requests` | gauge | Currently in-flight requests |
| `dwara_cache_hits_total` | counter | Cache hits by route |
| `dwara_cache_misses_total` | counter | Cache misses by route |
| `dwara_circuit_breaker_state` | gauge | Circuit breaker state (0=closed, 1=open, 2=half-open) |

Labels are config-bounded (no consumer-name labels) to keep
cardinality predictable.

## Shutdown flush

On graceful shutdown (SIGTERM/SIGINT), the gateway flushes a final
metrics export before exiting. This ensures the last batch of
counters is delivered to the collector.

## Interaction with Prometheus

Both OTLP export and the Prometheus `/metrics` endpoint can run
simultaneously. Use whichever fits your environment; there is no
need to choose one.
