# Analytics stream

The [embedded analytics store](./analytics) keeps traffic history on
the gateway itself. The analytics stream is the opt-in way OUT: every
completed request's record — one per request, not rollups — is
streamed to an external HTTP collector in your own infrastructure,
for warehouses and SIEMs that want the raw firehose. The two are
independent: run either, both, or neither.

The stream is fire-and-forget end to end. A slow or dead collector
can never slow the gateway: records queue in a bounded buffer, and a
full buffer drops and counts rather than blocking a request.

## Enabling

Add an `analytics_stream` block to the gateway config:

```yaml
analytics_stream:
  buffer: 8192            # queue capacity, 64..=65536, default 8192
  flush_ms: 1000          # max batch latency (ms), 100..=60000
  batch_max: 512          # records per batch, 1..=4096
  sink:
    type: webhook
    url: https://collector.example.com/ingest
    headers:              # values may be ${...} secret references
      X-Token: ${file:/etc/dwara/collector-token}
    timeout_ms: 5000      # one budget per batch, all attempts share it
    max_attempts: 3
    backoff_base_ms: 250
    backoff_cap_ms: 4000
```

`type: webhook` is the one sink today. The sink set is closed so a
future sink (a Kafka producer is the planned second slot) is an
additive config change, never a silent behavior change.

Reloads are live: changing the sink URL, the cadence, or removing the
block applies to the next batch without a restart. Only the queue
capacity is fixed at startup (it is allocated once when the gateway
boots). A block ADDED by reload arms the stream immediately.

## What the collector receives

One `POST` per flushed batch, body one JSON object per line
(newline-delimited JSON, `content-type: application/x-ndjson`), one
line per completed request — including unrouted 404s (every completed
request means exactly that):

```json
{"id":"rec-18f3c2a1b9d0-00000a","gateway":"dwara-8213-18f3c2910b07",
 "timestamp":"2026-08-30T09:00:00.123Z","request_id":"req-...",
 "listener":"edge","route":"billing","consumer":"acme",
 "upstream":"billing-v1","endpoint":"10.0.0.4:8443","method":"GET",
 "path":"/v1/invoices","status":200,"duration_ms":4.2,"attempts":1,
 "rate_limited":false,"broken":false,"shed":false,
 "dimensions":{"plan":"gold"}}
```

Fields are the access record's redacted set: the path never includes
a query string, and there are no headers or credentials. `gateway`
identifies the emitting process and `id` is per-process monotonic, so
a collector can order each gateway's stream. Batches are delivered
strictly in order and never exceed 4096 records or 2 MiB, whichever
comes first, then the flusher moves to the next batch.

Answer `2xx` to accept a batch. Transient failures (transport
errors, 429, 502, 503, 504) are retried inside the batch's total
`timeout_ms` budget with exponential backoff (a seconds-form
`Retry-After` is honored); anything else fails the batch without
retry. A failed batch is counted and the stream moves on — the
gateway is not a durable queue, and delivery never blocks traffic.

## Metrics

Three families in [`/metrics`](./observability):

| Metric | Meaning |
| --- | --- |
| `dwara_access_records_streamed_total{outcome}` | records per batch outcome: `delivered`, `failed` (tried, not taken), or `dropped` (over the per-record size cap, or a queued tail when the stream was disabled) |
| `dwara_access_records_offered_total` | records offered at request completion |
| `dwara_access_records_dropped_total` | records dropped because the queue was full — the honest loss counter for an overloaded collector; raise `buffer` or fix the collector when it grows |
