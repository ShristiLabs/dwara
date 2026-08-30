# Real-time analytics stream (DW-121)

> Implements issue DW-121 (M2, `edition/oss`, effort M). Sources:
> `crates/dwara-core/src/events/stream.rs` (the pipeline — its module
> docs carry the full contract), the shared delivery engine extracted
> in `events/webhook.rs` (`compile_endpoint`, `deliver_with_retry`),
> config types in `config/mod.rs` and bounds in `config/limits.rs`,
> validation in `snapshot/mod.rs`, the wiring in
> `dataplane/proxy.rs` and `dwara-bin/src/main.rs`, the metric families
> in `observability.rs`. Tests: `crates/dwara-core/tests/stream.rs`
> (end to end: one line per request in one delivery per batch,
> dead-sink isolation, live retarget, arm-by-republish, the unrouted
> 404 record, coexistence with the embedded store) and
> `crates/dwara-core/tests/unit/stream.rs` (line shape and redaction,
> offer gating and drop accounting, sink compilation, batching
> semantics, the sink on the wire against scripted receivers, the
> validation matrix). Operator docs:
> [docs-site analytics-stream guide](../../docs-site/guide/analytics-stream.md).

DW-043 answers "what happened" locally; DW-121 is the opt-in firehose
out. Every completed request's access record — not rollups, not the
discrete DW-044 ops events — is streamed to an external sink for
operators who want raw traffic in their own warehouse or SIEM. The
issue's two hard requirements shape everything: exactly one delivered
record per completed request, and a pipeline failure that can never
block or slow the dataplane.

## Placement: the events domain, not analytics

The stream lives in `events/stream.rs` beside the webhook deliverer
because it IS an outbound delivery pipeline: it reuses the DW-044
delivery engine and consumes the access record type from
`observability`, both of which `events` may import. The analytics
domain may not import `events` (`scripts/check_deps.py`), and the
firehose needs nothing from the SQLite store — it taps the record at
request completion, upstream of any persistence. The two DW-121-adjacent
doc claims that predated this design (that the firehose would be "a
sibling implementation of the `AnalyticsSink` contract") were corrected
in this change: the stream ships the access record itself — with
`request_id` and the redacted path the extension event omits — through
its own `RecordSink` seam.

## The pipeline

```
request completes
  └─ offer: enabled-flag check -> try_send on a bounded channel
       (full => drop and count; disabled => return before allocating)
            └─ flusher task: drain -> ordered batch
                 (batch_max records | 2 MiB bytes | flush_ms tick)
                     └─ ONE delivery per batch, inline, strictly in order
                          (shared DW-044 engine: one total timeout,
                           exponential backoff, 429/502/503/504 retry set)
```

`AccessRecordStream::offer` is the hot path: one relaxed atomic load,
and for an armed stream one bounded `try_send`. There is no blocking
wait anywhere — a full channel drops and counts (throttled
`record_stream_channel_full` log, the analytics writer's cadence), the
same fire-and-forget posture as the embedded store's write path. A
disabled stream (no `analytics_stream` block, or a sink that failed to
compile) returns before allocating anything.

Batches flush on the first of three triggers — `batch_max` records,
the 2 MiB byte cap, or `flush_ms` since the batch's first record —
all read live from the current generation. Deliveries are made
strictly in order, inline in the flusher task: a record firehose's
arrival order is a receiver expectation, unlike alert events (which
the DW-044 deliverer dispatches as independent tasks). The cost of
ordering is bounded and deliberate: one slow batch holds the queue
back by at most its `timeout_ms`, then fails and the queue moves on;
a queue that outgrows `buffer` drops at OFFER time, counted.

## The wire format

One NDJSON body per batch (`application/x-ndjson`,
`user-agent: dwara-record-stream`): one JSON object per line, one line
per record:

```json
{"id":"rec-18f3c2a1b9d0-00000a","gateway":"dwara-8213-18f3c2910b07",
 "timestamp":"2026-08-30T09:00:00.123Z","request_id":"req-...",
 "listener":"edge","route":"billing","consumer":"acme",
 "upstream":"billing-v1","endpoint":"10.0.0.4:8443","method":"GET",
 "path":"/v1/invoices","status":200,"duration_ms":4.2,"attempts":1,
 "rate_limited":false,"broken":false,"shed":false,
 "dimensions":{"plan":"gold"}}
```

The field list is the access record's redacted-by-construction set:
`path` never carries a query string, no headers, no credentials;
`dimensions` carries only DW-043's config-declared header-sourced tags
(16 x 128 bytes). `id` (`rec-<hex unix ms>-<hex seq>`) plus `gateway`
give a receiver per-instance ordering across restarts. A line over the
16 KiB record cap (absurd path/dimension lengths only) is dropped and
counted, never truncated — a receiver never sees a malformed line.

## The sink seam

`RecordSink` is deliberately one method — deliver a batch, answer
whether the receiver took it — because the pipeline's guarantees
(ordering, bounded memory, drop-and-count) live in the flusher. The
`webhook` batch sink is the one shipped implementation; a Kafka
producer is the documented second slot, deferred by the lean-deps
rule (the same decision that keeps Parquet out of the DW-156 backlog):
a sink slot that drags a client library must earn its dependency
weight. The webhook sink compiles through `WebhookTarget::
compile_endpoint` — the same URL decomposition, `${...}` header-secret
resolution, and retry-knob handling the alert deliverer uses — so the
two pipelines cannot drift on delivery semantics.

## Configuration, validation, reload

```yaml
analytics_stream:
  buffer: 8192              # channel capacity, 64..=65536, default 8192
  flush_ms: 1000            # max batch latency, 100..=60000, default 1000
  batch_max: 512            # records per batch, 1..=4096, default 512
  sink:
    type: webhook
    url: https://collector.example.com/ingest
    headers:                # values may be ${...} references (DW-045)
      X-Token: ${file:/etc/dwara/collector-token}
    timeout_ms: 5000        # one budget per batch, all attempts share it
    max_attempts: 3
    backoff_base_ms: 250
    backoff_cap_ms: 4000
```

The sink set is a closed, internally-tagged enum; the variant payloads
carry `deny_unknown_fields`, so a misspelled knob is still a rejected
config. Validation runs the URL/header grammar through the same
extracted validators as alert webhooks (`validate_delivery_url`,
`validate_delivery_headers`), plus the shared retry-knob bounds and
the pipeline-knob bounds in `config::limits`.

Lifecycle: the channel and its capacity are boot-time (the binary
constructs the stream ALWAYS — an unconfigured stream is disabled by
its enabled flag, so a live reload can arm the pipeline without a
restart); the sink set, cadence, batch bound, and enabled state are
generation state, compiled in `DataPlane::refresh`. The refresh pushes
the compiled sink set to the flusher BEFORE flipping the offer path's
enabled flag — a reload arming the stream never queues a record the
flusher has no sink for yet — and a disable with a queued tail counts
the tail as `outcome="dropped"` so the accounting identity `offered ==
delivered + failed + dropped` holds. A sink whose compilation fails is
skipped LOUD and leaves the stream disabled (fail closed — never
delivered with placeholder bytes).

On shutdown the flusher drains what is already queued into one final
flush attempt, bounded by the binary's 5 s window; the gateway is not
a durable queue.

## Metrics

| Family | Kind | Meaning |
| --- | --- | --- |
| `dwara_access_records_streamed_total{outcome}` | counter | records per batch outcome; `outcome` is the closed set `delivered` / `failed` (tried and not taken) / `dropped` (never delivered: over the record byte cap, or a disabled stream's queued tail) |
| `dwara_access_records_offered_total` | gauge | records offered at request completion (scrape-time snapshot; the offer path bumps a plain atomic) |
| `dwara_access_records_dropped_total` | gauge | records dropped at OFFER time (channel full or stream disabled) |

Cardinality is bounded by construction (three outcome series; the
gauges are aggregate). The [alert webhooks](./alerting.md) page covers
the shared delivery engine; [embedded analytics](./analytics.md)
covers the local store this stream complements.
