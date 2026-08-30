//! Schema-validation limits: numeric bounds the config compiler enforces
//! and runtime code must respect.
//!
//! These constants are part of the CONFIG CONTRACT (a value validation
//! rejects can never reach the runtime), so they live beside the schema
//! rather than in the modules that also use them at runtime: validation
//! (`snapshot::validate`) and the runtime consumers (the balancer's ring
//! construction, the slow-start clamp, the retry parameter resolution)
//! all read the same numbers from here.

/// Ketama vnode count per unit of endpoint weight (a weight-1 endpoint
/// gets 160 vnodes; a weight-w endpoint gets `160 * w` — footprint is
/// additive, so adding an endpoint never resizes existing segments).
pub const KETAMA_VNODES: u64 = 160;

/// Validation bound on total ip_hash ring size (`sum(weight) * 160`).
/// Keeps ring construction cheap and the BTreeMap small even for skewed
/// weight sets.
pub const MAX_RING_VNODES: u64 = 65_536;

/// Validation bound for `upstreams[].slow_start_ms` (10 minutes): the ramp
/// window is per-endpoint-entry, and unbounded windows would keep recycled
/// addresses permanently underweighted.
pub const MAX_SLOW_START_MS: u64 = 600_000;

/// Validation bound for `upstreams[].timeouts.happy_eyeballs_ms`
/// (DW-030, 10 minutes — the slow-start bound's twin rationale: a racing
/// delay past this no longer races anything, it serializes dials behind a
/// sleeper). `0` is legal and disables racing instead.
pub const MAX_HAPPY_EYEBALLS_MS: u64 = 600_000;

/// Validation bound on `retries.attempts` (mirrored in `snapshot::validate`).
pub const MAX_RETRY_ATTEMPTS: u32 = 10;

/// Runtime bound on the per-key GCRA state a rate-limiter window holds
/// PER SHARD of its keyed store (see `extensions::rate_limiter`). Not a
/// schema bound — no config value is checked against it — but a
/// process-lifetime memory guarantee: an `[ip]`-selector limiter under
/// key spray can hold at most `shards * this` keys per window per rule,
/// after which idlest-first eviction takes over (a deliberately fixed
/// constant rather than an ops knob; revisit if operators need to tune).
pub const MAX_RATE_LIMITER_KEYS_PER_SHARD: usize = 4_096;

/// Runtime bound on the replay-nonce entries the HMAC request-signing
/// nonce cache (DW-036, `security::authn`) holds PER SHARD. Not a
/// schema bound — a process-lifetime memory guarantee under nonce
/// flood, exactly the GCRA cap's rationale: entries expire after twice
/// the clock-skew window anyway, and the cap only binds when an
/// attacker floods nonces faster than expiry retires them (a fixed
/// constant rather than an ops knob).
pub const MAX_NONCE_CACHE_ENTRIES_PER_SHARD: usize = 4_096;

/// Validation bound on `gateway.webhooks[].max_attempts` (DW-044):
/// deliveries retry at most this many times in total, so a dead target
/// cannot occupy its delivery task (or the retry budget) indefinitely.
pub const MAX_WEBHOOK_ATTEMPTS: u32 = 10;

/// Validation bound on `gateway.webhooks[].timeout_ms` (DW-044): one
/// minute is the largest per-delivery budget worth waiting on an ALERT
/// (the gateway is not a durable queue; anything slower should be an
/// event sink, not a webhook).
pub const MAX_WEBHOOK_TIMEOUT_MS: u64 = 60_000;

/// Validation bound on `gateway.analytics_stream.buffer` (DW-121): the
/// firehose channel's capacity floor. Below this a single flush tick of
/// bursty traffic would spill into emit-time drops that no buffer
/// tuning could have absorbed.
pub const MIN_STREAM_BUFFER: u64 = 64;

/// Validation bound on `gateway.analytics_stream.buffer` (DW-121): the
/// ceiling on records queued between the dataplane and the flusher.
/// Every queued record is an owned copy of the access record, so the
/// buffer is the firehose's whole memory story — this bound keeps a
/// mistyped config from allocating an unbounded "bounded" queue.
pub const MAX_STREAM_BUFFER: u64 = 65_536;

/// Validation bound on `gateway.analytics_stream.flush_ms` (DW-121):
/// the batch-latency ceiling (one minute — the same shape as the
/// webhook timeout ceiling: a batch older than this is a backlogged
/// pipeline, not a tuning knob).
pub const MAX_STREAM_FLUSH_MS: u64 = 60_000;

/// Validation floor on `gateway.analytics_stream.flush_ms` (DW-121):
/// below 100 ms the flusher degenerates into per-record delivery, which
/// the batch knob exists to prevent.
pub const MIN_STREAM_FLUSH_MS: u64 = 100;

/// Validation bound on `gateway.analytics_stream.batch_max` (DW-121):
/// records per flushed batch ceiling (with the byte cap, whichever
/// comes first — the batch is the delivery unit, so this is also the
/// per-delivery record-count bound).
pub const MAX_STREAM_BATCH_RECORDS: u64 = 4_096;

/// Validation bound on `routes[].websocket.max_frames_per_sec`
/// (DW-039): one hundred thousand frames per second sustained is the
/// most an operator should need to allow (a chatty app ticks far
/// below it; above it the policing itself becomes the load).
pub const MAX_WEBSOCKET_FRAMES_PER_SEC: u64 = 100_000;
