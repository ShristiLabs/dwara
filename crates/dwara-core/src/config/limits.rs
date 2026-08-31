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

/// Validation bounds on `retries.hedge.hedge_after_ms` (DW-063): the
/// tail-latency threshold before a speculative copy is sent. Below 1 ms
/// is pointless (the copy would race immediately); above 5 minutes the
/// upstream is almost certainly dead and a retry or breaker is the
/// right tool, not a hedge.
pub const MIN_HEDGE_AFTER_MS: u64 = 1;
pub const MAX_HEDGE_AFTER_MS: u64 = 300_000;

/// Validation bound on `retries.hedge.hedge_max` (DW-063): at most this
/// many speculative copies per request. Each copy consumes an
/// endpoint slot and a retry-budget charge, so the cap bounds the
/// amplification factor.
pub const MAX_HEDGE_COPIES: u32 = 4;

/// Validation bound on `routes[].fault_injection.delay.fixed_ms`
/// (DW-062): the maximum injectable delay. Above 5 minutes the upstream
/// is almost certainly dead and a timeout or breaker is the right tool,
/// not a fault-injection delay.
pub const MAX_FAULT_DELAY_MS: u64 = 300_000;

/// Validation bound on `routes[].fault_injection.abort.status`
/// (DW-062): the HTTP status range for abort injection.
pub const MIN_FAULT_ABORT_STATUS: u16 = 100;
pub const MAX_FAULT_ABORT_STATUS: u16 = 599;

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

/// Default grace period (days) after a license expires before the gate
/// degrades to OSS (DW-032). Configurable via
/// `gateway.license.grace_period_days`; 0 means no grace (immediate
/// degradation on expiry). Lives in config (the lowest domain) so both
/// extensions::licensing (the gate) and snapshot::validate (the bounds
/// check) can read it without an upward import.
pub const DEFAULT_LICENSE_GRACE_PERIOD_DAYS: u32 = 7;

/// Maximum configurable grace period (days) after license expiry
/// (DW-032). `gateway.license.grace_period_days` is validated to
/// 0..=this.
pub const MAX_LICENSE_GRACE_PERIOD_DAYS: u32 = 30;

/// Validation floor on `gateway.redis_rate_limiter.connection_timeout_ms`
/// (DW-031): below 100 ms a connection attempt is too aggressive for a
/// network round-trip (the timeout would fire before DNS resolution
/// completes on many setups).
pub const MIN_REDIS_CONNECTION_TIMEOUT_MS: u64 = 100;

/// Validation ceiling on `gateway.redis_rate_limiter.connection_timeout_ms`
/// (DW-031): 30 seconds is the longest a startup connection should
/// stall the gateway (beyond that the operator should fix their Redis,
/// not widen the timeout).
pub const MAX_REDIS_CONNECTION_TIMEOUT_MS: u64 = 30_000;

/// Validation floor on `gateway.redis_rate_limiter.key_ttl_s` (DW-031):
/// below 1 second keys would expire before the GCRA bucket can refill
/// for any non-trivial rate, making the limiter ineffective.
pub const MIN_REDIS_KEY_TTL_S: u64 = 1;

/// Validation ceiling on `gateway.redis_rate_limiter.key_ttl_s`
/// (DW-031): 7 days is the longest a stale rate-limit key should
/// linger in Redis (beyond that the operator should lower it to keep
/// Redis memory bounded under key spray).
pub const MAX_REDIS_KEY_TTL_S: u64 = 604_800;

/// Validation floor on `gateway.oidc_providers[].introspection_cache_ttl_s`
/// (DW-034): below 1 second the introspection cache would expire before
/// the next request can benefit, degenerating into a per-request IdP
/// call (the cache exists precisely to avoid that).
pub const MIN_OIDC_INTROSPECTION_CACHE_TTL_S: u64 = 1;

/// Validation ceiling on
/// `gateway.oidc_providers[].introspection_cache_ttl_s` (DW-034): one
/// hour is the longest a cached `active: true` introspection should be
/// trusted without re-checking (a revoked token would otherwise keep
/// authenticating for an hour after revocation).
pub const MAX_OIDC_INTROSPECTION_CACHE_TTL_S: u64 = 3600;

/// Validation floor on `upstreams[].dns_discovery.refresh_interval_s`
/// (DW-042): below 1 second the discovery task would re-resolve faster
/// than DNS can meaningfully change, hammering the name server.
pub const MIN_DNS_DISCOVERY_REFRESH_S: u64 = 1;

/// Validation ceiling on `upstreams[].dns_discovery.refresh_interval_s`
/// (DW-042): one hour is the longest an operator should go without
/// noticing a stale endpoint set (beyond that the TTL-driven refresh
/// is the better mechanism).
pub const MAX_DNS_DISCOVERY_REFRESH_S: u64 = 3_600;

/// Validation floor on `gateway.config_convergence.poll_interval_ms`
/// (DW-054): below 100 ms the convergence poll would hammer the backend
/// faster than another instance can publish a generation, and the
/// round-trip itself dominates the interval.
pub const MIN_CONFIG_CONVERGENCE_POLL_MS: u64 = 100;

/// Validation ceiling on `gateway.config_convergence.poll_interval_ms`
/// (DW-054): one minute is the longest convergence lag an operator
/// should tolerate (the done-when targets sub-second convergence; a
/// poll this slow is a misconfiguration).
pub const MAX_CONFIG_CONVERGENCE_POLL_MS: u64 = 60_000;

/// Validation floor on
/// `gateway.config_convergence.drift_check_interval_ms` (DW-054): below
/// one second the drift check would race the poll and report transient
/// mid-convergence divergence as drift (noise).
pub const MIN_CONFIG_CONVERGENCE_DRIFT_CHECK_MS: u64 = 1_000;

/// Validation ceiling on
/// `gateway.config_convergence.drift_check_interval_ms` (DW-054): five
/// minutes is the longest an operator should go without a drift report
/// (beyond that a divergent instance serves stale config for too long
/// before anyone notices).
pub const MAX_CONFIG_CONVERGENCE_DRIFT_CHECK_MS: u64 = 300_000;
