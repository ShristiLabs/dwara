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

/// Validation bound on `retries.attempts` (mirrored in `snapshot::validate`).
pub const MAX_RETRY_ATTEMPTS: u32 = 10;
