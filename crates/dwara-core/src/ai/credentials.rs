//! Provider credential pools (DW-080, Ent).
//!
//! A credential pool holds N resolved API keys for a single provider.
//! At request time the pool picks one credential (round-robin or
//! weighted); when a key receives a 429 from the provider, it is
//! quarantined for a configurable window and subsequent requests
//! rotate to the next available key. Pool exhaustion (all keys
//! quarantined) degrades gracefully — the request fails with a 429 +
//! Retry-After, not a panic.
//!
//! The pool is compiled from the `ai.providers[].credential_pool`
//! config block at `AiRuntime::compile` time (each entry's secret is
//! resolved via the same `resolve_configured_secret` path as singular
//! auth). The pool lives inside `CompiledProvider` and is accessed
//! per-request by the AI proxy. Quarantine state is mutable and
//! thread-safe (behind `Mutex`); the rest of `CompiledProvider` is
//! immutable.
//!
//! Ent-only: the config schema accepts `credential_pool` regardless of
//! the `ent` feature, but snapshot validation rejects it when `ent` is
//! off (the runtime module is not compiled and the pool machinery does
//! not exist). This keeps the config schema uniform across editions
//! while the behavior is edition-gated.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::ai::{AiCredentialPool, AiPoolStrategy};

/// A single resolved credential in the pool. The header name + value
/// are injected into the outbound request exactly like singular auth.
#[derive(Debug, Clone)]
pub struct PoolEntry {
    /// Header name (e.g. `Authorization`, `x-api-key`).
    pub header: String,
    /// Resolved header value (secret-bearing; never logged).
    pub value: String,
    /// Index into the pool (for attribution + admin API visibility).
    pub index: usize,
}

/// Per-key quarantine state. A key is quarantined until `until` passes;
/// after that it re-enters rotation.
#[derive(Debug, Clone)]
struct QuarantineState {
    /// When the quarantine window expires and the key re-enters rotation.
    until: Instant,
    /// How many times this key has been quarantined (cumulative, for
    /// admin API visibility).
    count: u64,
}

/// AI-09 (#198): Per-key health state derived from provider rate-limit
/// headers. Updated on every provider response (200 or error). The
/// pool uses `remaining` to proactively cool keys before a 429 occurs:
/// when `remaining` is 0 (or below a threshold), the key is
/// quarantined for the provider's reset window.
#[derive(Debug, Clone, Default)]
pub struct KeyHealth {
    /// Remaining requests in the current window (from
    /// `x-ratelimit-remaining-requests` or equivalent). None when the
    /// provider does not report it.
    pub remaining_requests: Option<u64>,
    /// Remaining tokens in the current window (from
    /// `x-ratelimit-remaining-tokens` or equivalent). None when the
    /// provider does not report it.
    pub remaining_tokens: Option<u64>,
    /// When the current rate-limit window resets (from
    /// `x-ratelimit-reset-requests` / `x-ratelimit-reset-tokens` or
    /// equivalent), as an `Instant` relative to the process clock.
    pub reset_at: Option<Instant>,
    /// The HTTP status of the last provider response observed for
    /// this key.
    pub last_status: Option<u16>,
    /// When the health was last updated (process clock).
    pub updated_at: Option<Instant>,
}

/// The compiled credential pool (DW-080). Lives inside
/// `CompiledProvider` behind an `Arc` so the quarantine state can be
/// shared across request tasks without cloning the whole provider.
#[derive(Debug)]
pub struct CredentialPool {
    /// Resolved credential entries (header + value per key).
    entries: Vec<PoolEntry>,
    /// Rotation strategy.
    strategy: AiPoolStrategy,
    /// Default quarantine window.
    quarantine_secs: u64,
    /// Mutable quarantine state: key index -> quarantine expiry.
    /// Behind a Mutex for thread-safe per-request access.
    quarantine: Mutex<HashMap<usize, QuarantineState>>,
    /// AI-09 (#198): Per-key health state from provider headers.
    health: Mutex<HashMap<usize, KeyHealth>>,
    /// Round-robin counter (behind a Mutex for atomicity).
    rr_counter: Mutex<usize>,
}

impl CredentialPool {
    /// Build a pool from the config block + resolved credentials.
    /// `entries` must be non-empty and in the same order as the config
    /// `credentials` list (the index is used for quarantine tracking).
    pub fn new(entries: Vec<PoolEntry>, cfg: &AiCredentialPool) -> Self {
        Self {
            entries,
            strategy: cfg.strategy,
            quarantine_secs: cfg.quarantine_secs,
            quarantine: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
            rr_counter: Mutex::new(0),
        }
    }

    /// Number of credentials in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Pick a credential for the next request. Skips quarantined keys;
    /// if all keys are quarantined, returns None (pool exhaustion — the
    /// caller should fail with a 429 + Retry-After).
    ///
    /// For `RoundRobin`: cycles through non-quarantined keys in order.
    /// For `Weighted`: uses a deterministic hash of `request_id` to
    /// pick a key (same hash as canary splits), skipping quarantined
    /// keys.
    pub fn pick(&self, request_id: &str) -> Option<&PoolEntry> {
        let available = self.available_indices();
        if available.is_empty() {
            return None;
        }
        let idx = match self.strategy {
            AiPoolStrategy::RoundRobin => {
                let mut counter = self.rr_counter.lock().unwrap();
                let pick = available[*counter % available.len()];
                *counter = (*counter + 1) % available.len().max(1);
                pick
            }
            AiPoolStrategy::Weighted => {
                // Deterministic pick: hash the request id and pick
                // from the available set. Same approach as canary
                // weighted_pick (ai/routing.rs).
                let hash = weighted_hash(request_id);
                available[hash % available.len()]
            }
        };
        self.entries.get(idx)
    }

    /// Quarantine a credential after a 429 from the provider. The key
    /// is skipped for `quarantine_secs` (or the provider's Retry-After,
    /// capped at 600 seconds, if the caller passes it). Idempotent —
    /// quarantining an already-quarantined key extends the window.
    pub fn quarantine(&self, index: usize, retry_after_secs: Option<u64>) {
        let secs = retry_after_secs.unwrap_or(self.quarantine_secs).min(600);
        let until = Instant::now() + Duration::from_secs(secs);
        let mut q = self.quarantine.lock().unwrap();
        let entry = q
            .entry(index)
            .or_insert(QuarantineState { until, count: 0 });
        entry.until = until;
        entry.count += 1;
    }

    /// AI-09 (#198): Record per-key health from provider response
    /// headers. Called on every provider response (200 or error).
    /// When `remaining_requests` is 0 (or `remaining_tokens` is 0),
    /// the key is proactively quarantined until `reset_at` to prevent
    /// a 429 on the next request.
    pub fn record_health(&self, index: usize, health: KeyHealth) {
        // Proactive cooldown: if remaining is 0, quarantine until reset.
        let should_cooldown =
            health.remaining_requests == Some(0) || health.remaining_tokens == Some(0);
        if should_cooldown {
            let until = health
                .reset_at
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(self.quarantine_secs));
            let now = Instant::now();
            if until > now {
                let secs = (until - now).as_secs().min(600);
                self.quarantine(index, Some(secs));
                tracing::info!(
                    code = "ai_credential_pool_proactive_cooldown",
                    key_index = index,
                    remaining_requests = ?health.remaining_requests,
                    remaining_tokens = ?health.remaining_tokens,
                    "credential pool key proactively cooled down (rate-limit exhausted)"
                );
            }
        }
        let mut h = self.health.lock().unwrap();
        h.insert(index, health);
    }

    /// Returns true if all keys are currently quarantined (pool
    /// exhaustion). The caller should fail with a 429 + Retry-After.
    pub fn is_exhausted(&self) -> bool {
        self.available_indices().is_empty()
    }

    /// The earliest quarantine expiry among all keys (for the
    /// Retry-After header on pool-exhaustion 429s). Returns None if
    /// no keys are quarantined.
    pub fn earliest_quarantine_expiry(&self) -> Option<Instant> {
        let q = self.quarantine.lock().unwrap();
        let now = Instant::now();
        q.values()
            .filter(|state| state.until > now)
            .map(|state| state.until)
            .min()
    }

    /// Snapshot of the pool state for the admin API (per-key usage +
    /// quarantine status + health). Never includes secret values.
    pub fn status(&self) -> Vec<CredentialStatus> {
        let q = self.quarantine.lock().unwrap();
        let h = self.health.lock().unwrap();
        let now = Instant::now();
        self.entries
            .iter()
            .map(|e| {
                let state = q.get(&e.index);
                let health = h.get(&e.index);
                CredentialStatus {
                    index: e.index,
                    header: e.header.clone(),
                    quarantined: state.is_some_and(|s| s.until > now),
                    quarantine_count: state.map(|s| s.count).unwrap_or(0),
                    remaining_requests: health.and_then(|h| h.remaining_requests),
                    remaining_tokens: health.and_then(|h| h.remaining_tokens),
                    last_status: health.and_then(|h| h.last_status),
                }
            })
            .collect()
    }

    /// Indices of non-quarantined keys (available for rotation).
    fn available_indices(&self) -> Vec<usize> {
        let now = Instant::now();
        let q = self.quarantine.lock().unwrap();
        (0..self.entries.len())
            .filter(|&i| q.get(&i).is_none_or(|s| s.until <= now))
            .collect()
    }
}

/// Admin-facing per-key status (no secret values).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CredentialStatus {
    /// Pool index (0-based).
    pub index: usize,
    /// Header name (e.g. `Authorization`).
    pub header: String,
    /// Whether the key is currently quarantined (429 from provider
    /// or proactive cooldown from rate-limit headers).
    pub quarantined: bool,
    /// Cumulative number of times this key has been quarantined.
    pub quarantine_count: u64,
    /// AI-09 (#198): Remaining requests in the current rate-limit
    /// window (from provider headers). None when not reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_requests: Option<u64>,
    /// AI-09 (#198): Remaining tokens in the current rate-limit
    /// window (from provider headers). None when not reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_tokens: Option<u64>,
    /// AI-09 (#198): HTTP status of the last provider response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_status: Option<u16>,
}

/// Deterministic hash for weighted picks (same approach as
/// `ai::routing::weighted_pick`). Uses FNV-1a on the request id.
fn weighted_hash(s: &str) -> usize {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash as usize
}
