//! AI prompt/response logging engine (DW-081): the per-generation
//! compiled logging config plus redactor.
//!
//! Wraps the `ai.logging` config block and its compiled [`Redactor`]
//! into one immutable engine stored on the dataplane behind an
//! ArcSwap and swapped on reload. The capture hook in
//! `dataplane::ai_proxy` consults this engine to decide whether to
//! capture a request, apply sampling, and redact before storage.
//!
//! # Sampling
//!
//! The sample decision is DETERMINISTIC per request: a hash of the
//! request id maps to a 0.0..=1.0 value, and the request is captured
//! when that value is below `sample_rate`. A re-send with the same
//! request id lands on the same decision (reproducible), and the
//! distribution is uniform across request ids.
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only (see `scripts/check_deps.py`); this
//! module reads `config::ai::AiConfig` and nothing else. The
//! analytics RECORD DTO lives in `analytics` (a plain struct, not
//! importing `ai`) — the dataplane converts at the call site.

use crate::ai::redaction::Redactor;
use crate::config::ai::AiConfig;
use std::sync::Arc;

/// The per-generation compiled logging engine (DW-081): the enabled
/// flag, sampling rate, retention window, and compiled redactor. Built
/// at dataplane refresh from the published config; immutable once
/// built. Stored on the dataplane behind an ArcSwap and swapped on
/// reload, so a logging change applies to the next request with no
/// restart.
#[derive(Debug, Clone)]
pub struct AiLoggingEngine {
    enabled: bool,
    sample_rate: f64,
    retention_secs: u64,
    redactor: Arc<Redactor>,
}

impl AiLoggingEngine {
    /// Compile from the `ai:` config block. `None` when the block is
    /// absent or the `logging` sub-block is absent (no capture —
    /// privacy-first). When present, the `enabled` flag governs
    /// capture; the redactor is always compiled (a disabled engine
    /// still carries one so a per-consumer `Some(true)` override can
    /// flip capture on without a recompile).
    pub fn compile(cfg: Option<&AiConfig>) -> Option<Self> {
        let cfg = cfg?;
        let logging = cfg.logging.as_ref()?;
        let redactor = Arc::new(Redactor::compile(&logging.redaction));
        Some(AiLoggingEngine {
            enabled: logging.enabled,
            sample_rate: logging.sample_rate,
            retention_secs: logging.retention_secs,
            redactor,
        })
    }

    /// Whether global capture is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The configured sampling rate (0.0..=1.0).
    pub fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    /// The configured retention window in seconds.
    pub fn retention_secs(&self) -> u64 {
        self.retention_secs
    }

    /// The compiled redactor.
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// Resolve whether capture is enabled for a given consumer,
    /// applying the per-consumer override. `consumer_override` is the
    /// consumer's `ai_logging` field: None inherits the global
    /// setting; Some(b) overrides it.
    pub fn capture_for(&self, consumer_override: Option<bool>) -> bool {
        match consumer_override {
            Some(b) => b,
            None => self.enabled,
        }
    }

    /// Deterministic sampling decision for a request id. Returns true
    /// when the request should be captured (the hash of the request id
    /// maps below `sample_rate`). A rate of 1.0 always captures; 0.0
    /// never captures.
    pub fn should_sample(&self, request_id: &str) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        // FxHash-style mix of the request id bytes, mapped to 0.0..=1.0.
        let hash = hash_request_id(request_id);
        let frac = (hash as f64) / (u64::MAX as f64);
        frac < self.sample_rate
    }
}

/// A deterministic hash of the request id for sampling. Uses a simple
/// multiplicative hash (FNV-1a variant) — the goal is uniform
/// distribution across request ids, not cryptographic strength.
fn hash_request_id(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(enabled: bool, sample_rate: f64) -> AiLoggingEngine {
        AiLoggingEngine {
            enabled,
            sample_rate,
            retention_secs: 604_800,
            redactor: Arc::new(Redactor::inert()),
        }
    }

    #[test]
    fn sample_rate_zero_never_captures() {
        let e = engine(true, 0.0);
        assert!(!e.should_sample("req-1"));
        assert!(!e.should_sample("req-2"));
    }

    #[test]
    fn sample_rate_one_always_captures() {
        let e = engine(true, 1.0);
        assert!(e.should_sample("req-1"));
        assert!(e.should_sample("req-2"));
    }

    #[test]
    fn sample_rate_is_deterministic() {
        let e = engine(true, 0.5);
        // The same id always yields the same decision.
        let d1 = e.should_sample("req-abc");
        let d2 = e.should_sample("req-abc");
        assert_eq!(d1, d2);
    }

    #[test]
    fn per_consumer_override_disables() {
        let e = engine(true, 1.0);
        assert!(!e.capture_for(Some(false)));
    }

    #[test]
    fn per_consumer_override_enables() {
        let e = engine(false, 1.0);
        assert!(e.capture_for(Some(true)));
    }

    #[test]
    fn per_consumer_none_inherits_global() {
        let e = engine(true, 1.0);
        assert!(e.capture_for(None));
        let e2 = engine(false, 1.0);
        assert!(!e2.capture_for(None));
    }
}
