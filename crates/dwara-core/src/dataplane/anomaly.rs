//! Lightweight statistical anomaly scoring (DW-090).
//!
//! A first-line traffic filter that scores requests against configurable
//! request-shape signals (header entropy, header count/bytes, path
//! length/depth, query count, body size, unusual method). Each signal
//! produces a normalized [0, 1] sub-score; the overall score is the
//! average of the configured signals' scores. A score at or above the
//! policy's `threshold` is blocked (403 `anomaly_blocked`) unless
//! `dry_run` is set (scored and logged, request proceeds).
//!
//! ## Request-path position
//!
//! The anomaly check runs AFTER the WAF-lite filter and BEFORE the route
//! limits (DW-027): it is an inspection phase like the WAF, rejecting
//! abusive request shapes before any resource is spent on auth or rate
//! limiting. It inspects the ORIGINAL request (before path rewrite /
//! transforms).
//!
//! ## Design constraints
//!
//! - No ML, no heavy computation on the hot path: every signal is O(1)
//!   or O(n) in the header count/size (already bounded by the parser
//!   hardening knobs).
//! - No new dependencies: the Shannon entropy and normalization math is
//!   in-house (a byte-frequency histogram over a stack array).
//! - The scorer is compiled once per config generation (like the WAF and
//!   rate-limit engines) and reused across requests.

use hyper::HeaderMap;

use crate::config::{AnomalyPolicy, AnomalySignal};

/// A compiled anomaly-scoring generation: the configured signals, the
/// block threshold, the body inspection cap, and the dry-run flag. Built
/// once per config generation from [`AnomalyPolicy`] and reused across
/// requests.
pub struct AnomalyScorer {
    signals: Vec<AnomalySignal>,
    threshold: f64,
    max_body_inspect_bytes: u64,
    dry_run: bool,
}

/// The result of scoring one request: the overall score, whether it
/// triggered (>= threshold), and the per-signal sub-scores for
/// observability/logging.
pub struct AnomalyResult {
    /// The overall score in [0, 1] (the average of the configured
    /// signals' sub-scores).
    pub score: f64,
    /// Whether the score is at or above the policy's threshold.
    pub triggered: bool,
    /// One (signal_name, sub_score) pair per configured signal, in
    /// configuration order. The signal names are the snake_case enum
    /// variants.
    pub signals: Vec<(String, f64)>,
}

impl AnomalyScorer {
    /// Compile a scorer from the policy config. Returns `None` when the
    /// policy is disabled (`enabled: false`) — the caller skips scoring
    /// entirely in that case.
    pub fn compile(policy: &AnomalyPolicy) -> Option<Self> {
        if !policy.enabled {
            return None;
        }
        Some(AnomalyScorer {
            signals: policy.signals.clone(),
            threshold: policy.threshold,
            max_body_inspect_bytes: policy.max_body_inspect_bytes,
            dry_run: policy.dry_run,
        })
    }

    /// Whether this scorer is in dry-run (audit-log-only) mode.
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Score a request against the configured signals. `body_prefix` is
    /// an optional buffered body slice (up to `max_body_inspect_bytes`);
    /// `None` means the body was not inspected (the `body_size` signal
    /// scores 0.0 in that case).
    pub fn score(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body_prefix: Option<&[u8]>,
    ) -> AnomalyResult {
        let mut subs: Vec<(String, f64)> = Vec::with_capacity(self.signals.len());
        for &signal in &self.signals {
            let (name, val) = match signal {
                AnomalySignal::HeaderEntropy => ("header_entropy", header_entropy(headers)),
                AnomalySignal::HeaderCount => ("header_count", header_count(headers)),
                AnomalySignal::HeaderBytes => ("header_bytes", header_bytes(headers)),
                AnomalySignal::PathLength => ("path_length", path_length(path)),
                AnomalySignal::PathDepth => ("path_depth", path_depth(path)),
                AnomalySignal::QueryCount => ("query_count", query_count(query.unwrap_or(""))),
                AnomalySignal::BodySize => (
                    "body_size",
                    body_size(body_prefix, self.max_body_inspect_bytes),
                ),
                AnomalySignal::MethodUnusual => ("method_unusual", method_unusual(method)),
            };
            subs.push((name.to_string(), val));
        }
        let score = if subs.is_empty() {
            0.0
        } else {
            subs.iter().map(|(_, v)| *v).sum::<f64>() / subs.len() as f64
        };
        let triggered = score >= self.threshold;
        AnomalyResult {
            score,
            triggered,
            signals: subs,
        }
    }
}

/// Shannon entropy of concatenated header values, normalized by 8 (the
/// max entropy for byte values). Returns a value in [0, 1] where 1 =
/// high entropy (potentially suspicious randomized/obfuscated payloads).
///
/// The histogram is a stack-allocated [u64; 256] byte-frequency table.
/// Concatenating all header values and computing the byte distribution
/// is O(total header bytes) — already bounded by the parser hardening
/// knobs (`DWARA_HTTP1_MAX_HEADERS`, `DWARA_HTTP1_MAX_BUF_KIB`).
fn header_entropy(headers: &HeaderMap) -> f64 {
    // Concatenate all header values into a single byte stream.
    let mut buf: Vec<u8> = Vec::new();
    for val in headers.values() {
        buf.extend_from_slice(val.as_bytes());
    }
    if buf.is_empty() {
        return 0.0;
    }
    // Byte-frequency histogram.
    let mut counts = [0u64; 256];
    for &b in &buf {
        counts[b as usize] += 1;
    }
    let total = buf.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        entropy -= p * p.log2();
    }
    // Normalize by 8 (max entropy for 256 equally-likely byte values).
    (entropy / 8.0).clamp(0.0, 1.0)
}

/// Header count outlier: `count / 50`, capped at 1.0. A request with 50
/// or more header fields scores 1.0.
fn header_count(headers: &HeaderMap) -> f64 {
    let count = headers.len() as f64;
    (count / 50.0).clamp(0.0, 1.0)
}

/// Total header bytes outlier: `bytes / 8192`, capped at 1.0. The byte
/// count is the sum of every header name + value + separator overhead
/// (name.len() + value.len() + 4 for ": " and "\r\n").
fn header_bytes(headers: &HeaderMap) -> f64 {
    let mut bytes: u64 = 0;
    for (name, val) in headers.iter() {
        bytes += name.as_str().len() as u64;
        bytes += val.as_bytes().len() as u64;
        bytes += 4; // ": " + "\r\n"
    }
    (bytes as f64 / 8192.0).clamp(0.0, 1.0)
}

/// Path length outlier: `len / 1024`, capped at 1.0.
fn path_length(path: &str) -> f64 {
    (path.len() as f64 / 1024.0).clamp(0.0, 1.0)
}

/// Path depth outlier: the number of non-empty path segments / 20,
/// capped at 1.0. A path like `/a/b/c/d` has depth 4.
fn path_depth(path: &str) -> f64 {
    let depth = path.split('/').filter(|s| !s.is_empty()).count() as f64;
    (depth / 20.0).clamp(0.0, 1.0)
}

/// Query parameter count outlier: the number of `key=value` pairs /
/// 50, capped at 1.0. Splits on `&` and counts non-empty segments.
fn query_count(query: &str) -> f64 {
    if query.is_empty() {
        return 0.0;
    }
    let count = query.split('&').filter(|s| !s.is_empty()).count() as f64;
    (count / 50.0).clamp(0.0, 1.0)
}

/// Body size outlier: `min(body_len, cap) / cap`, capped at 1.0. When
/// no body prefix was inspected, scores 0.0.
fn body_size(body_prefix: Option<&[u8]>, cap: u64) -> f64 {
    let cap = cap.max(1) as f64;
    let len = body_prefix.map(|b| b.len() as f64).unwrap_or(0.0);
    (len / cap).clamp(0.0, 1.0)
}

/// Unusual HTTP method: 1.0 if the method is not one of GET, POST, PUT,
/// DELETE, PATCH, HEAD, OPTIONS; 0.0 otherwise. Case-sensitive (HTTP
/// methods are uppercase by convention and hyper normalizes them).
fn method_unusual(method: &str) -> f64 {
    match method {
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => 0.0,
        _ => 1.0,
    }
}
