//! Integration tests for anomaly scoring (DW-090).
//!
//! These tests exercise the `AnomalyScorer` through the public API:
//! `AnomalyScorer::compile` and `score`. They verify each signal's
//! normalization, the overall score computation (average of sub-scores),
//! the threshold trigger, and the dry-run mode.

use hyper::HeaderMap;

use dwara_core::config::{AnomalyPolicy, AnomalySignal};
use dwara_core::dataplane::anomaly::AnomalyScorer;

fn policy_with(signals: Vec<AnomalySignal>, threshold: f64) -> AnomalyPolicy {
    AnomalyPolicy {
        enabled: true,
        dry_run: false,
        signals,
        threshold,
        max_body_inspect_bytes: 4096,
    }
}

fn scorer_with(signals: Vec<AnomalySignal>, threshold: f64) -> AnomalyScorer {
    let policy = policy_with(signals, threshold);
    AnomalyScorer::compile(&policy).expect("enabled policy compiles")
}

// --- compile -----------------------------------------------------------

#[test]
fn disabled_policy_does_not_compile() {
    let policy = AnomalyPolicy {
        enabled: false,
        dry_run: false,
        signals: vec![AnomalySignal::HeaderCount],
        threshold: 0.8,
        max_body_inspect_bytes: 4096,
    };
    assert!(AnomalyScorer::compile(&policy).is_none());
}

#[test]
fn enabled_policy_compiles() {
    let policy = policy_with(vec![AnomalySignal::HeaderCount], 0.8);
    assert!(AnomalyScorer::compile(&policy).is_some());
}

// --- individual signals ------------------------------------------------

#[test]
fn header_count_signal_normalizes() {
    let scorer = scorer_with(vec![AnomalySignal::HeaderCount], 1.0);
    // 0 headers -> 0.0
    let result = scorer.score("GET", "/", None, &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 0.0);
    // 50+ headers -> 1.0 (capped)
    let mut headers = HeaderMap::new();
    for i in 0..60 {
        let name = hyper::header::HeaderName::from_bytes(format!("x-{i}").as_bytes())
            .expect("valid header name");
        headers.insert(name, "v".parse().unwrap());
    }
    let result = scorer.score("GET", "/", None, &headers, None);
    assert_eq!(result.signals[0].1, 1.0);
}

#[test]
fn path_length_signal_normalizes() {
    let scorer = scorer_with(vec![AnomalySignal::PathLength], 1.0);
    // Short path -> near 0
    let result = scorer.score("GET", "/api", None, &HeaderMap::new(), None);
    assert!(result.signals[0].1 < 0.01);
    // 1024+ chars -> 1.0 (capped)
    let long_path = "/".to_string() + &"a".repeat(1024);
    let result = scorer.score("GET", &long_path, None, &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 1.0);
}

#[test]
fn path_depth_signal_normalizes() {
    let scorer = scorer_with(vec![AnomalySignal::PathDepth], 1.0);
    // /a/b/c -> depth 3, score 3/20 = 0.15
    let result = scorer.score("GET", "/a/b/c", None, &HeaderMap::new(), None);
    assert!((result.signals[0].1 - 0.15).abs() < 0.001);
    // 20+ segments -> 1.0 (capped)
    let deep_path = "/a".repeat(21);
    let result = scorer.score("GET", &deep_path, None, &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 1.0);
}

#[test]
fn query_count_signal_normalizes() {
    let scorer = scorer_with(vec![AnomalySignal::QueryCount], 1.0);
    // No query -> 0.0
    let result = scorer.score("GET", "/api", None, &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 0.0);
    // Empty query string -> 0.0
    let result = scorer.score("GET", "/api", Some(""), &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 0.0);
    // 3 params -> 3/50 = 0.06
    let result = scorer.score("GET", "/api", Some("a=1&b=2&c=3"), &HeaderMap::new(), None);
    assert!((result.signals[0].1 - 0.06).abs() < 0.001);
    // 50+ params -> 1.0 (capped)
    let query: String = (0..60)
        .map(|i| format!("k{i}=v"))
        .collect::<Vec<_>>()
        .join("&");
    let result = scorer.score("GET", "/api", Some(&query), &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 1.0);
}

#[test]
fn method_unusual_signal() {
    let scorer = scorer_with(vec![AnomalySignal::MethodUnusual], 1.0);
    // Standard methods -> 0.0
    for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        let result = scorer.score(method, "/", None, &HeaderMap::new(), None);
        assert_eq!(result.signals[0].1, 0.0, "method {method} should be 0.0");
    }
    // Unusual method -> 1.0
    let result = scorer.score("PROPFIND", "/", None, &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 1.0);
}

#[test]
fn body_size_signal_normalizes() {
    let scorer = scorer_with(vec![AnomalySignal::BodySize], 1.0);
    // No body -> 0.0
    let result = scorer.score("GET", "/", None, &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 0.0);
    // 100 bytes / 4096 cap ~ 0.0244
    let body = vec![0u8; 100];
    let result = scorer.score("GET", "/", None, &HeaderMap::new(), Some(&body));
    assert!((result.signals[0].1 - (100.0 / 4096.0)).abs() < 0.001);
    // 4096+ bytes -> 1.0 (capped)
    let body = vec![0u8; 5000];
    let result = scorer.score("GET", "/", None, &HeaderMap::new(), Some(&body));
    assert_eq!(result.signals[0].1, 1.0);
}

#[test]
fn header_entropy_signal() {
    let scorer = scorer_with(vec![AnomalySignal::HeaderEntropy], 1.0);
    // No headers -> 0.0
    let result = scorer.score("GET", "/", None, &HeaderMap::new(), None);
    assert_eq!(result.signals[0].1, 0.0);
    // Low-entropy header values (repeated chars) -> low score
    let mut headers = HeaderMap::new();
    headers.insert("x-low", "aaaa".parse().unwrap());
    let result_low = scorer.score("GET", "/", None, &headers, None);
    assert!(
        result_low.signals[0].1 < 0.5,
        "low entropy should score low"
    );
    // High-entropy header values (varied ASCII bytes) -> higher score
    // than the low-entropy case. Use printable ASCII chars only (valid
    // header value bytes).
    let mut headers = HeaderMap::new();
    let high_entropy: String = (0..100)
        .map(|i| (b'!' as u32 + (i * 7 % 90)) as u8 as char)
        .collect();
    headers.insert("x-high", high_entropy.parse().unwrap());
    let result = scorer.score("GET", "/", None, &headers, None);
    assert!(
        result.signals[0].1 > result_low.signals[0].1,
        "high entropy ({}) should score above low entropy ({})",
        result.signals[0].1,
        result_low.signals[0].1
    );
}

// --- overall score and threshold ---------------------------------------

#[test]
fn overall_score_is_average_of_subscores() {
    let scorer = scorer_with(
        vec![AnomalySignal::MethodUnusual, AnomalySignal::PathLength],
        1.0,
    );
    // MethodUnusual = 0.0 (GET), PathLength = ~0.004 (/api = 4/1024)
    let result = scorer.score("GET", "/api", None, &HeaderMap::new(), None);
    let expected = (0.0 + 4.0 / 1024.0) / 2.0;
    assert!((result.score - expected).abs() < 0.001);
}

#[test]
fn trigger_at_threshold() {
    // MethodUnusual alone with threshold 1.0: PROPFIND scores 1.0,
    // which is >= 1.0, so it triggers.
    let scorer = scorer_with(vec![AnomalySignal::MethodUnusual], 1.0);
    let result = scorer.score("PROPFIND", "/", None, &HeaderMap::new(), None);
    assert!(
        result.triggered,
        "score 1.0 >= threshold 1.0 should trigger"
    );
    // GET scores 0.0, which is < 1.0, so it does not trigger.
    let result = scorer.score("GET", "/", None, &HeaderMap::new(), None);
    assert!(!result.triggered);
}

#[test]
fn trigger_below_threshold_does_not_block() {
    // Two signals: MethodUnusual (0.0 for GET) and PathLength (~0.004
    // for /api). Average ~0.002. Threshold 0.5 -> no trigger.
    let scorer = scorer_with(
        vec![AnomalySignal::MethodUnusual, AnomalySignal::PathLength],
        0.5,
    );
    let result = scorer.score("GET", "/api", None, &HeaderMap::new(), None);
    assert!(!result.triggered);
    assert!(result.score < 0.5);
}

// --- dry run -----------------------------------------------------------

#[test]
fn dry_run_flag_is_propagated() {
    let policy = AnomalyPolicy {
        enabled: true,
        dry_run: true,
        signals: vec![AnomalySignal::MethodUnusual],
        threshold: 0.5,
        max_body_inspect_bytes: 4096,
    };
    let scorer = AnomalyScorer::compile(&policy).expect("compiles");
    assert!(scorer.dry_run());
}

#[test]
fn enforce_flag_is_propagated() {
    let policy = AnomalyPolicy {
        enabled: true,
        dry_run: false,
        signals: vec![AnomalySignal::MethodUnusual],
        threshold: 0.5,
        max_body_inspect_bytes: 4096,
    };
    let scorer = AnomalyScorer::compile(&policy).expect("compiles");
    assert!(!scorer.dry_run());
}
