//! Unit tests for the admission queue config validation matrix (DW-053).

use dwara_core::config::{parse_gateway, AdmissionQueue};
use dwara_core::snapshot::validate;

/// A minimal valid config with a cap and one route, so the only
/// validation issues are the ones the test targets.
fn base_yaml(cap: &str, aq: &str) -> String {
    format!(
        "{cap}{aq}\
         routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9001\n"
    )
}

fn aq_block(
    enabled: bool,
    max_queue_size: u32,
    queue_timeout_ms: u64,
    per_priority: bool,
) -> String {
    format!(
        "admission_queue:\n\
         \x20 enabled: {enabled}\n\
         \x20 max_queue_size: {max_queue_size}\n\
         \x20 queue_timeout_ms: {queue_timeout_ms}\n\
         \x20 per_priority: {per_priority}\n"
    )
}

#[test]
fn enabled_queue_requires_a_cap() {
    let yaml = base_yaml("", &aq_block(true, 10, 100, true));
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "admission_queue.enabled"
            && i.message.contains("requires max_concurrent_requests")),
        "enabled queue without cap must be rejected: {issues:?}"
    );
}

#[test]
fn disabled_queue_without_cap_is_valid() {
    let yaml = base_yaml("", &aq_block(false, 10, 100, true));
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field.starts_with("admission_queue")),
        "disabled queue without cap must be valid: {issues:?}"
    );
}

#[test]
fn enabled_queue_with_cap_is_valid() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 200, 50, true),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field.starts_with("admission_queue")),
        "enabled queue with cap must be valid: {issues:?}"
    );
}

#[test]
fn max_queue_size_zero_is_rejected() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 0, 100, true),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "admission_queue.max_queue_size"
                && i.message.contains("must be > 0")),
        "max_queue_size 0 must be rejected: {issues:?}"
    );
}

#[test]
fn max_queue_size_over_10000_is_rejected() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 10001, 100, true),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "admission_queue.max_queue_size"
                && i.message.contains("out of range")),
        "max_queue_size 10001 must be rejected: {issues:?}"
    );
}

#[test]
fn max_queue_size_10000_is_valid() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 10000, 100, true),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field == "admission_queue.max_queue_size"),
        "max_queue_size 10000 must be valid: {issues:?}"
    );
}

#[test]
fn queue_timeout_zero_is_rejected() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 10, 0, true),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "admission_queue.queue_timeout_ms"
                && i.message.contains("must be > 0")),
        "queue_timeout_ms 0 must be rejected: {issues:?}"
    );
}

#[test]
fn queue_timeout_over_10000_is_rejected() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 10, 10001, true),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "admission_queue.queue_timeout_ms"
                && i.message.contains("out of range")),
        "queue_timeout_ms 10001 must be rejected: {issues:?}"
    );
}

#[test]
fn queue_timeout_10000_is_valid() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 10, 10000, true),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field == "admission_queue.queue_timeout_ms"),
        "queue_timeout_ms 10000 must be valid: {issues:?}"
    );
}

#[test]
fn per_priority_defaults_to_true() {
    // Omit per_priority: the default should be true.
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        "admission_queue:\n  enabled: true\n  max_queue_size: 10\n  \
         queue_timeout_ms: 100\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    assert!(gateway.admission_queue.as_ref().unwrap().per_priority);
}

#[test]
fn per_priority_false_is_valid() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        &aq_block(true, 10, 100, false),
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    assert!(!gateway.admission_queue.as_ref().unwrap().per_priority);
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field.starts_with("admission_queue")),
        "per_priority false must be valid: {issues:?}"
    );
}

#[test]
fn admission_queue_absent_is_valid() {
    let yaml = base_yaml("max_concurrent_requests: 10\n", "");
    let gateway = parse_gateway(&yaml).expect("parses");
    assert!(gateway.admission_queue.is_none());
    let issues = validate(&gateway);
    assert!(
        !issues
            .iter()
            .any(|i| i.field.starts_with("admission_queue")),
        "absent admission_queue must be valid: {issues:?}"
    );
}

#[test]
fn deny_unknown_fields_on_admission_queue() {
    let yaml = base_yaml(
        "max_concurrent_requests: 10\n",
        "admission_queue:\n  enabled: true\n  max_queue_size: 10\n  \
         queue_timeout_ms: 100\n  bogus: true\n",
    );
    let result = parse_gateway(&yaml);
    assert!(
        result.is_err(),
        "unknown field must be rejected by deny_unknown_fields"
    );
}

#[test]
fn admission_queue_struct_round_trips() {
    let aq = AdmissionQueue {
        enabled: true,
        max_queue_size: 200,
        queue_timeout_ms: 50,
        per_priority: true,
    };
    // Serialize and deserialize: the round trip must preserve values.
    let yaml_str = serde_yaml_ng::to_string(&aq).unwrap();
    let back: AdmissionQueue = serde_yaml_ng::from_str(&yaml_str).unwrap();
    assert_eq!(aq, back);
}
