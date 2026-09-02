//! Unit tests for the response-cache engine's pure pieces (DW-037):
//! the store envelope codec, key derivation's separation guarantees,
//! validator (If-None-Match / ETag) matching, the storage veto matrix,
//! and the epoch invalidation rules. End-to-end behavior lives in
//! `tests/caching.rs`.

use std::collections::BTreeMap;

use dwara_core::config::cache::CompiledRouteCache;
use dwara_core::dataplane::response_cache::{
    derive_key, inm_matches, store_veto, validators_match, EntryEnvelope,
};
use dwara_core::security::authn::Identity;

fn identity(name: &str) -> Identity {
    Identity {
        consumer_name: name.to_string(),
        credential_kind: dwara_core::state::store::CredentialKind::ApiKey,
        consumer_type: dwara_core::config::ConsumerType::User,
        groups: Vec::new(),
        claims: BTreeMap::new(),
        body_digest: None,
    }
}

fn policy(vary: &[&str]) -> CompiledRouteCache {
    CompiledRouteCache {
        ttl: std::time::Duration::from_secs(30),
        stale_while_revalidate: std::time::Duration::from_secs(0),
        max_body_bytes: 1024,
        vary: vary.iter().map(|s| s.to_string()).collect(),
        coalesce_wait: None,
    }
}

fn entry() -> EntryEnvelope {
    EntryEnvelope {
        epoch: 3,
        stored_at_ms: 1_000,
        status: 200,
        headers: vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"etag".to_vec(), b"\"v1\"".to_vec()),
            (b"x-custom".to_vec(), b"kept".to_vec()),
        ],
        body: br#"{"ok":true}"#.to_vec(),
    }
}

#[test]
fn envelope_round_trips_exactly() {
    let e = entry();
    let bytes = e.encode();
    let back = EntryEnvelope::decode(&bytes).expect("envelope decodes");
    assert_eq!(back, e);
    assert_eq!(back.header("etag"), Some(&b"\"v1\""[..]));
    assert_eq!(
        back.header("ETAG"),
        Some(&b"\"v1\""[..]),
        "case-insensitive"
    );
    assert_eq!(back.header("missing"), None);
}

#[test]
fn envelope_rejects_corruption_and_foreign_bytes() {
    let bytes = entry().encode();
    // Bad magic (a foreign writer / wrong schema).
    assert!(EntryEnvelope::decode(b"XXXXjunk").is_none());
    // Truncation at every interior offset.
    for cut in 1..bytes.len() {
        assert!(
            EntryEnvelope::decode(&bytes[..cut]).is_none(),
            "cut at {cut}"
        );
    }
    // Trailing bytes (framing mismatch).
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(EntryEnvelope::decode(&padded).is_none());
    // A version from the future.
    let mut future = bytes;
    let v = ENVELOPE_VERSION_INDEX;
    future[v] += 1;
    assert!(EntryEnvelope::decode(&future).is_none());
}

/// Offset of the schema-version byte in the envelope frame (magic is
/// 4 bytes; version follows).
const ENVELOPE_VERSION_INDEX: usize = 4;

#[test]
fn keys_separate_every_dimension() {
    let base = derive_key("api", 0, None, "/x", Some("q=1"), &[]);
    // Route.
    assert_ne!(base, derive_key("other", 0, None, "/x", Some("q=1"), &[]));
    // Epoch (the purge/config invalidation dimension).
    assert_ne!(base, derive_key("api", 1, None, "/x", Some("q=1"), &[]));
    // Consumer (the DW-029 masking isolation dimension).
    let a = derive_key("api", 0, Some(&identity("a")), "/x", Some("q=1"), &[]);
    let b = derive_key("api", 0, Some(&identity("b")), "/x", Some("q=1"), &[]);
    assert_ne!(a, b);
    assert_ne!(a, base, "authenticated and anonymous never share");
    // Path and query.
    assert_ne!(base, derive_key("api", 0, None, "/y", Some("q=1"), &[]));
    assert_ne!(base, derive_key("api", 0, None, "/x", Some("q=2"), &[]));
    assert_ne!(base, derive_key("api", 0, None, "/x", None, &[]));
    // Vary values (different values; different SETS with empty values).
    let vary_a = vec![("x-tenant".to_string(), "a".to_string())];
    let vary_b = vec![("x-tenant".to_string(), "b".to_string())];
    assert_ne!(
        derive_key("api", 0, None, "/x", None, &vary_a),
        derive_key("api", 0, None, "/x", None, &vary_b)
    );
    assert_ne!(
        derive_key("api", 0, None, "/x", None, &vary_a),
        derive_key("api", 0, None, "/x", None, &[])
    );
    // Determinism: same inputs, same key.
    assert_eq!(base, derive_key("api", 0, None, "/x", Some("q=1"), &[]));
    // Keys are opaque hex, never contain the path or query.
    assert!(!base.contains("/x"));
    assert!(!base.contains("q=1"));
}

#[test]
fn inm_matching_is_weak_and_list_aware() {
    assert!(inm_matches("*", Some("\"v1\"")));
    assert!(inm_matches("\"v1\"", Some("\"v1\"")));
    assert!(inm_matches("\"v0\", \"v1\"", Some("\"v1\"")));
    // Weak comparison: W/ prefixes ignored on both sides (RFC 9110
    // 8.8.3 — If-None-Match uses the weak function).
    assert!(inm_matches("W/\"v1\"", Some("\"v1\"")));
    assert!(inm_matches("\"v1\"", Some("W/\"v1\"")));
    assert!(!inm_matches("\"v2\"", Some("\"v1\"")));
    // No stored validator: never a match.
    assert!(!inm_matches("*", None));
    assert!(!inm_matches("\"v1\"", None));
}

#[test]
fn validators_agree_on_absence_and_weak_equality() {
    assert!(validators_match(None, None));
    assert!(validators_match(Some("\"v1\""), Some("W/\"v1\"")));
    assert!(!validators_match(Some("\"v2\""), Some("\"v1\"")));
    assert!(!validators_match(Some("\"v1\""), None));
    assert!(!validators_match(None, Some("\"v1\"")));
}

fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
    let mut map = hyper::HeaderMap::new();
    for (name, value) in pairs {
        map.insert(
            hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            hyper::header::HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

#[test]
fn store_veto_matrix() {
    let p = policy(&["x-tenant"]);
    // Plain 200: storable.
    assert_eq!(
        store_veto(&headers(&[("content-type", "text/plain")]), &p),
        None
    );
    // Each veto, deterministic and named.
    assert_eq!(
        store_veto(&headers(&[("set-cookie", "s=1")]), &p),
        Some("set_cookie")
    );
    for cc in ["no-store", "private", "no-cache", "max-age=5, no-store"] {
        assert_eq!(
            store_veto(&headers(&[("cache-control", cc)]), &p),
            Some("cache_control"),
            "cache-control: {cc} must veto"
        );
    }
    // A non-vetoing directive does not.
    assert_eq!(
        store_veto(&headers(&[("cache-control", "max-age=5")]), &p),
        None
    );
    assert_eq!(
        store_veto(&headers(&[("content-encoding", "gzip")]), &p),
        Some("content_encoding")
    );
    assert_eq!(
        store_veto(&headers(&[("vary", "*")]), &p),
        Some("vary_star")
    );
    assert_eq!(
        store_veto(&headers(&[("vary", "x-other")]), &p),
        Some("vary_uncovered")
    );
    // Covered dimensions (including case) store.
    assert_eq!(
        store_veto(&headers(&[("vary", "x-tenant, x-tenant")]), &p),
        None
    );
}

#[test]
fn compiled_policy_folds_policy_derived_vary() {
    use dwara_core::config::cache::RouteCache;
    let rc = RouteCache {
        ttl_secs: 30,
        stale_while_revalidate_secs: Some(5),
        max_body_bytes: 4096,
        vary: vec!["x-tenant".to_string()],
        coalescing: None,
    };
    let compiled = CompiledRouteCache::compile(&rc, true, true);
    // Configured + Accept (match.accept route) + Origin (CORS route).
    assert_eq!(compiled.vary, vec!["x-tenant", "accept", "origin"]);
    assert_eq!(compiled.ttl.as_secs(), 30);
    assert_eq!(compiled.stale_while_revalidate.as_secs(), 5);
    assert_eq!(compiled.max_body_bytes, 4096);
    assert_eq!(compiled.coalesce_wait, None);
    // No folds without the policies; configured duplicates dedupe.
    let rc2 = RouteCache {
        ttl_secs: 30,
        stale_while_revalidate_secs: None,
        max_body_bytes: 4096,
        vary: vec!["accept".to_string()],
        coalescing: Some(dwara_core::config::cache::RouteCacheCoalescing { wait_ms: 1500 }),
    };
    assert_eq!(
        CompiledRouteCache::compile(&rc2, false, false).vary,
        vec!["accept"]
    );
    assert_eq!(
        CompiledRouteCache::compile(&rc2, false, false).coalesce_wait,
        Some(std::time::Duration::from_millis(1500)),
        "the coalescing wait compiles through (DW-038)"
    );
}
