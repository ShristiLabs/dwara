//! Unit tests for the response-cache engine's pure pieces (DW-037):
//! the store envelope codec, key derivation's separation guarantees,
//! validator (If-None-Match / ETag) matching, the storage veto matrix,
//! and the epoch invalidation rules. End-to-end behavior lives in
//! `tests/caching.rs`.

use std::collections::BTreeMap;

use dwara_core::config::cache::CompiledRouteCache;
use dwara_core::dataplane::response_cache::{
    derive_key, inm_matches, store_veto, validators_match, CacheControl, EntryEnvelope,
};
use dwara_core::security::authn::Identity;
use hyper::Method;

fn identity(name: &str) -> Identity {
    Identity {
        consumer_name: name.to_string(),
        credential_kind: dwara_core::state::store::CredentialKind::ApiKey,
        consumer_type: dwara_core::config::ConsumerType::User,
        groups: Vec::new(),
        claims: BTreeMap::new(),
        body_digest: None,
        agent: None,
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
        freshness_ttl_ms: 0,
        stale_if_error_ms: 0,
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
    let get = Method::GET;
    let base = derive_key("api", 0, None, &get, "/x", Some("q=1"), &[]);
    // Route.
    assert_ne!(
        base,
        derive_key("other", 0, None, &get, "/x", Some("q=1"), &[])
    );
    // Epoch (the purge/config invalidation dimension).
    assert_ne!(
        base,
        derive_key("api", 1, None, &get, "/x", Some("q=1"), &[])
    );
    // Method (DP-04: HEAD and GET are distinct representations).
    assert_ne!(
        base,
        derive_key("api", 0, None, &Method::HEAD, "/x", Some("q=1"), &[]),
        "HEAD and GET must key independently"
    );
    // Consumer (the DW-029 masking isolation dimension).
    let a = derive_key("api", 0, Some(&identity("a")), &get, "/x", Some("q=1"), &[]);
    let b = derive_key("api", 0, Some(&identity("b")), &get, "/x", Some("q=1"), &[]);
    assert_ne!(a, b);
    assert_ne!(a, base, "authenticated and anonymous never share");
    // Path and query.
    assert_ne!(
        base,
        derive_key("api", 0, None, &get, "/y", Some("q=1"), &[])
    );
    assert_ne!(
        base,
        derive_key("api", 0, None, &get, "/x", Some("q=2"), &[])
    );
    assert_ne!(base, derive_key("api", 0, None, &get, "/x", None, &[]));
    // Vary values (different values; different SETS with empty values).
    let vary_a = vec![("x-tenant".to_string(), "a".to_string())];
    let vary_b = vec![("x-tenant".to_string(), "b".to_string())];
    assert_ne!(
        derive_key("api", 0, None, &get, "/x", None, &vary_a),
        derive_key("api", 0, None, &get, "/x", None, &vary_b)
    );
    assert_ne!(
        derive_key("api", 0, None, &get, "/x", None, &vary_a),
        derive_key("api", 0, None, &get, "/x", None, &[])
    );
    // Determinism: same inputs, same key.
    assert_eq!(
        base,
        derive_key("api", 0, None, &get, "/x", Some("q=1"), &[])
    );
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

#[test]
fn envelope_v2_carries_freshness_and_stale_if_error() {
    let mut e = entry();
    e.freshness_ttl_ms = 60_000;
    e.stale_if_error_ms = 30_000;
    let bytes = e.encode();
    // The version byte is v2.
    assert_eq!(bytes[ENVELOPE_VERSION_INDEX], 2);
    let back = EntryEnvelope::decode(&bytes).expect("v2 envelope decodes");
    assert_eq!(back.freshness_ttl_ms, 60_000);
    assert_eq!(back.stale_if_error_ms, 30_000);
    assert_eq!(back, e);
}

#[test]
fn cache_control_parser_handles_directives() {
    // All directives in one header value (the common shape); the
    // parser also folds multiple Cache-Control headers, but the
    // `headers()` helper inserts (overwrites), so multi-value folding
    // is exercised by the parse path itself, not the helper.
    let h = headers(&[(
        "cache-control",
        "public, max-age=30, s-maxage=120, stale-if-error=600",
    )]);
    let cc = CacheControl::parse(&h);
    assert!(!cc.no_store);
    assert!(!cc.private);
    assert!(!cc.no_cache);
    assert!(!cc.must_revalidate);
    assert_eq!(cc.max_age, Some(30));
    assert_eq!(cc.s_maxage, Some(120));
    assert_eq!(cc.stale_if_error, Some(600));
    // s-maxage wins over max-age for a shared cache.
    assert_eq!(cc.effective_max_age(), Some(120));

    // The storage vetoes.
    for cc_value in ["no-store", "private", "no-cache"] {
        let cc = CacheControl::parse(&headers(&[("cache-control", cc_value)]));
        assert!(
            cc.no_store || cc.private || cc.no_cache,
            "{cc_value} parsed"
        );
    }
    // must-revalidate is captured.
    let cc = CacheControl::parse(&headers(&[(
        "cache-control",
        "max-age=10, must-revalidate",
    )]));
    assert!(cc.must_revalidate);
    assert_eq!(cc.effective_max_age(), Some(10));

    // Absent header: empty (the caller falls back to the policy).
    let cc = CacheControl::parse(&hyper::HeaderMap::new());
    assert_eq!(cc, CacheControl::default());

    // A malformed delta-seconds is treated as absent, not a failure.
    let cc = CacheControl::parse(&headers(&[("cache-control", "max-age=abc")]));
    assert_eq!(cc.max_age, None);

    // Case-insensitive directive names.
    let cc = CacheControl::parse(&headers(&[("cache-control", "MAX-AGE=5, No-Store")]));
    assert_eq!(cc.max_age, Some(5));
    assert!(cc.no_store);

    // Multiple Cache-Control headers are folded (the helper inserts, so
    // build the HeaderMap by hand here to exercise get_all).
    let mut multi = hyper::HeaderMap::new();
    multi.append(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("max-age=30"),
    );
    multi.append(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("stale-if-error=600"),
    );
    let cc = CacheControl::parse(&multi);
    assert_eq!(cc.max_age, Some(30));
    assert_eq!(cc.stale_if_error, Some(600));
}

#[test]
fn store_veto_still_passes_max_age() {
    let p = policy(&["x-tenant"]);
    // max-age alone is NOT a veto (it is a freshness directive, DP-04
    // honors it as the TTL rather than rejecting storage).
    assert_eq!(
        store_veto(&headers(&[("cache-control", "max-age=5, s-maxage=10")]), &p),
        None
    );
    assert_eq!(
        store_veto(&headers(&[("cache-control", "stale-if-error=30")]), &p),
        None
    );
}

#[test]
fn store_veto_must_revalidate_is_not_a_storage_veto() {
    // DP-04: must-revalidate is a freshness directive, not a storage
    // veto (only no-store / private / no-cache forbid storage). The
    // entry stores; must-revalidate's effect is to zero the
    // stale-if-error window and block stale-while-revalidate serving
    // (exercised end-to-end in caching.rs).
    let p = policy(&["x-tenant"]);
    assert_eq!(
        store_veto(
            &headers(&[("cache-control", "max-age=10, must-revalidate")]),
            &p
        ),
        None,
        "must-revalidate alone does not veto storage"
    );
    assert_eq!(
        store_veto(&headers(&[("cache-control", "must-revalidate")]), &p),
        None,
    );
}

#[test]
fn envelope_v1_decodes_with_zeroed_freshness_fields() {
    // DP-04 back-compat: a v1 envelope (no freshness_ttl_ms /
    // stale_if_error_ms fields) decodes with both fields zeroed so the
    // configured policy applies. Simulate a v1 frame by stripping the
    // 16 v2 bytes (two u64s after the status) from a v2 encoding and
    // downgrading the version byte.
    let e = entry();
    let v2 = e.encode();
    assert_eq!(v2[ENVELOPE_VERSION_INDEX], 2);
    // Layout: magic[0..4], version[4], epoch[5..13], stored_at[13..21],
    // status[21..23], freshness_ttl_ms[23..31], stale_if_error_ms
    // [31..39], header_count[39..43], ...
    let mut v1 = Vec::with_capacity(v2.len() - 16);
    v1.extend_from_slice(&v2[..23]);
    v1[ENVELOPE_VERSION_INDEX] = 1;
    v1.extend_from_slice(&v2[39..]);
    let back = EntryEnvelope::decode(&v1).expect("v1 envelope decodes");
    assert_eq!(back.epoch, e.epoch);
    assert_eq!(back.status, e.status);
    assert_eq!(back.body, e.body);
    assert_eq!(
        back.freshness_ttl_ms, 0,
        "v1 has no freshness field; the policy applies"
    );
    assert_eq!(
        back.stale_if_error_ms, 0,
        "v1 has no stale-if-error field; the policy applies"
    );
}

#[test]
fn cache_control_parser_edge_cases() {
    // A directive with no argument yields None (not a parse failure).
    let cc = CacheControl::parse(&headers(&[("cache-control", "s-maxage")]));
    assert_eq!(cc.s_maxage, None);
    let cc = CacheControl::parse(&headers(&[("cache-control", "stale-if-error")]));
    assert_eq!(cc.stale_if_error, None);

    // A quoted delta-seconds (non-numeric after trim) is treated as
    // absent: delta-seconds is an unquoted token (RFC 7234 section
    // 1.2.1), so a quoted value is malformed and the directive reads
    // as unset rather than failing the whole header.
    let cc = CacheControl::parse(&headers(&[("cache-control", "max-age=\"30\"")]));
    assert_eq!(cc.max_age, None);

    // Whitespace around the `=` is tolerated.
    let cc = CacheControl::parse(&headers(&[("cache-control", "max-age = 30")]));
    assert_eq!(cc.max_age, Some(30));

    // A repeated directive uses the last occurrence's argument (the
    // parser overwrites per directive, matching common cache behavior).
    let cc = CacheControl::parse(&headers(&[("cache-control", "max-age=5, max-age=30")]));
    assert_eq!(cc.max_age, Some(30));

    // Unknown directives are ignored (forward-compat) and do not block
    // the known ones in the same header.
    let cc = CacheControl::parse(&headers(&[(
        "cache-control",
        "stale-while-revalidate=60, max-age=10, foo=bar",
    )]));
    assert_eq!(cc.max_age, Some(10));
    assert_eq!(cc.stale_if_error, None);

    // effective_max_age falls back to max-age when s-maxage is absent.
    let cc = CacheControl::parse(&headers(&[("cache-control", "max-age=45")]));
    assert_eq!(cc.s_maxage, None);
    assert_eq!(cc.effective_max_age(), Some(45));

    // An empty / whitespace-only header yields an empty CacheControl.
    let cc = CacheControl::parse(&headers(&[("cache-control", "  ,  ")]));
    assert_eq!(cc, CacheControl::default());
}
