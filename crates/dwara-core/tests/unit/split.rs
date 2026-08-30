//! Unit tests for DW-040: the weighted split's deterministic pick
//! (stability, boundaries, zero weights, distribution), the cookie
//! reader, the affinity mint, and the config validation matrix. The
//! end-to-end pins (statistical ratios, stickiness across requests
//! and reloads, the blue-green flip) live in `tests/canary.rs`.

use dwara_core::dataplane::split::{mint_affinity_id, read_cookie, ServiceSplit};

// --- helpers --------------------------------------------------------------

fn headers(cookies: &[&str]) -> hyper::HeaderMap {
    let mut h = hyper::HeaderMap::new();
    for c in cookies {
        h.append(hyper::header::COOKIE, c.parse().unwrap());
    }
    h
}

/// A split over (name, weight) pairs — the handle is a dummy Arc over
/// a name-only construction path... the public API needs real
/// handles, so the pure pick is exercised through the registry-free
/// constructor in dwara-core's own tests; HERE we pin the observable
/// behavior end to end in tests/canary.rs and the pure grammar below.
fn validate_yaml(services: &str) -> Vec<String> {
    let yaml = format!(
        "{services}routes:\n\
         - name: r\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         upstreams:\n\
         - name: a\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n\
         - name: b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 2\n"
    );
    let gateway = dwara_core::config::parse_gateway(&yaml).unwrap();
    dwara_core::snapshot::validate(&gateway)
        .into_iter()
        .map(|i| format!("{i}"))
        .collect()
}

// --- the cookie reader ------------------------------------------------------

#[test]
fn cookie_reading_takes_the_first_match_across_lines() {
    let h = headers(&[
        "a=1; dwara_affinity=first",
        "other=2; dwara_affinity=second",
    ]);
    assert_eq!(
        read_cookie(&h, "dwara_affinity").as_deref(),
        Some("first"),
        "the first header line wins"
    );
    assert_eq!(read_cookie(&h, "other").as_deref(), Some("2"));
    assert_eq!(read_cookie(&h, "missing"), None);
    // Whitespace-tolerant pairs; an empty value is not a session.
    let h = headers(&[" spaced = v ;  dwara_affinity ="]);
    assert_eq!(read_cookie(&h, "spaced").as_deref(), Some("v"));
    assert_eq!(read_cookie(&h, "dwara_affinity"), None);
}

#[test]
fn affinity_ids_are_unique_and_hex() {
    let a = mint_affinity_id();
    let b = mint_affinity_id();
    assert_ne!(a, b);
    for id in [&a, &b] {
        assert!(
            id.bytes().all(|c| c.is_ascii_hexdigit()),
            "printable hex handle: {id}"
        );
    }
}

// --- validation --------------------------------------------------------------

#[test]
fn a_well_formed_split_and_sticky_service_validates() {
    assert!(validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: a\n\
         \x20     weight: 95\n\
         \x20   - upstream: b\n\
         \x20     weight: 5\n\
         \x20 sticky:\n\
         \x20   cookie: dwara_affinity\n"
    )
    .is_empty());
    // Default weight 1 and default ttl both fine; a 0-weight parked
    // side is legal as long as the total is positive.
    assert!(validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: a\n\
         \x20   - upstream: b\n\
         \x20     weight: 0\n"
    )
    .is_empty());
}

#[test]
fn split_validation_rejects_the_authoring_mistakes() {
    // Both target shapes set.
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 upstream: a\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: a\n\
         \x20   - upstream: b\n",
    );
    assert!(issues.join("\n").contains("both set"));

    // Neither.
    let issues = validate_yaml("services:\n- name: svc\n");
    assert!(issues.join("\n").contains("neither"));

    // One target (that's `upstream`), unknown upstream, duplicate.
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: a\n",
    );
    assert!(issues.join("\n").contains("2..=8"));
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: ghost\n\
         \x20   - upstream: b\n",
    );
    assert!(issues.join("\n").contains("unknown upstream 'ghost'"));
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: a\n\
         \x20   - upstream: a\n",
    );
    assert!(issues.join("\n").contains("duplicate upstream 'a'"));

    // All-zero weights route nowhere.
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: a\n\
         \x20     weight: 0\n\
         \x20   - upstream: b\n\
         \x20     weight: 0\n",
    );
    assert!(issues.join("\n").contains("every weight is 0"));
}

#[test]
fn sticky_validation_rejects_non_token_cookie_names_and_bad_ttls() {
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 upstream: a\n\
         \x20 sticky:\n\
         \x20   cookie: \"bad name;\"\n",
    );
    assert!(issues.join("\n").contains("not a valid cookie name"));
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 upstream: a\n\
         \x20 sticky:\n\
         \x20   cookie: dwara_affinity\n\
         \x20   ttl_s: 0\n",
    );
    assert!(issues.join("\n").contains("ttl_s must be in"));
    let issues = validate_yaml(
        "services:\n\
         - name: svc\n\
         \x20 upstream: a\n\
         \x20 sticky:\n\
         \x20   cookie: dwara_affinity\n\
         \x20   ttl_s: 99999999\n",
    );
    assert!(issues.join("\n").contains("ttl_s must be in"));
}

// --- the pick's grammar (real handles through the public registry) ---------

fn registry() -> dwara_core::dataplane::upstream::UpstreamRegistry {
    let yaml = "allow_empty_routes: true\nupstreams:
- name: a
  endpoints:
  - address: 127.0.0.1
    port: 1
- name: b
  endpoints:
  - address: 127.0.0.1
    port: 2
";
    let gateway = dwara_core::config::parse_gateway(yaml).unwrap();
    let state = dwara_core::snapshot::ConfigState::new();
    state.compile_and_publish(&gateway).expect("publish");
    dwara_core::dataplane::upstream::UpstreamRegistry::from_snapshot(&state.snapshot())
}

#[test]
fn the_pick_is_stable_per_key_respects_zero_weights_and_converges() {
    let reg = registry();
    let a = reg.get("a").unwrap();
    let b = reg.get("b").unwrap();
    let split = ServiceSplit::new(&[(a, 90), (b, 10)]);

    // Stability: the same key always lands on the same branch.
    for key in ["alpha", "beta", "gamma", "d"] {
        let first = split.pick(key).name();
        for _ in 0..50 {
            assert_eq!(split.pick(key).name(), first, "key {key} is stable");
        }
    }
    assert_eq!(split.total_weight(), 100);

    // Distribution: over a wide key set, shares converge on the
    // weights with a margin that cannot invert.
    let mut a_n = 0u32;
    let n = 5_000u32;
    for i in 0..n {
        if split.pick(&format!("key-{i}")).name() == "a" {
            a_n += 1;
        }
    }
    assert!(
        (4_350..=4_650).contains(&a_n),
        "90/10 split over {n} keys: {a_n}"
    );

    // Zero weights never serve: the parked side of blue-green.
    let parked = ServiceSplit::new(&[(reg.get("a").unwrap(), 0), (reg.get("b").unwrap(), 100)]);
    for i in 0..1_000u32 {
        assert_eq!(parked.pick(&format!("k{i}")).name(), "b");
    }
    assert_eq!(parked.weights(), vec![0, 100]);
}

#[test]
fn quoted_and_unusual_cookie_values_hash_consistently() {
    // RFC 6265 permits quoted values; the reader returns them verbatim
    // and the pick only ever hashes — no parsing beyond name=value.
    let h = headers(&["dwara_affinity=\"quoted-session\""]);
    let v = read_cookie(&h, "dwara_affinity").unwrap();
    assert_eq!(v, "\"quoted-session\"");
    // A value full of legal-but-unusual bytes: no panic, stable pick.
    let reg = registry();
    let split = ServiceSplit::new(&[(reg.get("a").unwrap(), 50), (reg.get("b").unwrap(), 50)]);
    let odd = "aGVsbG8.-_~!*'()@#$%&+;=,:/  tab";
    let first = split.pick(odd).name();
    for _ in 0..20 {
        assert_eq!(split.pick(odd).name(), first);
    }
}

#[test]
fn an_oversized_cookie_value_picks_without_panicking() {
    // Header size limits (431 class) bound real inputs before this
    // point; the pick itself must stay linear and panic-free on
    // whatever arrives.
    let reg = registry();
    let split = ServiceSplit::new(&[(reg.get("a").unwrap(), 1), (reg.get("b").unwrap(), 1)]);
    let huge = "x".repeat(16 * 1024);
    let _ = split.pick(&huge).name();
}
