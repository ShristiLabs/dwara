//! Integration tests for the config compile pipeline (DW-005): validation
//! rules, route matching semantics, content hash, publish atomicity and
//! generation monotonicity. Complements the in-module unit tests in
//! `src/snapshot.rs`, which cover the happy path and the basic
//! rollback case.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dwara_core::config::{
    Credential, Endpoint, Gateway, Listener, ListenerProtocol, ListenerTls, LoadBalancer,
    NameValueMatch, PathMatch, PathMatchKind, PathRewrite, Policy, RateLimit, Route, RouteAction,
    RouteMatch, Service, TlsMode, Upstream, UpstreamProtocol,
};
use dwara_core::snapshot::{compile, validate, CompileError, ConfigState};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn listener(name: &str, address: &str, port: u16) -> Listener {
    Listener {
        name: name.into(),
        address: address.into(),
        port,
        protocol: ListenerProtocol::Http,
        tls: None,
    }
}

fn proxy_route(name: &str, kind: PathMatchKind, value: &str) -> Route {
    Route {
        name: name.into(),
        service: "svc".into(),
        r#match: RouteMatch {
            path: PathMatch {
                kind,
                value: value.into(),
            },
            host: None,
            methods: vec![],
            headers: Default::default(),
            query: vec![],
            cookies: vec![],
        },
        action: RouteAction::Proxy { rewrite: None },
        policies: vec![],
    }
}

fn service(name: &str, upstream: &str) -> Service {
    Service {
        name: name.into(),
        upstream: upstream.into(),
        base_path: None,
        version: None,
        policies: vec![],
    }
}

fn upstream(name: &str) -> Upstream {
    Upstream {
        name: name.into(),
        load_balancer: LoadBalancer::RoundRobin,
        protocol: UpstreamProtocol::Http1,
        endpoints: vec![Endpoint {
            address: "127.0.0.1".into(),
            port: 9001,
            weight: 1,
        }],
        connection_cap: None,
        slow_start_ms: None,
        health: None,
        active_health: None,
        retries: None,
        timeouts: None,
    }
}

/// Smallest fully valid gateway: one listener, one proxy route, one service,
/// one upstream.
fn base_gateway() -> Gateway {
    Gateway {
        trusted_proxies: vec![],
        listeners: vec![listener("l", "0.0.0.0", 8080)],
        routes: vec![proxy_route("r", PathMatchKind::Exact, "/x")],
        services: vec![service("svc", "pool")],
        upstreams: vec![upstream("pool")],
        consumers: vec![],
        policies: vec![],
    }
}

/// Assert `gw` fails validation with exactly one issue naming the given
/// entity, name and field.
fn assert_single_issue(gw: &Gateway, entity: &str, name: &str, field: &str) {
    let issues = validate(gw);
    assert_eq!(
        issues.len(),
        1,
        "expected exactly one issue, got: {issues:?}"
    );
    let i = &issues[0];
    assert_eq!(i.entity, entity, "issue entity: {i}");
    assert_eq!(i.name, name, "issue name: {i}");
    assert_eq!(i.field, field, "issue field: {i}");
}

// ---------------------------------------------------------------------------
// 1. Validation rules, one per test
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_duplicate_listener_name() {
    let mut gw = base_gateway();
    gw.listeners.push(listener("l", "127.0.0.1", 9090));
    assert_single_issue(&gw, "listener", "l", "name");
}

#[test]
fn validation_rejects_duplicate_route_name() {
    let mut gw = base_gateway();
    gw.routes
        .push(proxy_route("r", PathMatchKind::Exact, "/other"));
    assert_single_issue(&gw, "route", "r", "name");
}

#[test]
fn validation_rejects_duplicate_service_name() {
    let mut gw = base_gateway();
    gw.services.push(service("svc", "pool"));
    assert_single_issue(&gw, "service", "svc", "name");
}

#[test]
fn validation_rejects_duplicate_upstream_name() {
    let mut gw = base_gateway();
    gw.upstreams.push(upstream("pool"));
    assert_single_issue(&gw, "upstream", "pool", "name");
}

#[test]
fn validation_rejects_duplicate_consumer_name() {
    let mut gw = base_gateway();
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![],
        policies: vec![],
    });
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![],
        policies: vec![],
    });
    assert_single_issue(&gw, "consumer", "c", "name");
}

#[test]
fn validation_rejects_duplicate_policy_name() {
    let mut gw = base_gateway();
    gw.policies.push(dwara_core::config::Policy {
        name: "p".into(),
        rate_limit: None,
        timeouts: None,
    });
    gw.policies.push(dwara_core::config::Policy {
        name: "p".into(),
        rate_limit: None,
        timeouts: None,
    });
    assert_single_issue(&gw, "policy", "p", "name");
}

#[test]
fn validation_rejects_listener_bind_conflict_same_address_and_port() {
    let mut gw = base_gateway();
    gw.listeners.push(listener("l2", "0.0.0.0", 8080));
    assert_single_issue(&gw, "listener", "l2", "port");
}

#[test]
fn validation_allows_same_port_on_distinct_addresses() {
    let mut gw = base_gateway();
    gw.listeners.push(listener("l2", "127.0.0.1", 8080));
    assert!(validate(&gw).is_empty(), "distinct addr, same port is fine");
}

#[test]
fn validation_rejects_dangling_route_service_reference() {
    let mut gw = base_gateway();
    gw.routes[0].service = "ghost".into();
    assert_single_issue(&gw, "route", "r", "service");
}

#[test]
fn validation_rejects_dangling_service_upstream_reference() {
    let mut gw = base_gateway();
    gw.services[0].upstream = "ghost".into();
    assert_single_issue(&gw, "service", "svc", "upstream");
}

#[test]
fn validation_rejects_dangling_service_policy_reference() {
    let mut gw = base_gateway();
    gw.services[0].policies.push("ghost".into());
    assert_single_issue(&gw, "service", "svc", "policies");
}

#[test]
fn validation_rejects_dangling_route_policy_reference() {
    let mut gw = base_gateway();
    gw.routes[0].policies.push("ghost".into());
    assert_single_issue(&gw, "route", "r", "policies");
}

#[test]
fn validation_rejects_path_not_starting_with_slash() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.path.value = "no-slash".into();
    assert_single_issue(&gw, "route", "r", "match.path.value");
}

#[test]
fn validation_rejects_redirect_status_200() {
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Redirect {
        scheme: None,
        host: None,
        path: None,
        status: 200,
    };
    assert_single_issue(&gw, "route", "r", "action.status");
}

#[test]
fn validation_accepts_redirect_status_3xx() {
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Redirect {
        scheme: None,
        host: None,
        path: None,
        status: 308,
    };
    assert!(validate(&gw).is_empty());
}

#[test]
fn validation_rejects_respond_status_999() {
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Respond {
        status: 999,
        body: None,
        headers: Default::default(),
    };
    assert_single_issue(&gw, "route", "r", "action.status");
}

#[test]
fn validation_rejects_respond_status_0() {
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Respond {
        status: 0,
        body: None,
        headers: Default::default(),
    };
    assert_single_issue(&gw, "route", "r", "action.status");
}

#[test]
fn validation_rejects_upstream_with_zero_endpoints() {
    let mut gw = base_gateway();
    gw.upstreams[0].endpoints.clear();
    assert_single_issue(&gw, "upstream", "pool", "endpoints");
}

#[test]
fn validation_rejects_endpoint_weight_zero() {
    let mut gw = base_gateway();
    gw.upstreams[0].endpoints[0].weight = 0;
    assert_single_issue(&gw, "upstream", "pool", "endpoints[0].weight");
}

#[test]
fn validation_rejects_empty_api_key_credential() {
    let mut gw = base_gateway();
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![Credential::ApiKey { key: String::new() }],
        policies: vec![],
    });
    assert_single_issue(&gw, "consumer", "c", "credentials[0]");
}

#[test]
fn validation_rejects_empty_jwt_issuer() {
    let mut gw = base_gateway();
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![Credential::Jwt {
            issuer: String::new(),
            audiences: vec![],
        }],
        policies: vec![],
    });
    assert_single_issue(&gw, "consumer", "c", "credentials[0]");
}

#[test]
fn validation_rejects_empty_mtls_fingerprint() {
    let mut gw = base_gateway();
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![Credential::Mtls {
            fingerprint: String::new(),
        }],
        policies: vec![],
    });
    assert_single_issue(&gw, "consumer", "c", "credentials[0]");
}

#[test]
fn validation_rejects_dangling_consumer_policy_reference() {
    let mut gw = base_gateway();
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![],
        policies: vec!["ghost".into()],
    });
    assert_single_issue(&gw, "consumer", "c", "policies");
}

// ---------------------------------------------------------------------------
// 2. Multi-issue accumulation (never fail-fast)
// ---------------------------------------------------------------------------

#[test]
fn validation_accumulates_multiple_distinct_issues() {
    let mut gw = base_gateway();
    gw.routes[0].service = "ghost-svc".into(); // dangling route ref
    gw.services[0].upstream = "ghost-pool".into(); // dangling service ref
    gw.upstreams[0].endpoints.clear(); // empty upstream
    gw.routes[0].r#match.path.value = "bad".into(); // path without /
    let issues = validate(&gw);
    assert!(
        issues.len() >= 4,
        "all four problems must be reported, got {issues:?}"
    );
    let keys: HashSet<_> = issues
        .iter()
        .map(|i| (i.entity.clone(), i.field.clone()))
        .collect();
    assert!(keys.contains(&("route".into(), "service".into())));
    assert!(keys.contains(&("service".into(), "upstream".into())));
    assert!(keys.contains(&("upstream".into(), "endpoints".into())));
    assert!(keys.contains(&("route".into(), "match.path.value".into())));
}

// ---------------------------------------------------------------------------
// 3. Compile matching semantics
// ---------------------------------------------------------------------------

/// Gateway with one exact, one regex, and one prefix route that ALL match
/// "/all/kinds" — precedence must pick the exact route.
fn precedence_gateway() -> Gateway {
    let mut gw = base_gateway();
    gw.routes = vec![
        proxy_route("the-exact", PathMatchKind::Exact, "/all/kinds"),
        proxy_route("the-regex", PathMatchKind::Regex, r"/all/.*"),
        proxy_route("the-prefix", PathMatchKind::Prefix, "/all"),
    ]
    .into_iter()
    .map(|mut r| {
        r.service = "svc".into();
        r
    })
    .collect();
    gw
}

#[test]
fn compile_exact_beats_regex_beats_prefix() {
    let gw = precedence_gateway();
    let compiled = compile(&gw).expect("valid config compiles");
    let snap = publish_once(&gw);
    assert_eq!(
        snap.match_route("/all/kinds").map(|r| r.name.as_str()),
        Some("the-exact"),
        "exact match must win over regex and prefix"
    );

    // Regex beats prefix: "/all/other" matches regex and prefix but not exact.
    assert_eq!(
        snap.match_route("/all/other").map(|r| r.name.as_str()),
        Some("the-regex")
    );
    // Route order in the compiled gateway is preserved for index lookup.
    assert_eq!(compiled.gateway().routes[0].name, "the-exact");
}

#[test]
fn compile_exact_template_captures_path_parameter() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.path.value = "/users/{id}".into();
    let snap = publish_once(&gw);
    assert!(
        snap.match_route("/users/42").is_some(),
        "path parameter must match a concrete segment"
    );
    assert!(
        snap.match_route("/users/42/posts").is_none(),
        "exact template must not match beyond the template"
    );
}

#[test]
fn compile_regex_first_declared_wins_on_multi_match() {
    let mut gw = base_gateway();
    gw.routes = vec![
        proxy_route("first", PathMatchKind::Regex, r"/m/(foo|bar)"),
        proxy_route("second", PathMatchKind::Regex, r"/m/foo"),
    ];
    let snap = publish_once(&gw);
    assert_eq!(
        snap.match_route("/m/foo").map(|r| r.name.as_str()),
        Some("first"),
        "first-declared regex pattern must win when several match"
    );
}

#[test]
fn compile_prefix_longest_wins() {
    let mut gw = base_gateway();
    gw.routes = vec![
        proxy_route("short", PathMatchKind::Prefix, "/api"),
        proxy_route("long", PathMatchKind::Prefix, "/api/v1"),
    ];
    let snap = publish_once(&gw);
    assert_eq!(
        snap.match_route("/api/v1/users").map(|r| r.name.as_str()),
        Some("long"),
        "longest matching prefix must win"
    );
    assert_eq!(
        snap.match_route("/api/other").map(|r| r.name.as_str()),
        Some("short")
    );
}

#[test]
fn compile_non_matching_path_resolves_to_no_route() {
    let snap = publish_once(&base_gateway());
    assert!(snap.match_route("/definitely/not/routed").is_none());
}

// ---------------------------------------------------------------------------
// 4. Compile errors
// ---------------------------------------------------------------------------

#[test]
fn compile_rejects_broken_regex_with_valid_leading_slash() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.path.kind = PathMatchKind::Regex;
    gw.routes[0].r#match.path.value = "/[unclosed".into();
    match compile(&gw) {
        Err(CompileError::InvalidRegex { route, pattern, .. }) => {
            assert_eq!(route, "r");
            assert_eq!(pattern, "/[unclosed");
        }
        other => panic!("expected InvalidRegex, got {other:?}"),
    }
}

#[test]
fn compile_rejects_conflicting_exact_templates() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.path.value = "/x/{id}".into();
    gw.routes
        .push(proxy_route("r2", PathMatchKind::Exact, "/x/{other}"));
    match compile(&gw) {
        Err(CompileError::RouteConflict { route, pattern, .. }) => {
            assert_eq!(route, "r2");
            assert_eq!(pattern, "/x/{other}");
        }
        other => panic!("expected RouteConflict, got {other:?}"),
    }
}

#[test]
fn compile_reports_no_issues_for_valid_gateway() {
    assert!(compile(&base_gateway()).is_ok());
}

// ---------------------------------------------------------------------------
// 5. Publish atomicity + generations
// ---------------------------------------------------------------------------

fn publish_once(gw: &Gateway) -> Arc<dwara_core::snapshot::Snapshot> {
    let state = ConfigState::new();
    state
        .compile_and_publish(gw)
        .expect("valid config publishes");
    state.snapshot()
}

#[test]
fn publish_first_valid_config_is_generation_1_with_matching_info() {
    let state = ConfigState::new();
    let gw = base_gateway();
    let compiled = compile(&gw).unwrap();
    let info = state.compile_and_publish(&gw).unwrap();
    assert_eq!(info.generation, 1);
    assert_eq!(info.content_hash, compiled.content_hash());
    assert_eq!(info.route_count, 1);
    let snap = state.snapshot();
    assert_eq!(snap.generation(), 1);
    assert_eq!(snap.content_hash(), info.content_hash);
}

#[test]
fn publish_failure_keeps_old_snapshot_and_does_not_advance_generation() {
    let state = ConfigState::new();
    state.compile_and_publish(&base_gateway()).unwrap();
    let old = state.snapshot();

    let mut bad = base_gateway();
    bad.upstreams[0].endpoints.clear(); // invalid: no endpoints
    assert!(state.compile_and_publish(&bad).is_err());

    let after = state.snapshot();
    assert_eq!(
        after.generation(),
        1,
        "failed publish must not advance the generation"
    );
    assert_eq!(
        after.content_hash(),
        old.content_hash(),
        "failed publish must keep the old content"
    );
}

#[test]
fn publish_generations_are_gap_free_after_failures() {
    let state = ConfigState::new();
    let mut bad = base_gateway();
    bad.routes[0].service = "ghost".into();
    for _ in 0..3 {
        assert!(state.compile_and_publish(&bad).is_err());
    }
    let info = state.compile_and_publish(&base_gateway()).unwrap();
    assert_eq!(info.generation, 1, "failures must not consume generations");
    let info2 = state.compile_and_publish(&base_gateway()).unwrap();
    assert_eq!(info2.generation, 2);
}

#[test]
fn publish_concurrent_mixed_configs_final_generation_equals_successes() {
    const THREADS: usize = 8;
    let state = Arc::new(ConfigState::new());
    let mut handles = Vec::new();
    for i in 0..THREADS {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || {
            let gw = if i % 2 == 0 {
                // valid; distinct content so hashes differ
                let mut g = base_gateway();
                g.routes[0].r#match.path.value = format!("/x/{i}");
                g
            } else {
                let mut g = base_gateway();
                g.services[0].upstream = "ghost".into(); // invalid
                g
            };
            state
                .compile_and_publish(&gw)
                .ok()
                .map(|info| info.generation)
        }));
    }
    let mut generations: Vec<u64> = handles
        .into_iter()
        .filter_map(|h| h.join().expect("thread must not panic"))
        .collect();
    generations.sort_unstable();
    let successes = generations.len();
    assert_eq!(
        successes,
        THREADS / 2,
        "even threads publish, odd threads fail"
    );
    let expected: Vec<u64> = (1..=successes as u64).collect();
    assert_eq!(generations, expected, "gap-free, no duplicate generations");
    let snap = state.snapshot();
    assert_eq!(snap.generation(), successes as u64);
    assert_eq!(snap.gateway().routes.len(), 1);
    // Final snapshot content is whichever successful publisher won the race:
    // any of the four valid routes is an acceptable final winner.
    let final_route_is_a_winner = (0..THREADS)
        .step_by(2)
        .any(|i| snap.match_route(&format!("/x/{i}")).is_some());
    assert!(final_route_is_a_winner);
}

#[test]
fn publish_snapshot_reads_are_never_torn_during_concurrent_publishes() {
    const THREADS: usize = 8;
    let state = Arc::new(ConfigState::new());
    let reader = Arc::clone(&state);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_r = Arc::clone(&stop);
    // Ordered samples so invariants can be asserted over the reader's
    // actual observation window (from its FIRST sample onward).
    let samples: Arc<std::sync::Mutex<Vec<(u64, u64)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let reader_samples = Arc::clone(&samples);
    let reader = std::thread::spawn(move || {
        while !stop_r.load(std::sync::atomic::Ordering::Relaxed) {
            let snap = reader.snapshot();
            // Torn state would pair a generation with a foreign hash; the
            // recorded (generation, hash) pairs are checked for
            // self-consistency below.
            reader_samples
                .lock()
                .expect("samples lock")
                .push((snap.generation(), snap.content_hash()));
            std::thread::yield_now();
        }
    });
    // Determinism: wait (bounded) until the reader has recorded at least one
    // sample BEFORE any publisher runs, so the observation window is
    // guaranteed to start at generation 0 without relying on scheduler
    // timing. Bounded wait, not sleep-as-synchronization: publishers only
    // start after the first sample exists or the 2s budget expires (in
    // which case the first-recorded-sample assertions below still hold).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while samples.lock().expect("samples lock").is_empty() && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(
        !samples.lock().expect("samples lock").is_empty(),
        "reader must record at least one sample within 2s"
    );
    let mut handles = Vec::new();
    for i in 0..THREADS {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || {
            let mut g = base_gateway();
            g.routes[0].r#match.path.value = format!("/v/{i}");
            state.compile_and_publish(&g).map(|_| ())
        }));
    }
    for h in handles {
        h.join().expect("publisher thread must not panic").unwrap();
    }
    // All publishes are done; wait (bounded) until the reader has actually
    // sampled the final generation before signalling stop — otherwise the
    // reader could exit between the last publish and its next sample,
    // turning "final generation observed" into a scheduling assumption.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while samples
        .lock()
        .expect("samples lock")
        .iter()
        .map(|&(g, _)| g)
        .max()
        != Some(THREADS as u64)
        && std::time::Instant::now() < deadline
    {
        std::thread::yield_now();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    reader.join().expect("reader must not panic");
    let samples = Arc::try_unwrap(samples)
        .expect("sole samples ref")
        .into_inner()
        .expect("samples lock");
    // Invariants hold from the reader's FIRST recorded sample onward; the
    // bounded wait above guarantees that sample is generation 0, but the
    // assertions below never depend on that scheduling fact.
    let first = samples[0];
    assert_eq!(
        first,
        (0, 0),
        "first recorded sample is generation 0 (empty)"
    );
    // Generations only move forward: no earlier generation after a later
    // one was observed.
    let mut max_gen = first.0;
    for &(g, _) in &samples[1..] {
        assert!(g >= max_gen, "generation must be non-decreasing");
        max_gen = g;
    }
    // Each generation must map to exactly one hash (no torn pair
    // observed). Repeated identical samples are fine.
    let mut hash_by_gen: HashMap<u64, u64> = HashMap::new();
    for &(g, h) in &samples {
        if let Some(prev) = hash_by_gen.insert(g, h) {
            assert_eq!(
                prev, h,
                "generation {g} observed with two different hashes (torn read)"
            );
        }
    }
    assert_eq!(max_gen, THREADS as u64, "final generation must be observed");
}

// ---------------------------------------------------------------------------
// 6. Content hash
// ---------------------------------------------------------------------------

#[test]
fn content_hash_is_stable_for_identical_gateway() {
    let a = compile(&base_gateway()).unwrap();
    let b = compile(&base_gateway()).unwrap();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn content_hash_differs_for_semantically_different_gateway() {
    let a = compile(&base_gateway()).unwrap();
    let mut gw = base_gateway();
    gw.routes[0].r#match.path.value = "/changed".into();
    let b = compile(&gw).unwrap();
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn content_hash_is_stable_across_yaml_key_order() {
    // Same document with top-level mapping keys in a different order must
    // normalize to the same typed value and therefore the same hash.
    let yaml_a = "listeners:\n  - name: l\n    address: 0.0.0.0\n    port: 8080\nroutes:\n  - name: r\n    service: svc\n    match:\n      path:\n        type: exact\n        value: /x\n    action:\n      type: proxy\nservices:\n  - name: svc\n    upstream: pool\nupstreams:\n  - name: pool\n    endpoints:\n      - address: 127.0.0.1\n        port: 9001\n";
    let yaml_b = "upstreams:\n  - name: pool\n    endpoints:\n      - address: 127.0.0.1\n        port: 9001\nservices:\n  - name: svc\n    upstream: pool\nroutes:\n  - name: r\n    service: svc\n    match:\n      path:\n        type: exact\n        value: /x\n    action:\n      type: proxy\nlisteners:\n  - name: l\n    address: 0.0.0.0\n    port: 8080\n";
    let a = dwara_core::config::parse_gateway(yaml_a).expect("yaml_a parses");
    let b = dwara_core::config::parse_gateway(yaml_b).expect("yaml_b parses");
    assert!(validate(&a).is_empty() && validate(&b).is_empty());
    let ha = compile(&a).unwrap().content_hash();
    let hb = compile(&b).unwrap().content_hash();
    assert_eq!(
        ha, hb,
        "hash must be computed over normalized content, not source key order"
    );
}

// ---------------------------------------------------------------------------
// 7. Cold start
// ---------------------------------------------------------------------------

#[test]
fn cold_start_serves_empty_generation_zero_snapshot() {
    let state = ConfigState::new();
    let snap = state.snapshot();
    assert_eq!(snap.generation(), 0);
    assert_eq!(snap.content_hash(), 0);
    assert!(snap.gateway().listeners.is_empty());
    assert!(snap.gateway().routes.is_empty());
    assert!(snap.gateway().services.is_empty());
    assert!(snap.gateway().upstreams.is_empty());
    assert!(snap.match_route("/anything").is_none());
}

// ---------------------------------------------------------------------------
// 8. Listener protocol/TLS validation
// ---------------------------------------------------------------------------

fn https_gateway(tls: Option<ListenerTls>) -> Gateway {
    let mut gw = base_gateway();
    gw.listeners[0].protocol = ListenerProtocol::Https;
    gw.listeners[0].tls = tls;
    gw
}

#[test]
fn validation_rejects_https_listener_without_tls_block() {
    let gw = https_gateway(None);
    assert_single_issue(&gw, "listener", "l", "tls");
}

#[test]
fn validation_rejects_terminate_without_cert_file() {
    let gw = https_gateway(Some(ListenerTls {
        mode: TlsMode::Terminate,
        cert_file: None,
        key_file: Some("/etc/certs/key.pem".into()),
        certificates: vec![],
        sni_routes: vec![],
    }));
    assert_single_issue(&gw, "listener", "l", "tls.cert_file");
}

#[test]
fn validation_rejects_terminate_without_key_file() {
    let gw = https_gateway(Some(ListenerTls {
        mode: TlsMode::Terminate,
        cert_file: Some("/etc/certs/cert.pem".into()),
        key_file: None,
        certificates: vec![],
        sni_routes: vec![],
    }));
    assert_single_issue(&gw, "listener", "l", "tls.key_file");
}

#[test]
fn validation_accepts_terminate_with_cert_and_key() {
    let gw = https_gateway(Some(ListenerTls {
        mode: TlsMode::Terminate,
        cert_file: Some("/etc/certs/cert.pem".into()),
        key_file: Some("/etc/certs/key.pem".into()),
        certificates: vec![],
        sni_routes: vec![],
    }));
    assert!(validate(&gw).is_empty());
}

#[test]
fn validation_accepts_passthrough_without_cert_or_key() {
    let gw = https_gateway(Some(ListenerTls {
        mode: TlsMode::Passthrough,
        cert_file: None,
        key_file: None,
        certificates: vec![],
        sni_routes: vec![],
    }));
    assert!(validate(&gw).is_empty());
}

#[test]
fn validation_rejects_passthrough_with_cert_and_key() {
    let gw = https_gateway(Some(ListenerTls {
        mode: TlsMode::Passthrough,
        cert_file: Some("/etc/certs/cert.pem".into()),
        key_file: Some("/etc/certs/key.pem".into()),
        certificates: vec![],
        sni_routes: vec![],
    }));
    assert_single_issue(&gw, "listener", "l", "tls");
}

#[test]
fn validation_rejects_http_listener_with_tls_block() {
    let mut gw = base_gateway();
    gw.listeners[0].tls = Some(ListenerTls {
        mode: TlsMode::Terminate,
        cert_file: Some("/etc/certs/cert.pem".into()),
        key_file: Some("/etc/certs/key.pem".into()),
        certificates: vec![],
        sni_routes: vec![],
    });
    assert_single_issue(&gw, "listener", "l", "tls");
}

// ---------------------------------------------------------------------------
// 9. Policy rate-limit validation
// ---------------------------------------------------------------------------

fn policy_gateway(rl: RateLimit) -> Gateway {
    let mut gw = base_gateway();
    gw.policies.push(Policy {
        name: "p".into(),
        rate_limit: Some(rl),
        timeouts: None,
    });
    gw
}

#[test]
fn validation_rejects_rate_limit_with_zero_requests() {
    let gw = policy_gateway(RateLimit {
        requests: 0,
        window_seconds: 60,
    });
    assert_single_issue(&gw, "policy", "p", "rate_limit.requests");
}

#[test]
fn validation_rejects_rate_limit_with_zero_window() {
    let gw = policy_gateway(RateLimit {
        requests: 100,
        window_seconds: 0,
    });
    assert_single_issue(&gw, "policy", "p", "rate_limit.window_seconds");
}

#[test]
fn validation_accepts_rate_limit_with_positive_requests_and_window() {
    let gw = policy_gateway(RateLimit {
        requests: 100,
        window_seconds: 60,
    });
    assert!(validate(&gw).is_empty());
}

// ---------------------------------------------------------------------------
// 10. Catch-all prefix validation
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_root_prefix_as_catch_all() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.path.kind = PathMatchKind::Prefix;
    gw.routes[0].r#match.path.value = "/".into();
    let issues = validate(&gw);
    assert_eq!(issues.len(), 1, "got: {issues:?}");
    assert_eq!(issues[0].field, "match.path.value");
    assert!(
        issues[0].message.contains("would match every path"),
        "message must say the prefix matches everything: {}",
        issues[0].message
    );
}

#[test]
fn validation_rejects_double_slash_prefix_as_catch_all() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.path.kind = PathMatchKind::Prefix;
    gw.routes[0].r#match.path.value = "//".into();
    let issues = validate(&gw);
    assert_eq!(issues.len(), 1, "got: {issues:?}");
    assert_eq!(issues[0].field, "match.path.value");
    assert!(
        issues[0].message.contains("would match every path"),
        "message must say the prefix matches everything: {}",
        issues[0].message
    );
}

#[test]
fn validation_accepts_explicit_prefixes_with_and_without_trailing_slash() {
    let mut gw = base_gateway();
    gw.routes = vec![
        proxy_route("trailing", PathMatchKind::Prefix, "/api/"),
        proxy_route("plain", PathMatchKind::Prefix, "/api"),
    ];
    assert!(validate(&gw).is_empty());
}

// ---------------------------------------------------------------------------
// 11. Listener and endpoint address/port sanity
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_listener_port_zero() {
    let mut gw = base_gateway();
    gw.listeners[0].port = 0;
    assert_single_issue(&gw, "listener", "l", "port");
}

#[test]
fn validation_rejects_empty_listener_address() {
    let mut gw = base_gateway();
    gw.listeners[0].address = String::new();
    assert_single_issue(&gw, "listener", "l", "address");
}

#[test]
fn validation_rejects_empty_upstream_endpoint_address() {
    let mut gw = base_gateway();
    gw.upstreams[0].endpoints[0].address = String::new();
    assert_single_issue(&gw, "upstream", "pool", "endpoints[0].address");
}

// ---------------------------------------------------------------------------
// 12. DW-010 validation: query/cookie matchers, rewrites, respond headers
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_empty_query_matcher_name() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.query = vec![NameValueMatch {
        name: "  ".into(),
        value: None,
    }];
    assert_single_issue(&gw, "route", "r", "match.query");
}

#[test]
fn validation_rejects_empty_cookie_matcher_name() {
    let mut gw = base_gateway();
    gw.routes[0].r#match.cookies = vec![NameValueMatch {
        name: String::new(),
        value: None,
    }];
    assert_single_issue(&gw, "route", "r", "match.cookies");
}

#[test]
fn validation_rejects_empty_query_matcher_value() {
    // An empty value can never match (raw exact-match semantics); the
    // message steers the operator to presence-only matching.
    let mut gw = base_gateway();
    gw.routes[0].r#match.query = vec![NameValueMatch {
        name: "beta".into(),
        value: Some(String::new()),
    }];
    let issues = validate(&gw);
    assert_eq!(issues.len(), 1, "got: {issues:?}");
    assert_eq!(issues[0].field, "match.query");
    assert!(issues[0].message.contains("omit value"));
}

#[test]
fn validation_rejects_replace_prefix_replacement_without_leading_slash() {
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Proxy {
        rewrite: Some(PathRewrite::ReplacePrefix {
            prefix: "/api".into(),
            replacement: "internal".into(),
        }),
    };
    assert_single_issue(&gw, "route", "r", "action.rewrite.replacement");
}

#[test]
fn validation_rejects_replace_prefix_empty_replacement_as_root() {
    // An EMPTY replacement is explicitly allowed (prefix becomes the root).
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Proxy {
        rewrite: Some(PathRewrite::ReplacePrefix {
            prefix: "/api".into(),
            replacement: String::new(),
        }),
    };
    assert!(validate(&gw).is_empty());
}

#[test]
fn validation_rejects_respond_header_value_with_control_character() {
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Respond {
        status: 200,
        body: None,
        headers: [("x-evil".to_string(), "a\r\nb".to_string())].into(),
    };
    assert_single_issue(&gw, "route", "r", "action.headers");
}

#[test]
fn validation_rejects_rewrite_regex_substitution_without_leading_slash() {
    // TEST EDIT (DW-010 hardening follow-up): this test previously pinned
    // the OLD reality — a free-form substitution passed validation and
    // compiled, and a relative result was silently no-op'd by the
    // dataplane (also pinned by golden case 42, now deleted). The
    // substitution must now start with '/' or a capture reference so it
    // expands to an absolute path.
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Proxy {
        rewrite: Some(PathRewrite::Regex {
            pattern: "^/api/(.*)$".into(),
            substitution: "no-leading-slash/$1".into(),
        }),
    };
    assert_single_issue(&gw, "route", "r", "action.rewrite.substitution");
    match compile(&gw) {
        Err(CompileError::Validation(_)) => {}
        other => panic!("expected Validation rejection, got {other:?}"),
    }
}

#[test]
fn validation_rejects_rewrite_regex_substitution_with_unsafe_characters() {
    // Whitespace, '?', '#', and control characters would corrupt the
    // path/query split or the upstream request line.
    // Each case starts with '/' so ONLY the charset rule fires.
    for bad in ["/ x/$1", "/x?/$1", "/x#/$1", "/x\u{0000}/$1"] {
        let mut gw = base_gateway();
        gw.routes[0].action = RouteAction::Proxy {
            rewrite: Some(PathRewrite::Regex {
                pattern: "^/api/(.*)$".into(),
                substitution: bad.into(),
            }),
        };
        let issues = validate(&gw);
        assert_eq!(
            issues.len(),
            1,
            "substitution '{bad:?}': expected exactly one issue, got: {issues:?}"
        );
        assert_eq!(issues[0].field, "action.rewrite.substitution");
    }
}

#[test]
fn validation_accepts_capture_only_rewrite_regex_substitution() {
    // A substitution that is a pure capture reference ('$1' or '${name}')
    // expands to the captured text; the captured group is a path segment
    // from the inbound URI, so this is the one non-'/' start that is safe.
    for ok in ["$1", "${name}", "/x/$1", "/$1/suffix"] {
        let mut gw = base_gateway();
        gw.routes[0].action = RouteAction::Proxy {
            rewrite: Some(PathRewrite::Regex {
                pattern: "^/api/(.*)$".into(),
                substitution: ok.into(),
            }),
        };
        assert!(validate(&gw).is_empty(), "substitution '{ok}' should pass");
        compile(&gw).unwrap_or_else(|e| panic!("substitution '{ok}' should compile: {e}"));
    }
}

#[test]
fn compile_and_publish_rejects_invalid_rewrite_regex() {
    let mut gw = base_gateway();
    gw.routes[0].action = RouteAction::Proxy {
        rewrite: Some(PathRewrite::Regex {
            pattern: "/bad/(unclosed".into(),
            substitution: "/x/$1".into(),
        }),
    };
    let state = ConfigState::new();
    match state.compile_and_publish(&gw) {
        Err(CompileError::InvalidRegex { route, .. }) => assert_eq!(route, "r"),
        other => panic!("expected InvalidRegex, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 13. DONE-WHEN guard: new rules still gate publishing
// ---------------------------------------------------------------------------

#[test]
fn publish_failure_on_new_rule_violation_keeps_old_snapshot_and_generation() {
    let state = ConfigState::new();
    state.compile_and_publish(&base_gateway()).unwrap();
    let old = state.snapshot();

    // Invalid only under the new rule set: https listener without a tls block.
    let bad = https_gateway(None);
    assert!(
        state.compile_and_publish(&bad).is_err(),
        "config invalid under the new TLS rules must never publish"
    );

    let after = state.snapshot();
    assert_eq!(after.generation(), 1, "generation must be unchanged");
    assert_eq!(
        after.content_hash(),
        old.content_hash(),
        "old snapshot content must be retained"
    );
}
