//! DW-024 micro-benchmarks: per-request hot-path primitives.
//!
//! Benchmark IDs are STABLE identifiers — the regression gate
//! (scripts/bench-baseline.py, run by .github/workflows/bench.yml) parses
//! criterion's `--output-format bencher` output keyed on "group/id", so
//! renames here require regenerating benches/baseline.json:
//!
//!     cargo bench --workspace --bench micro -- --output-format bencher \
//!         | scripts/bench-baseline.py --write benches/baseline.json \
//!             --force --machine <label-of-the-machine-that-ran-it>
//!
//! Run `cargo bench --workspace --bench micro` locally for the human-
//! readable report. Absolute numbers are machine-dependent; the gate
//! compares relative change against the checked-in baseline (25% slack).
//!
//! These are dev/bench-only (criterion is a dev-dependency); nothing here
//! ships in the gateway binary.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dwara_core::balance::UpstreamLb;
use dwara_core::config::credentials::{credential_selector, sha256_stored_hash};
use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, PathMatch, PathMatchKind, Route, RouteAction, RouteMatch,
    Service, Upstream, UpstreamProtocol,
};
use dwara_core::extensions::rate_limiter::{GcraRateLimiter, GcraWindowSpec};
use dwara_core::snapshot;
use subtle::ConstantTimeEq;

/// A representative gateway: 100 routes over 10 services and 5 upstreams,
/// mixed match kinds mirroring realistic route tables (60 prefix, 30
/// exact — half of them parameterized, 10 regex).
fn bench_gateway() -> Gateway {
    let mut routes = Vec::new();
    for i in 0..10 {
        for j in 0..10 {
            let (kind, value) = match j % 10 {
                0..=5 => (PathMatchKind::Prefix, format!("/svc{i}/v{j}")),
                6..=8 => (PathMatchKind::Exact, format!("/svc{i}/exact/v{{id}}/{j}")),
                _ => (PathMatchKind::Regex, format!(r"/svc{i}/re/v{j}/[0-9]+")),
            };
            routes.push(Route {
                name: format!("route-{i}-{j}"),
                service: format!("service-{i}"),
                cache: None,
                methods: Vec::new(),
                slo: None,
                websocket: None,
                waf: None,
                request_validation: None,
                openapi: None,
                mirror: None,
                fault_injection: None,
                r#match: RouteMatch {
                    path: PathMatch { kind, value },
                    host: None,
                    methods: Vec::new(),
                    headers: BTreeMap::new(),
                    query: Vec::new(),
                    cookies: Vec::new(),
                    accept: None,
                },
                action: RouteAction::Proxy { rewrite: None },
                policies: Vec::new(),
                priority: None,
                auth_required: false,
                cors: None,
                compression: None,
                limits: None,
                authorization: None,
                deprecation: None,
                maintenance: None,
                transforms: None,
                security_headers: None,
                masking: None,
                plugins: Vec::new(),
                graphql: None,
                grpc_web: None,
                translation: None,
            });
        }
    }
    let services = (0..10)
        .map(|i| Service {
            name: format!("service-{i}"),
            upstream: Some(format!("upstream-{}", i % 5)),
            split: None,
            sticky: None,
            base_path: None,
            version: None,
            policies: Vec::new(),
            authorization: None,
        })
        .collect();
    let upstreams = (0..5)
        .map(|u| Upstream {
            name: format!("upstream-{u}"),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: (0..5)
                .map(|e| Endpoint {
                    address: format!("10.0.{u}.{e}"),
                    port: 8080,
                    weight: 1,
                    region: None,
                    zone: None,
                })
                .collect(),
            connection_cap: None,
            slow_start_ms: None,
            health: None,
            active_health: None,
            retries: None,
            breaker: None,
            max_pending: None,
            trusted_ca_file: None,
            timeouts: None,
            oauth2_client_credentials: None,
            dns_discovery: None,
            peak_ewma: None,
            locality: None,
            pq: false,
        })
        .collect();
    Gateway {
        listeners: Vec::new(),
        routes,
        services,
        upstreams,
        consumers: Vec::new(),
        policies: Vec::new(),
        global_policies: Vec::new(),
        authorization: None,
        trusted_proxies: Vec::new(),
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        allow_empty_routes: false,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
        license: None,
        oidc_providers: Vec::new(),
        redis_rate_limiter: None,
        config_convergence: None,
        plugins: Vec::new(),
        ai: None,
        fleet: None,
        lifecycle: None,
        mesh: None,
    }
}

fn bench_micro(c: &mut Criterion) {
    // --- route resolution -------------------------------------------------

    let compiled = snapshot::compile(&bench_gateway()).expect("bench fixture compiles");
    let table = compiled.route_table();

    let mut g = c.benchmark_group("route");
    g.throughput(Throughput::Elements(1));
    g.bench_function("find_full_prefix_hit", |b| {
        b.iter(|| table.find_full("/svc3/v7/some/deep/path"))
    });
    g.bench_function("find_full_exact_param", |b| {
        b.iter(|| table.find_full("/svc4/exact/v7/42"))
    });
    g.bench_function("find_full_regex_hit", |b| {
        b.iter(|| table.find_full("/svc9/re/v9/12345"))
    });
    g.bench_function("find_full_miss", |b| {
        b.iter(|| table.find_full("/nowhere/at/all"))
    });
    g.finish();

    // --- config compile ---------------------------------------------------

    let mut g = c.benchmark_group("config");
    g.throughput(Throughput::Elements(1));
    g.bench_function("validate_100_routes", |b| {
        b.iter(|| snapshot::validate(&bench_gateway()))
    });
    g.bench_function("compile_100_routes", |b| {
        b.iter(|| snapshot::compile(&bench_gateway()).map(|c| c.content_hash()))
    });
    g.finish();

    // --- header hygiene ---------------------------------------------------

    let mut g = c.benchmark_group("headers");
    g.throughput(Throughput::Elements(1));
    // Build the fixture HeaderMap once and clone per iteration
    // (HeaderMap: Clone) so the bench measures strip_hop_by_hop itself,
    // not header-name parsing and allocation.
    let mut fixture = hyper::header::HeaderMap::new();
    for i in 0..30 {
        fixture.insert(
            format!("x-bench-{i}")
                .parse::<hyper::header::HeaderName>()
                .unwrap(),
            format!("value-{i}").parse().unwrap(),
        );
    }
    fixture.insert("connection", "keep-alive, x-bench-0".parse().unwrap());
    g.bench_function("strip_hop_by_hop_30", |b| {
        b.iter(|| {
            let mut headers = fixture.clone();
            dwara_core::proxy::strip_hop_by_hop(&mut headers, false, false)
        })
    });
    g.finish();

    // --- balancer pick ----------------------------------------------------

    let endpoints: Vec<Endpoint> = (0..5)
        .map(|e| Endpoint {
            address: format!("10.1.0.{e}"),
            port: 8080,
            weight: if e == 0 { 3 } else { 1 },
            region: None,
            zone: None,
        })
        .collect();
    let wrr = UpstreamLb::new(&endpoints, LoadBalancer::RoundRobin, Duration::from_secs(0));
    let ketama = UpstreamLb::new(&endpoints, LoadBalancer::IpHash, Duration::from_secs(0));

    let mut g = c.benchmark_group("balancer");
    g.throughput(Throughput::Elements(1));
    g.bench_function("pick_wrr_5", |b| b.iter(|| wrr.pick(None)));
    g.bench_function("pick_ketama_5", |b| {
        b.iter(|| ketama.pick(Some("203.0.113.7")))
    });
    g.finish();

    // --- rate limit -------------------------------------------------------

    let limiter = GcraRateLimiter::new(vec![
        GcraWindowSpec {
            requests: NonZeroU32::new(1000).unwrap(),
            window: Duration::from_secs(1),
            burst: None,
        },
        GcraWindowSpec {
            requests: NonZeroU32::new(100_000).unwrap(),
            window: Duration::from_secs(60),
            burst: None,
        },
    ])
    .expect("two specs");
    // Prime the keyed state so the bench measures steady-state hits, not
    // first-touch bucket allocation.
    let _ = limiter.check("bench-key", 1);

    let mut g = c.benchmark_group("ratelimit");
    g.throughput(Throughput::Elements(1));
    g.bench_function("gcra_hit", |b| b.iter(|| limiter.check("bench-key", 1)));
    g.finish();

    // --- api-key verify (sha256 + constant-time compare) -------------------

    // The per-request fast path of the DW-019 config-seeded authenticator:
    // hash the presented key for the selector, hash again for comparison,
    // compare in constant time. verify_secret itself is private, so this
    // benches the exact primitive sequence it runs.
    let stored = sha256_stored_hash("dwara-bench-secret");
    let mut g = c.benchmark_group("authn");
    g.throughput(Throughput::Elements(1));
    g.bench_function("apikey_verify_sha256_ct", |b| {
        b.iter(|| {
            let selector = credential_selector("dwara-bench-secret");
            let computed = sha256_stored_hash("dwara-bench-secret");
            let ok: bool = computed.as_bytes().ct_eq(stored.as_bytes()).into();
            (selector, ok)
        })
    });
    g.finish();
}

criterion_group!(benches, bench_micro);
criterion_main!(benches);
