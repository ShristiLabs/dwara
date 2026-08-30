//! Active health checks (DW-013): probe classification, ejection within
//! the interval budget, probe-driven recovery, probe-task lifecycle on
//! respawn, plus the reserved `/healthz` and `/readyz` gateway endpoints.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

use dwara_core::active::{probe_once, ActiveProbes};
use dwara_core::config::{
    ActiveHealth, Endpoint, Gateway, LoadBalancer, PassiveHealth, PathMatch, PathMatchKind,
    ProbeKind, Route, RouteAction, RouteMatch, Service, Upstream, UpstreamProtocol,
};
use dwara_core::proxy::{self, DataPlane, ProxyBody};
use dwara_core::snapshot::{self, ConfigState};
use dwara_core::upstream::UpstreamRegistry;

mod support;

use support::dead_port;

// ---------------------------------------------------------------- helpers

/// HTTP/1.1 server answering every request with 200 or 500 depending on
/// `healthy`. Returns the bound port.
async fn serve_switchable(healthy: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let healthy = Arc::clone(&healthy);
            let service = service_fn(move |_req: Request<Incoming>| {
                let healthy = Arc::clone(&healthy);
                async move {
                    let status = if healthy.load(Ordering::Relaxed) {
                        StatusCode::OK
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    };
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }
            });
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    port
}

fn base_gateway(active: ActiveHealth, endpoints: Vec<Endpoint>) -> Gateway {
    Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams: vec![Upstream {
            name: "pool".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints,
            connection_cap: None,
            slow_start_ms: None,
            health: Some(PassiveHealth {
                // Long eject window: recovery in the tests must come from
                // the PROBE success streak, not from window expiry.
                eject_ms: 60_000,
                ..PassiveHealth::default()
            }),
            active_health: Some(active),
            retries: None,
            timeouts: None,
            breaker: None,
            max_pending: None,
            trusted_ca_file: None,
            oauth2_client_credentials: None,
        }],
        consumers: vec![],
        policies: vec![],
        global_policies: Vec::new(),
        authorization: None,
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        // Genuinely zero-route shape: these suites exercise upstream health
        // machinery, not routing (#129 opt-in).
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
        license: None,
        redis_rate_limiter: None,
    }
}

fn fast_active(kind: ProbeKind, failure_threshold: u32) -> ActiveHealth {
    ActiveHealth {
        kind,
        path: "/healthz".into(),
        interval_ms: 100,
        timeout_ms: 100,
        success_threshold: 2,
        failure_threshold,
        jitter_ms: 0,
    }
}

/// Publish `gw`, build the dataplane, and respawn active probes against it
/// (the exact sequence dwara-bin runs at startup and after each reload).
fn launch(gw: &Gateway) -> (Arc<DataPlane>, ActiveProbes) {
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(gw).expect("publish");
    let dp = DataPlane::new(Arc::clone(&state));
    let mut probes = ActiveProbes::new();
    probes.respawn(&dp.registry(), &state.snapshot());
    (dp, probes)
}

/// Tracker of endpoint `idx`'s current availability, polled until `want`
/// or the deadline. Returns the elapsed time at the observed state.
async fn wait_available(dp: &Arc<DataPlane>, idx: usize, want: bool, deadline: Duration) -> bool {
    let handle = dp.registry().get("pool").expect("handle");
    let lb = handle.lb();
    let start = Instant::now();
    while start.elapsed() < deadline {
        let targets = lb.health_targets();
        let (_, _, tracker) = &targets[idx];
        let tracker = tracker.as_ref().expect("tracker");
        if tracker.is_available(lb.now_ms()) == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

// ------------------------------------------------------- probe classification

#[tokio::test]
async fn http_probe_classifies_2xx_success_5xx_failure() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let flag = Arc::new(AtomicBool::new(true));
    let port = serve_switchable(Arc::clone(&flag)).await;
    let t = Duration::from_secs(2);

    assert!(
        probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            port,
            "/healthz",
            t,
            None
        )
        .await
    );
    flag.store(false, Ordering::Relaxed);
    assert!(
        !probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            port,
            "/healthz",
            t,
            None
        )
        .await
    );
    // Refused port: failure.
    assert!(
        !probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            dead_port(),
            "/healthz",
            t,
            None
        )
        .await
    );
    // Unroutable address: times out inside the bound.
    let started = Instant::now();
    assert!(
        !probe_once(
            ProbeKind::Http,
            None,
            "10.255.255.1",
            81,
            "/healthz",
            Duration::from_millis(200),
            None
        )
        .await
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn tcp_probe_classifies_connect_success_and_failure() {
    let flag = Arc::new(AtomicBool::new(true));
    let port = serve_switchable(flag).await;
    assert!(
        probe_once(
            ProbeKind::Tcp,
            None,
            "127.0.0.1",
            port,
            "",
            Duration::from_secs(2),
            None
        )
        .await
    );
    assert!(
        !probe_once(
            ProbeKind::Tcp,
            None,
            "127.0.0.1",
            dead_port(),
            "",
            Duration::from_secs(2),
            None
        )
        .await
    );
}

// ------------------------------------------------------------- ejection / recovery

/// Done-when pin: with `failure_threshold: 2` and `interval_ms: 100` the
/// endpoint must leave rotation within ~2 intervals (plus probe overhead).
#[tokio::test]
async fn failing_endpoint_leaves_rotation_within_two_intervals() {
    let healthy = Arc::new(AtomicBool::new(true));
    let good = serve_switchable(Arc::clone(&healthy)).await;
    let bad = serve_switchable(Arc::new(AtomicBool::new(false))).await;

    let gw = base_gateway(
        fast_active(ProbeKind::Http, 2),
        vec![
            Endpoint {
                address: "127.0.0.1".into(),
                port: good,
                weight: 1,
            },
            Endpoint {
                address: "127.0.0.1".into(),
                port: bad,
                weight: 1,
            },
        ],
    );
    let (dp, _probes) = launch(&gw);
    let handle = dp.registry().get("pool").unwrap();
    let lb = handle.lb();

    let started = Instant::now();
    assert!(
        wait_available(&dp, 1, false, Duration::from_millis(600)).await,
        "failing endpoint must be ejected; {:?} elapsed",
        started.elapsed()
    );
    // 2 intervals = 200 ms; 600 ms allows the full probe round-trip slack
    // while still pinning "well under the passive default" timing. The
    // ejection happened after exactly failure_threshold probes.
    assert!(started.elapsed() < Duration::from_millis(600));

    // Rotation: the ejected endpoint is never picked.
    for _ in 0..50 {
        assert_eq!(
            lb.pick(None),
            Some(0),
            "only the healthy endpoint is picked"
        );
    }

    // The healthy endpoint is untouched.
    assert!(wait_available(&dp, 0, true, Duration::from_millis(50)).await);
}

/// Recovery is probe-driven: `success_threshold` consecutive successes
/// re-admit the endpoint even mid-ejection (eject_ms is 60 s here).
#[tokio::test]
async fn recovery_by_probe_returns_endpoint_to_rotation() {
    let flaky = Arc::new(AtomicBool::new(false));
    let port = serve_switchable(Arc::clone(&flaky)).await;

    let gw = base_gateway(
        fast_active(ProbeKind::Http, 2),
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port,
            weight: 1,
        }],
    );
    let (dp, _probes) = launch(&gw);

    // Sole endpoint fails: ejected (fail-open still serves it if traffic
    // came, but the tracker state must read ejected).
    assert!(wait_available(&dp, 0, false, Duration::from_millis(600)).await);

    // Backend heals: 2 consecutive probe successes re-admit it.
    flaky.store(true, Ordering::Relaxed);
    assert!(
        wait_available(&dp, 0, true, Duration::from_millis(800)).await,
        "probe success streak must re-admit the endpoint"
    );
}

/// TCP probes drive the same machinery.
#[tokio::test]
async fn tcp_probes_eject_dead_endpoint() {
    let port = serve_switchable(Arc::new(AtomicBool::new(true))).await;
    let gw = base_gateway(
        fast_active(ProbeKind::Tcp, 2),
        vec![
            Endpoint {
                address: "127.0.0.1".into(),
                port,
                weight: 1,
            },
            Endpoint {
                address: "127.0.0.1".into(),
                port: dead_port(),
                weight: 1,
            },
        ],
    );
    let (dp, _probes) = launch(&gw);
    assert!(wait_available(&dp, 1, false, Duration::from_millis(600)).await);
    let handle = dp.registry().get("pool").unwrap();
    for _ in 0..20 {
        assert_eq!(handle.lb().pick(None), Some(0));
    }
}

// ----------------------------------------------------------------- lifecycle

/// Rebuild cancels and respawns probe tasks: repeated respawns never leak
/// tasks (count stays at the endpoint count), and abort drains to zero.
#[tokio::test]
async fn respawn_cancels_and_respawns_probe_tasks_without_leaks() {
    let port = dead_port();
    let gw = base_gateway(
        fast_active(ProbeKind::Tcp, 2),
        vec![
            Endpoint {
                address: "127.0.0.1".into(),
                port,
                weight: 1,
            },
            Endpoint {
                address: "127.0.0.1".into(),
                port: dead_port(),
                weight: 1,
            },
        ],
    );
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gw).unwrap();
    let dp = DataPlane::new(Arc::clone(&state));

    let mut probes = ActiveProbes::new();
    for round in 0..3 {
        probes.respawn(&dp.registry(), &state.snapshot());
        // Give the runtime a moment to reap the aborted previous round
        // (abort takes effect at the next poll).
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            probes.task_count(),
            2,
            "round {round}: exactly one task per endpoint, no leaks"
        );
    }
    // Same-generation registry with a carried balancer also works through
    // the registry-from-snapshot path used by tests.
    let registry = UpstreamRegistry::from_snapshot(&state.snapshot());
    probes.respawn(&registry, &state.snapshot());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(probes.task_count(), 2);
    probes.abort_all();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(probes.task_count(), 0, "abort drains the task set");
}

// ------------------------------------------------------- /healthz and /readyz

fn get(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn body_of(resp: Response<ProxyBody>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn peer() -> std::net::IpAddr {
    "127.0.0.1".parse().unwrap()
}

#[tokio::test]
async fn readyz_is_503_before_first_publish_and_200_after() {
    let state = Arc::new(ConfigState::new());
    let dp = DataPlane::new(Arc::clone(&state));

    let resp = proxy::handle(&dp, peer(), get("/readyz")).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(body_of(resp).await.contains("\"code\":\"not_ready\""));
    // Liveness does not depend on readiness.
    let resp = proxy::handle(&dp, peer(), get("/healthz")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    state
        .compile_and_publish(&Gateway {
            trusted_proxies: vec![],
            listeners: vec![],
            routes: vec![],
            services: vec![],
            upstreams: vec![],
            consumers: vec![],
            policies: vec![],
            global_policies: Vec::new(),
            authorization: None,
            max_concurrent_requests: None,
            load_shed_dry_run: false,
            jwt_providers: Vec::new(),
            admin: None,
            // Zero-route by design: readiness flips on first publish, not on
            // routes existing (#129 opt-in).
            allow_empty_routes: true,
            hmac_auth: None,
            webhooks: Vec::new(),
            analytics: None,
            analytics_stream: None,
            geoip: None,
            admission_queue: None,
            mtls_consumer_mapping: None,
            mtls_forward_headers: None,
            license: None,
            redis_rate_limiter: None,
        })
        .unwrap();
    let resp = proxy::handle(&dp, peer(), get("/readyz")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_of(resp).await.contains("\"code\":\"ready\""));
}

#[tokio::test]
async fn reserved_paths_shadow_configured_routes() {
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&Gateway {
            trusted_proxies: vec![],
            listeners: vec![],
            routes: vec![
                Route {
                    name: "steal-liveness".into(),
                    cache: None,
                    methods: vec![],
                    slo: None,
                    websocket: None,
                    waf: None,
                    request_validation: None,
                    openapi: None,
                    service: "svc".into(),
                    r#match: RouteMatch {
                        path: PathMatch {
                            kind: PathMatchKind::Exact,
                            value: "/healthz".into(),
                        },
                        host: None,
                        methods: vec![],
                        headers: Default::default(),
                        query: vec![],
                        cookies: vec![],
                        accept: None,
                    },
                    action: RouteAction::Respond {
                        status: 418,
                        body: Some("shadowed".into()),
                        headers: Default::default(),
                    },
                    policies: vec![],
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
                },
                Route {
                    name: "catch".into(),
                    cache: None,
                    methods: vec![],
                    slo: None,
                    websocket: None,
                    waf: None,
                    request_validation: None,
                    openapi: None,
                    service: "svc".into(),
                    r#match: RouteMatch {
                        path: PathMatch {
                            kind: PathMatchKind::Regex,
                            value: "/.*".into(),
                        },
                        host: None,
                        methods: vec![],
                        headers: Default::default(),
                        query: vec![],
                        cookies: vec![],
                        accept: None,
                    },
                    action: RouteAction::Respond {
                        status: 200,
                        body: Some("route".into()),
                        headers: Default::default(),
                    },
                    policies: vec![],
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
                },
            ],
            services: vec![Service {
                name: "svc".into(),
                upstream: Some("up".into()),
                split: None,
                sticky: None,
                base_path: None,
                version: None,
                policies: vec![],
                authorization: None,
            }],
            upstreams: vec![Upstream {
                name: "up".into(),
                load_balancer: LoadBalancer::RoundRobin,
                protocol: UpstreamProtocol::Http1,
                endpoints: vec![Endpoint {
                    address: "127.0.0.1".into(),
                    port: 9,
                    weight: 1,
                }],
                connection_cap: None,
                slow_start_ms: None,
                health: None,
                active_health: None,
                retries: None,
                timeouts: None,
                breaker: None,
                max_pending: None,
                trusted_ca_file: None,
                oauth2_client_credentials: None,
            }],
            consumers: vec![],
            policies: vec![],
            global_policies: vec![],
            authorization: None,
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
            redis_rate_limiter: None,
        })
        .unwrap();
    let dp = DataPlane::new(Arc::clone(&state));

    // Exact route on /healthz is shadowed by the reserved path.
    let resp = proxy::handle(&dp, peer(), get("/healthz")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_of(resp).await.contains("\"code\":\"ok\""));
    // Regex catch-all does not capture /readyz.
    let resp = proxy::handle(&dp, peer(), get("/readyz")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_of(resp).await.contains("\"code\":\"ready\""));
    // Ordinary paths still route normally.
    let resp = proxy::handle(&dp, peer(), get("/anything")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_of(resp).await, "route");
}

// ------------------------------------------------------------ schema + validation

#[test]
fn schema_parses_active_health_with_defaults() {
    let text = "\
upstreams:
  - name: u
    endpoints:
      - address: 127.0.0.1
        port: 9
    health: {}
    active_health:
      kind: tcp
";
    let gw = dwara_core::config::parse_gateway(text).expect("parses");
    let a = gw.upstreams[0].active_health.as_ref().unwrap();
    assert_eq!(a.kind, ProbeKind::Tcp);
    assert_eq!(a.path, "/healthz");
    assert_eq!(a.interval_ms, 5000);
    assert_eq!(a.timeout_ms, 2000);
    assert_eq!(a.success_threshold, 2);
    assert_eq!(a.failure_threshold, 3);
    assert_eq!(a.jitter_ms, 500);
    assert!(gw.upstreams[0].health.is_some());

    // Round-trip: normalized YAML reparses identically.
    let yaml = dwara_core::config::gateway_to_yaml(&gw).unwrap();
    let again = dwara_core::config::parse_gateway(&yaml).unwrap();
    assert_eq!(gw, again);
}

#[test]
fn schema_rejects_unknown_active_health_fields() {
    let text = "\
upstreams:
  - name: u
    endpoints:
      - address: 127.0.0.1
        port: 9
    health: {}
    active_health:
      protocl: http
";
    assert!(dwara_core::config::parse_gateway(text).is_err());
}

#[test]
fn validation_rejects_active_health_without_passive_block() {
    let mut gw = base_gateway(ActiveHealth::default(), vec![]);
    gw.upstreams[0].health = None;
    let issues = snapshot::validate(&gw);
    assert!(
        issues.iter().any(|i| i.field == "active_health"),
        "active without passive must be rejected: {issues:?}"
    );
}

#[test]
fn validation_bounds_active_health_knobs() {
    let mut gw = base_gateway(ActiveHealth::default(), vec![]);
    gw.upstreams[0].endpoints = vec![Endpoint {
        address: "127.0.0.1".into(),
        port: 9,
        weight: 1,
    }];

    let default = ActiveHealth::default();

    gw.upstreams[0].active_health = Some(ActiveHealth {
        jitter_ms: default.interval_ms + 1,
        ..default.clone()
    });
    assert!(snapshot::validate(&gw)
        .iter()
        .any(|i| i.field == "active_health.jitter_ms"));

    gw.upstreams[0].active_health = Some(ActiveHealth {
        timeout_ms: default.interval_ms + 1,
        ..default.clone()
    });
    assert!(snapshot::validate(&gw)
        .iter()
        .any(|i| i.field == "active_health.timeout_ms"));

    gw.upstreams[0].active_health = Some(ActiveHealth {
        interval_ms: 0,
        ..default.clone()
    });
    assert!(snapshot::validate(&gw)
        .iter()
        .any(|i| i.field == "active_health.interval_ms"));

    gw.upstreams[0].active_health = Some(ActiveHealth {
        path: "healthz".into(),
        ..default.clone()
    });
    assert!(snapshot::validate(&gw)
        .iter()
        .any(|i| i.field == "active_health.path"));

    // Sane config validates clean (including tcp kind ignoring path).
    gw.upstreams[0].active_health = Some(ActiveHealth {
        kind: ProbeKind::Tcp,
        path: String::new(),
        ..default
    });
    assert!(
        snapshot::validate(&gw).is_empty(),
        "{:?}",
        snapshot::validate(&gw)
    );
}

#[test]
fn validation_rejects_zero_active_thresholds() {
    let gw = |a: ActiveHealth| {
        let mut g = base_gateway(a, vec![]);
        g.upstreams[0].endpoints = vec![Endpoint {
            address: "127.0.0.1".into(),
            port: 9,
            weight: 1,
        }];
        g
    };
    let default = ActiveHealth::default();
    for (field, a) in [
        (
            "active_health.success_threshold",
            ActiveHealth {
                success_threshold: 0,
                ..default.clone()
            },
        ),
        (
            "active_health.failure_threshold",
            ActiveHealth {
                failure_threshold: 0,
                ..default
            },
        ),
    ] {
        assert!(
            snapshot::validate(&gw(a)).iter().any(|i| i.field == field),
            "{field} = 0 must be rejected"
        );
    }
}

// ------------------------------------------- raw-origin helpers (new tests)

/// One (arrival instant, request line) pair recorded by a raw origin.
type Hit = (Instant, String);

/// Raw TCP origin: answers each connection with the next canned response
/// from `responses` (cycling the last one) and records every request line
/// it reads. Lets the tests pin exact wire bytes, methods, and timing.
async fn raw_origin(responses: Arc<Vec<Vec<u8>>>, hits: Arc<Mutex<Vec<Hit>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let idx = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let responses = Arc::clone(&responses);
            let hits = Arc::clone(&hits);
            let idx = Arc::clone(&idx);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                hits.lock().expect("hits").push((Instant::now(), line));
                let i = idx.fetch_add(1, Ordering::SeqCst).min(responses.len() - 1);
                let _ = stream.write_all(&responses[i]).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

const OK_EMPTY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A listener that accepts connections and never writes anything back.
async fn stalling_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = vec![];
        loop {
            match listener.accept().await {
                Ok((s, _)) => held.push(s),
                Err(_) => return,
            }
        }
    });
    port
}

/// A listener that accepts connections and closes them immediately.
async fn accept_close_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    port
}

// ------------------------------------------------------------- probe timing

/// Full-jitter pin: the inter-probe delay lives in [interval, interval +
/// jitter). The RNG is not seedable, so this is statistical: many probes
/// against a recording origin, every gap inside generous bounds.
#[tokio::test]
async fn probe_interarrival_respects_full_jitter_bounds() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(vec![]));
    let port = raw_origin(Arc::new(vec![OK_EMPTY.to_vec()]), Arc::clone(&hits)).await;

    let gw = base_gateway(
        ActiveHealth {
            kind: ProbeKind::Http,
            path: "/probe".into(),
            interval_ms: 250,
            timeout_ms: 200,
            success_threshold: 1,
            failure_threshold: 100,
            jitter_ms: 250,
        },
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port,
            weight: 1,
        }],
    );
    let _dp_probes = launch(&gw);

    // Collect at least 6 arrivals (5 gaps) within 4 s.
    let started = Instant::now();
    while hits.lock().expect("hits").len() < 6 {
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "not enough probes arrived: {:?}",
            hits.lock().expect("hits")
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let times: Vec<Instant> = hits.lock().expect("hits").iter().map(|(t, _)| *t).collect();
    // The probe verb is GET with the configured path (no HEAD).
    for (_, line) in hits.lock().expect("hits").iter() {
        assert!(
            line.starts_with("GET /probe HTTP/1.1"),
            "probe must be GET with the configured path: {line}"
        );
    }
    let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
    for g in gaps.iter().copied() {
        assert!(
            g >= Duration::from_millis(220),
            "gap below interval (scheduler margin 30 ms): {g:?} in {gaps:?}"
        );
        assert!(
            g < Duration::from_millis(540),
            "gap at or beyond interval+jitter (margin 40 ms): {g:?} in {gaps:?}"
        );
    }
}

/// A stalling server (accept, never answer) fails the probe via timeout,
/// roughly AT the timeout, not instantly and not unboundedly late.
#[tokio::test]
async fn http_probe_times_out_against_stalling_server() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let port = stalling_origin().await;
    let started = Instant::now();
    assert!(
        !probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            port,
            "/healthz",
            Duration::from_millis(100),
            None
        )
        .await,
        "stalling server is a failed probe"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(80),
        "failed before the timeout could fire: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(250),
        "blew past 2x timeout: {elapsed:?}"
    );
}

// ------------------------------------------------- probe classification (raw)

/// Non-2xx status lines (3xx AND 4xx — the active rule is 2xx-only, unlike
/// passive health where 4xx is a success), garbage bytes, and a closed
/// connection all fail; 2xx with or without a body succeeds.
#[tokio::test]
async fn http_probe_is_twoxx_only_and_ignores_bodies() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let cases: Vec<(&[u8], bool)> = vec![
        (
            b"HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (b"NOT-HTTP GARBAGE\r\n\r\n", false),
        (b"HTTP/1.1 204 No Content\r\n\r\n", true),
        (
            concat!(
                "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n",
                "hello-body"
            )
            .as_bytes(),
            true,
        ),
        (OK_EMPTY, true),
    ];
    let expected: Vec<bool> = cases.iter().map(|(_, ok)| *ok).collect();
    let responses: Vec<Vec<u8>> = cases.into_iter().map(|(r, _)| r.to_vec()).collect();
    let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(vec![]));
    let port = raw_origin(Arc::new(responses), Arc::clone(&hits)).await;

    for (i, want) in expected.iter().enumerate() {
        let got = probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            port,
            "/healthz",
            Duration::from_secs(2),
            None,
        )
        .await;
        assert_eq!(got, *want, "case {i} classified wrong");
    }
    assert_eq!(hits.lock().expect("hits").len(), expected.len());
}

/// `tcp` probes only require the connect: accepted-and-held and
/// accepted-then-closed both succeed; refused fails. `http` probes against
/// accept-then-close fail (no status line).
#[tokio::test]
async fn tcp_probe_classifies_refused_close_and_hold() {
    let hold = stalling_origin().await;
    let close = accept_close_origin().await;
    let t = Duration::from_secs(2);

    // tcp kind: connect is the only criterion.
    assert!(probe_once(ProbeKind::Tcp, None, "127.0.0.1", hold, "", t, None).await);
    assert!(probe_once(ProbeKind::Tcp, None, "127.0.0.1", close, "", t, None).await);
    assert!(!probe_once(ProbeKind::Tcp, None, "127.0.0.1", dead_port(), "", t, None).await);

    // http kind: a connection that closes before a status line is a failure.
    assert!(
        !probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            close,
            "/healthz",
            t,
            None
        )
        .await
    );
}

// --------------------------------------------------------- ejection done-when

/// Stricter timing pin than the ejection test above: with threshold 2 and
/// interval 100 ms (no jitter), the endpoint is out of rotation by 250 ms
/// wall clock, and every pick until then already avoids it once ejected.
#[tokio::test]
async fn failing_endpoint_ejected_within_250ms_and_picks_avoid_it() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let bad = serve_switchable(Arc::new(AtomicBool::new(false))).await;
    let gw = base_gateway(
        fast_active(ProbeKind::Http, 2),
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port: bad,
            weight: 1,
        }],
    );
    let (dp, _probes) = launch(&gw);
    let handle = dp.registry().get("pool").unwrap();
    let lb = handle.lb();

    let started = Instant::now();
    loop {
        let (_, _, tracker) = &lb.health_targets()[0];
        if !tracker.as_ref().unwrap().is_available(lb.now_ms()) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "not ejected within 250 ms: {:?}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Ejected picks are fail-open (sole endpoint): the pick still names it,
    // so assert via the candidate filter instead — the tracker is out.
    for _ in 0..20 {
        let (_, _, tracker) = &lb.health_targets()[0];
        assert!(
            !tracker.as_ref().unwrap().is_available(lb.now_ms()),
            "ejection must hold"
        );
    }
}

// ---------------------------------------------------------------- recovery

/// Recovery is purely probe-driven even when NO real traffic ever reaches
/// the endpoint: after healing, probes alone re-admit it and picks include
/// it again.
#[tokio::test]
async fn probes_alone_readmit_ejected_endpoint_with_zero_traffic() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let good = serve_switchable(Arc::new(AtomicBool::new(true))).await;
    let flaky = Arc::new(AtomicBool::new(false));
    let flaky_port = serve_switchable(Arc::clone(&flaky)).await;

    let gw = base_gateway(
        fast_active(ProbeKind::Http, 2),
        vec![
            Endpoint {
                address: "127.0.0.1".into(),
                port: good,
                weight: 1,
            },
            Endpoint {
                address: "127.0.0.1".into(),
                port: flaky_port,
                weight: 1,
            },
        ],
    );
    let (dp, _probes) = launch(&gw);
    let handle = dp.registry().get("pool").unwrap();
    let lb = handle.lb();

    // Failing from t0: out of rotation, picks never touch it.
    assert!(wait_available(&dp, 1, false, Duration::from_millis(600)).await);
    for _ in 0..20 {
        assert_eq!(lb.pick(None), Some(0), "only the healthy endpoint serves");
    }

    // Heal. No handle traffic is ever sent: probes alone must re-admit.
    flaky.store(true, Ordering::Relaxed);
    assert!(
        wait_available(&dp, 1, true, Duration::from_millis(800)).await,
        "probe streak must re-admit without any real traffic"
    );
    let mut saw_flaky = false;
    for _ in 0..20 {
        saw_flaky |= lb.pick(None) == Some(1);
    }
    assert!(saw_flaky, "re-admitted endpoint back in rotation");
}

// ------------------------------------------------- active/passive interplay

/// An active probe SUCCESS resets the shared passive consecutive-failure
/// streak: with passive consecutive_failures = 2, passive-failure /
/// (probe success) / passive-failure never ejects.
#[tokio::test]
async fn probe_success_resets_the_passive_failure_streak() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let good = serve_switchable(Arc::new(AtomicBool::new(true))).await;
    // Passive: 2 consecutive traffic failures eject. Active: threshold 100
    // so probes never eject on their own; interval 50 ms so several probe
    // successes land inside the wait below.
    let mut gw = base_gateway(
        ActiveHealth {
            kind: ProbeKind::Http,
            path: "/healthz".into(),
            interval_ms: 50,
            timeout_ms: 40,
            success_threshold: 1,
            failure_threshold: 100,
            jitter_ms: 0,
        },
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port: good,
            weight: 1,
        }],
    );
    gw.upstreams[0].health = Some(PassiveHealth {
        consecutive_failures: 2,
        eject_ms: 60_000,
        ..PassiveHealth::default()
    });
    let (dp, _probes) = launch(&gw);
    let handle = dp.registry().get("pool").unwrap();
    let lb = handle.lb();

    // Report one passive (real-traffic) failure: streak = 1.
    let d = lb.pick_for_dispatch(None).expect("pick");
    let health = d.health.as_ref().expect("health");
    health.report(lb.now_ms(), true);
    d.release();

    // Let the probe loop observe successes (several intervals pass).
    tokio::time::sleep(Duration::from_millis(300)).await;

    // One more passive failure: if the probe success reset the shared
    // streak, this is a streak of 1 — still available.
    let tracker;
    {
        let d = lb.pick_for_dispatch(None).expect("pick");
        let health = d.health.as_ref().expect("health");
        health.report(lb.now_ms(), true);
        tracker = Arc::clone(health.tracker());
        d.release();
    }
    assert!(
        tracker.is_available(lb.now_ms()),
        "probe success must reset the passive consecutive streak"
    );
    // Control: without an intervening probe success two passive failures
    // eject under consecutive_failures = 2 — prove the passive threshold is
    // actually armed in this configuration.
    for _ in 0..30 {
        let d = lb.pick_for_dispatch(None).expect("pick");
        d.health.as_ref().expect("health").report(lb.now_ms(), true);
        d.release();
    }
    assert!(
        !tracker.is_available(lb.now_ms()),
        "passive threshold 2 ejects once the streak is uninterrupted"
    );
}

/// Probe failures never enter the failure-ratio window: many failed probes
/// against a config whose passive ratio would eject instantly (min volume
/// 3, ratio 0.5, consecutive 100, active threshold 100) leave the endpoint
/// available — the ratio rule sees zero volume.
#[tokio::test]
async fn probe_failures_do_not_feed_the_ratio_window() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let bad = serve_switchable(Arc::new(AtomicBool::new(false))).await;
    let mut gw = base_gateway(
        ActiveHealth {
            kind: ProbeKind::Http,
            path: "/healthz".into(),
            interval_ms: 100,
            timeout_ms: 80,
            success_threshold: 2,
            failure_threshold: 100,
            jitter_ms: 0,
        },
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port: bad,
            weight: 1,
        }],
    );
    gw.upstreams[0].health = Some(PassiveHealth {
        consecutive_failures: 100,
        failure_ratio: 0.5,
        failure_min_volume: 3,
        eject_ms: 60_000,
        ..PassiveHealth::default()
    });
    let (dp, _probes) = launch(&gw);
    let handle = dp.registry().get("pool").unwrap();
    let lb = handle.lb();

    // ~12 failed probes: had they entered the window (volume 12, failures
    // 12, ratio 1.0 >= 0.5, volume >= 3) the endpoint would eject.
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    let (_, _, tracker) = &lb.health_targets()[0];
    let tracker = tracker.as_ref().expect("tracker");
    assert!(
        tracker.is_available(lb.now_ms()),
        "probe failures must not feed the passive ratio window"
    );
    assert_eq!(tracker.ejections(), 0, "no ejection path may fire");
}

// ----------------------------------------------------------------- lifecycle

/// Reload removing `active_health` stops probing (task count drops to
/// zero); reload re-adding it starts probing an EXISTING endpoint again.
#[tokio::test]
async fn reload_toggles_probe_tasks_with_the_active_health_block() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let port = dead_port();
    let gw_with = base_gateway(
        fast_active(ProbeKind::Tcp, 2),
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port,
            weight: 1,
        }],
    );
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gw_with).unwrap();
    let dp = DataPlane::new(Arc::clone(&state));

    let mut probes = ActiveProbes::new();
    probes.respawn(&dp.registry(), &state.snapshot());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(probes.task_count(), 1, "active health probes one endpoint");

    // Reload WITHOUT the block: same endpoint, no active_health.
    let mut gw_without = gw_with.clone();
    gw_without.upstreams[0].active_health = None;
    state.compile_and_publish(&gw_without).unwrap();
    dp.refresh();
    probes.respawn(&dp.registry(), &state.snapshot());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        probes.task_count(),
        0,
        "removing active_health stops probes"
    );

    // Reload re-adding it against the same (carried) endpoint.
    state.compile_and_publish(&gw_with).unwrap();
    dp.refresh();
    probes.respawn(&dp.registry(), &state.snapshot());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(probes.task_count(), 1, "re-adding starts probing again");
    probes.abort_all();
}

// ------------------------------------------------- /healthz + /readyz edges

/// Query strings do not escape the reserved paths, and /healthz stays 200
/// even while the only upstream endpoint is fully ejected.
#[tokio::test]
async fn reserved_paths_survive_query_strings_and_total_ejection() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let bad = serve_switchable(Arc::new(AtomicBool::new(false))).await;
    let gw = base_gateway(
        fast_active(ProbeKind::Http, 2),
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port: bad,
            weight: 1,
        }],
    );
    let (dp, _probes) = launch(&gw);

    // Sole endpoint fully ejected: liveness still answers 200 (readiness
    // never depended on upstream health, liveness never will).
    assert!(wait_available(&dp, 0, false, Duration::from_millis(600)).await);
    let resp = proxy::handle(&dp, peer(), get("/healthz")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_of(resp).await.contains("\"code\":\"ok\""));

    // Query strings keep the reserved handling.
    for (path, want) in [
        ("/healthz?x=1", ("ok", StatusCode::OK)),
        ("/readyz?x=1", ("ready", StatusCode::OK)),
    ] {
        let resp = proxy::handle(&dp, peer(), get(path)).await;
        assert_eq!(resp.status(), want.1, "{path}");
        // DW-021: reserved bodies are aligned to the JSON envelope.
        assert!(
            body_of(resp)
                .await
                .contains(&format!("\"code\":\"{}\"", want.0)),
            "{path}"
        );
    }
}

// ------------------------------------------------------- post-fix regressions

use dwara_core::active::catch_unwind_future;
use dwara_core::health::{EndpointHealth, HealthParams};

/// Passive params whose ratio rule ejects at 3+ events, 50% failures; the
/// probe report form mirrors `report_params` (ratio disabled, huge volume).
fn window_purity_params() -> (HealthParams, HealthParams) {
    let passive = HealthParams {
        window_ms: 60_000,
        consecutive_failures: 100,
        failure_ratio: 0.5,
        failure_min_volume: 3,
        eject_ms: 60_000,
        half_open_probes: 1,
    };
    let probe_report = HealthParams {
        window_ms: passive.window_ms,
        consecutive_failures: 100,
        failure_ratio: 1.0,
        failure_min_volume: u32::MAX,
        eject_ms: passive.eject_ms,
        half_open_probes: passive.half_open_probes,
    };
    (passive, probe_report)
}

/// WINDOW PURITY (reviewer scenario): many probe FAILURES must not give the
/// passive ratio rule any volume. After N probe failures, ONE passive
/// failure (window volume 1 < 3) does not eject; the control tracker fed
/// three passive failures ejects — proving the ratio rule itself is armed.
#[test]
fn probe_failures_leave_the_ratio_window_empty_for_passive_evaluation() {
    let (passive, probe_report) = window_purity_params();
    let t = EndpointHealth::new();
    let mut now = 10_000u64;

    // N = 10 probe failures: had they entered the window (volume 10,
    // failures 10 >= 0.5 * 10, volume >= 3) the endpoint would have ejected.
    for _ in 0..10 {
        t.report_probe(&probe_report, now, true);
        now += 10;
    }
    assert!(
        t.is_available(now),
        "probe failures alone must not eject (no streak threshold reached)"
    );

    // ONE passive failure: the passive evaluation sees volume 1 < 3.
    t.report(&passive, now, true);
    now += 10;
    assert!(
        t.is_available(now),
        "one passive failure must not eject: probe failures gave the window no volume"
    );

    // Control on a fresh tracker: three passive failures DO eject.
    let c = EndpointHealth::new();
    for _ in 0..3 {
        c.report(&passive, now, true);
        now += 10;
    }
    assert!(
        !c.is_available(now),
        "control: 3 passive failures at ratio 0.5 / volume 3 must eject"
    );
}

/// The shared streak still works across sources (probe failures count toward
/// the PASSIVE consecutive threshold), pinning that window purity does not
/// come from ignoring the streak.
#[test]
fn probe_failures_do_count_toward_the_shared_consecutive_streak() {
    let (passive, probe_report) = window_purity_params();
    // Probe-report form with a low consecutive threshold, as the loop would
    // build for failure_threshold = 3.
    let probe_report = HealthParams {
        consecutive_failures: 3,
        ..probe_report
    };
    let t = EndpointHealth::new();
    let mut now = 10_000u64;
    for _ in 0..3 {
        t.report_probe(&probe_report, now, true);
        now += 10;
    }
    assert!(
        !t.is_available(now),
        "3 consecutive probe failures must eject via the shared streak"
    );
    let _ = passive;
}

/// A raw origin that answers each request with the given write schedule:
/// (bytes, delay-before-write) pairs, staged across separate TCP writes.
async fn staged_origin(schedule: Vec<(Vec<u8>, u64)>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let schedule = schedule.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                for (bytes, delay_ms) in &schedule {
                    tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
                    if stream.write_all(bytes).await.is_err() {
                        return;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

/// FRAGMENTED STATUS LINE: a peer that delivers "HTTP/1.1 " ... 30 ms ...
/// "20" ... 20 ms ... "0 OK\r\nContent-Length: 0\r\n\r\n" across three TCP
/// writes succeeds (pre-fix single-read classification would have failed);
/// a peer that sends a partial status line and then closes is a failure.
#[tokio::test]
async fn fragmented_status_line_succeeds_and_mid_line_close_fails() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let fragmented = staged_origin(vec![
        (b"HTTP/1.1 ".to_vec(), 0),
        (b"20".to_vec(), 30),
        (b"0 OK\r\nContent-Length: 0\r\n\r\n".to_vec(), 20),
    ])
    .await;
    assert!(
        probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            fragmented,
            "/healthz",
            Duration::from_secs(2),
            None
        )
        .await,
        "status line fragmented across writes must still classify as 2xx success"
    );

    let truncated = staged_origin(vec![
        (b"HTTP/1.1 ".to_vec(), 0),
        (b"2".to_vec(), 30),
        // connection closes here mid-status-line
    ])
    .await;
    assert!(
        !probe_once(
            ProbeKind::Http,
            None,
            "127.0.0.1",
            truncated,
            "/healthz",
            Duration::from_secs(2),
            None
        )
        .await,
        "peer closing mid-status-line must be a failed probe"
    );
}

/// PANIC CONTAINMENT (helper contract; the loop has no deterministic panic
/// injection hook): `catch_unwind_future` converts a panicking future —
/// including a panic raised AFTER an await point — into `Err` with the
/// payload recoverable, and passes normal output through as `Ok`.
#[tokio::test]
async fn catch_unwind_future_contains_panics_at_await_points() {
    let ok = catch_unwind_future(async { 7u32 }).await;
    assert_eq!(ok.expect("normal future resolves Ok"), 7);

    let immediate = catch_unwind_future(async { panic!("boom-immediate") }).await;
    let payload = immediate.expect_err("immediate panic must surface as Err");
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("boom-immediate"),
        "panic payload survives for logging"
    );

    // The loop-relevant case: the panic fires at an await point inside the
    // future (as a probe iteration would), after real awaits have yielded.
    let at_await = catch_unwind_future(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        panic!("boom-at-await");
    })
    .await;
    let payload = at_await.expect_err("panic at an await point must surface as Err");
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("boom-at-await")
    );
}
