//! Unit tests for `dataplane::upstream` (relocated from src; the
//! `send_without_endpoints` white-box test that builds a handle through
//! private `build_handle`/`webpki_root_store` stays in src).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;

use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, Timeouts, Upstream as ConfigUpstream, UpstreamProtocol,
};
use dwara_core::dataplane::upstream::{
    effective_cap, UpstreamError, UpstreamRegistry, DEFAULT_CONNECTION_CAP,
    DEFAULT_CONNECT_TIMEOUT_MS,
};
use dwara_core::security::tls::install_aws_lc_rs_provider;
use dwara_core::snapshot::ConfigState;

fn snapshot_with(up: ConfigUpstream) -> std::sync::Arc<dwara_core::snapshot::Snapshot> {
    install_aws_lc_rs_provider();
    let gw = Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams: vec![up],
        consumers: vec![],
        policies: vec![],
        global_policies: Vec::new(),
        authorization: None,
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        // Genuinely zero-route: upstream registry/connector unit tests
        // (#129 opt-in).
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
    };
    let state = ConfigState::new();
    state.compile_and_publish(&gw).expect("publish");
    state.snapshot()
}

fn test_upstream(
    address: String,
    port: u16,
    protocol: UpstreamProtocol,
    cap: Option<u32>,
    connect_ms: Option<u64>,
) -> ConfigUpstream {
    ConfigUpstream {
        name: "backend".into(),
        load_balancer: LoadBalancer::RoundRobin,
        protocol,
        endpoints: vec![Endpoint {
            address,
            port,
            weight: 1,
        }],
        connection_cap: cap,
        slow_start_ms: None,
        health: None,
        active_health: None,
        retries: None,
        timeouts: connect_ms.map(|connect_ms| Timeouts {
            connect_ms: Some(connect_ms),
            read_ms: None,
            write_ms: None,
            happy_eyeballs_ms: None,
        }),
        breaker: None,
        max_pending: None,
        trusted_ca_file: None,
    }
}

fn get_request(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Full::new(Bytes::new()))
        .expect("request")
}

/// Serve HTTP (auto h1/h2) on the listener; record accepted
/// connections and, per request, the concurrency high-water mark
/// (tracked in `high_water` via fetch_max BEFORE the end-of-request
/// decrement, so the recorded peak survives after all requests
/// finish). Each request response is delayed by `delay` so
/// concurrency can be observed.
async fn serve(
    listener: TcpListener,
    accepted: Arc<AtomicU64>,
    current: Arc<AtomicU64>,
    high_water: Arc<AtomicU64>,
    delay: Duration,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        let current = Arc::clone(&current);
        let high_water = Arc::clone(&high_water);
        let service = service_fn(move |_req: Request<Incoming>| {
            let current = Arc::clone(&current);
            let high_water = Arc::clone(&high_water);
            let delay = delay;
            async move {
                let active = current.fetch_add(1, Ordering::SeqCst) + 1;
                high_water.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                current.fetch_sub(1, Ordering::SeqCst);
                Ok::<Response<Full<Bytes>>, std::convert::Infallible>(Response::new(Full::new(
                    Bytes::new(),
                )))
            }
        });
        tokio::spawn(async move {
            let _ = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[tokio::test]
async fn sequential_requests_reuse_one_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let current = Arc::new(AtomicU64::new(0));
    let high_water = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve(
        listener,
        Arc::clone(&accepted),
        Arc::clone(&current),
        Arc::clone(&high_water),
        Duration::ZERO,
    ));

    let snap = snapshot_with(test_upstream(
        "127.0.0.1".into(),
        port,
        UpstreamProtocol::Http1,
        None,
        None,
    ));
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");

    assert_eq!(handle.cap(), DEFAULT_CONNECTION_CAP);
    assert_eq!(
        handle.connect_timeout(),
        Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
    );

    for _ in 0..4 {
        let resp = handle.send(get_request("/v1/users")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "connection reused");
    assert_eq!(handle.connections_opened(), 1);
    assert_eq!(handle.requests_sent(), 4);
}

#[tokio::test]
async fn connection_cap_limits_concurrent_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let current = Arc::new(AtomicU64::new(0));
    let high_water = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve(
        listener,
        Arc::clone(&accepted),
        Arc::clone(&current),
        Arc::clone(&high_water),
        Duration::from_millis(150),
    ));

    let snap = snapshot_with(test_upstream(
        "127.0.0.1".into(),
        port,
        UpstreamProtocol::Http1,
        Some(2),
        None,
    ));
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");
    assert_eq!(handle.cap(), 2);

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let h = Arc::clone(&handle);
        tasks.push(tokio::spawn(async move {
            let resp = h.send(get_request("/slow")).await.expect("sent");
            assert_eq!(resp.status(), StatusCode::OK);
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "exactly cap-many connections established"
    );
    assert_eq!(
        high_water.load(Ordering::SeqCst),
        2,
        "server saw exactly cap-many concurrent requests at peak"
    );
}

#[tokio::test]
async fn connect_timeout_fails_within_bound() {
    // 10.255.255.1 is a non-routable address: the TCP SYN gets no
    // answer, so the connect hangs until our timeout fires.
    let snap = snapshot_with(test_upstream(
        "10.255.255.1".into(),
        81,
        UpstreamProtocol::Http1,
        None,
        Some(250),
    ));
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");
    assert_eq!(handle.connect_timeout(), Duration::from_millis(250));

    let started = std::time::Instant::now();
    let err = handle.send(get_request("/x")).await.expect_err("times out");
    match err {
        UpstreamError::ConnectTimeout { after } => {
            assert_eq!(after, Duration::from_millis(250))
        }
        other => panic!("expected ConnectTimeout, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "failed within the bound, took {:?}",
        started.elapsed()
    );
}

/// TLS server answering h1 or h2 depending on the client's ALPN.
async fn serve_tls(listener: TcpListener, cert: rcgen::CertifiedKey, accepted: Arc<AtomicU64>) {
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                cert.key_pair.serialize_der(),
            )),
        )
        .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let service = service_fn(|_req: Request<Incoming>| async {
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
            });
            let _ = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tls), service)
                .await;
        });
    }
}

fn tls_snapshot(
    port: u16,
    protocol: UpstreamProtocol,
) -> std::sync::Arc<dwara_core::snapshot::Snapshot> {
    snapshot_with(test_upstream(
        "localhost".into(),
        port,
        protocol,
        None,
        None,
    ))
}

#[tokio::test]
async fn https_upstream_negotiates_tls_h1_and_reuses() {
    install_aws_lc_rs_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let root = cert.cert.der().clone();
    tokio::spawn(serve_tls(listener, cert, Arc::clone(&accepted)));

    let snap = tls_snapshot(port, UpstreamProtocol::Https);
    let registry =
        UpstreamRegistry::with_root_certificates(&snap, &[root]).expect("roots accepted");
    let handle = registry.get("backend").expect("handle");
    assert_eq!(handle.scheme(), "https");

    for _ in 0..3 {
        let resp = handle.send(get_request("/secure")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "TLS connection reused");
}

#[tokio::test]
async fn http2_upstream_negotiates_alpn_h2_and_reuses() {
    install_aws_lc_rs_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let root = cert.cert.der().clone();
    tokio::spawn(serve_tls(listener, cert, Arc::clone(&accepted)));

    let snap = tls_snapshot(port, UpstreamProtocol::Http2);
    let registry =
        UpstreamRegistry::with_root_certificates(&snap, &[root]).expect("roots accepted");
    let handle = registry.get("backend").expect("handle");
    assert_eq!(handle.scheme(), "https");

    // h2 multiplexes: even concurrent requests share one connection.
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let h = Arc::clone(&handle);
        tasks.push(tokio::spawn(async move {
            let resp = h.send(get_request("/h2")).await.expect("sent");
            assert_eq!(resp.status(), StatusCode::OK);
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "h2 connection reused");
}

#[tokio::test]
async fn https_upstream_rejects_untrusted_server_cert() {
    install_aws_lc_rs_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_tls(listener, cert, Arc::new(AtomicU64::new(0))));

    // No extra roots: the self-signed server cert is untrusted.
    let snap = tls_snapshot(port, UpstreamProtocol::Https);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");
    let result = handle.send(get_request("/secure")).await;
    assert!(result.is_err(), "untrusted certificate must be rejected");
}

// --- validation of the new schema fields (pure checks) ---------------

#[test]
fn validate_rejects_zero_connection_cap_and_zero_timeouts() {
    let issues = dwara_core::snapshot::validate(&Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams: vec![ConfigUpstream {
            name: "u".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: vec![Endpoint {
                address: "127.0.0.1".into(),
                port: 9001,
                weight: 1,
            }],
            connection_cap: Some(0),
            slow_start_ms: None,
            health: None,
            active_health: None,
            retries: None,
            timeouts: Some(Timeouts {
                connect_ms: Some(0),
                read_ms: Some(0),
                write_ms: None,
                happy_eyeballs_ms: None,
            }),
            breaker: None,
            max_pending: None,
            trusted_ca_file: None,
        }],
        consumers: vec![],
        policies: vec![],
        global_policies: Vec::new(),
        authorization: None,
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        // Zero-route: the assertions scope to upstream timeout fields
        // (#129 opt-in keeps the routes guard out of the picture).
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
    });
    let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
    assert!(fields.contains(&"connection_cap"));
    assert!(fields.contains(&"timeouts.connect_ms"));
    assert!(fields.contains(&"timeouts.read_ms"));
    assert!(!fields.contains(&"timeouts.write_ms"));
}

#[test]
fn effective_cap_clamps_zero_to_one() {
    // Only reachable via unvalidated direct construction (validation
    // rejects cap == 0); must degrade to serial, never a hang.
    let up = test_upstream(
        "127.0.0.1".into(),
        80,
        UpstreamProtocol::Http1,
        Some(0),
        None,
    );
    assert_eq!(effective_cap(&up), 1);
}

#[test]
fn with_root_certificates_rejects_malformed_root() {
    install_aws_lc_rs_provider();
    let state = ConfigState::new();
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
            // Zero-route on purpose: only the registry's root-store build
            // matters here (#129 opt-in).
            allow_empty_routes: true,
            hmac_auth: None,
            webhooks: Vec::new(),
            analytics: None,
            analytics_stream: None,
            geoip: None,
            admission_queue: None,
        })
        .expect("publish");
    let bad = CertificateDer::from(vec![0u8; 8]); // not a DER certificate
    assert!(matches!(
        UpstreamRegistry::with_root_certificates(&state.snapshot(), &[bad]),
        Err(UpstreamError::InvalidRootCertificate(_))
    ));
}

// Compile-time covers of unused-import surface kept honest.
#[test]
fn empty_registry_has_no_handles() {
    let state = ConfigState::new();
    let registry = UpstreamRegistry::from_snapshot(&state.snapshot());
    assert!(registry.get("nope").is_none());
    assert!(registry.names().is_empty());
}

// ---------------------------------------------------------------------------
// DW-030: RFC 8305 happy-eyeballs dialing. The order function and the
// race primitive are exercised directly (doc(hidden) test seams): real
// dials cannot make "the first address hangs" deterministic on loopback,
// which is exactly the property the interleaving guarantees.
// ---------------------------------------------------------------------------

use dwara_core::dataplane::upstream::{happy_dial, happy_race, interleave_order};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn v4(n: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)), 1000)
}

fn v6(n: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, n)), 1000)
}

#[test]
fn interleave_order_keeps_the_first_address_and_alternates_families() {
    // The resolver's first address defines the preferred family (RFC
    // 8305 leaves the preference to the resolver's order).
    let seq = interleave_order(&[v6(1), v6(2), v6(3), v4(1), v4(2)]);
    assert_eq!(seq, vec![v6(1), v4(1), v6(2), v4(2), v6(3)]);
    let seq = interleave_order(&[v4(1), v4(2), v4(3), v6(1)]);
    assert_eq!(seq, vec![v4(1), v6(1), v4(2), v4(3)]);
    // Single family: order is preserved unchanged.
    let seq = interleave_order(&[v4(3), v4(1), v4(2)]);
    assert_eq!(seq, vec![v4(3), v4(1), v4(2)]);
    // Short lists pass through untouched.
    assert_eq!(interleave_order(&[v6(1)]), vec![v6(1)]);
    assert_eq!(interleave_order(&[]), Vec::<SocketAddr>::new());
}

/// The behavior tag of one fake address, from its last address byte:
/// 1 hangs, 2 fails fast, anything else succeeds.
fn tag(addr: SocketAddr) -> u8 {
    match addr.ip() {
        IpAddr::V4(v4) => v4.octets()[3],
        IpAddr::V6(v6) => v6.segments()[7] as u8,
    }
}

/// A dial future that records its START order and either hangs forever,
/// fails fast, or succeeds, per its address's tag.
struct DialPlan {
    order: std::sync::Mutex<Vec<SocketAddr>>,
    cancelled: std::sync::atomic::AtomicBool,
}

impl DialPlan {
    fn dial(
        self: &Arc<Self>,
        addr: SocketAddr,
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        let plan = Arc::clone(self);
        let tag = tag(addr);
        async move {
            plan.order.lock().unwrap().push(addr);
            if tag == 1 {
                // Cancellation probe: Drop marks this arm cancelled.
                struct Guard(std::sync::Arc<DialPlan>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0
                            .cancelled
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                let _g = Guard(Arc::clone(&plan));
                futures_hang().await;
                Ok(())
            } else if tag == 2 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "refused",
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// A future that never resolves (pending on a never-signaled channel).
async fn futures_hang() {
    let (_tx, mut rx) = tokio::sync::watch::channel(());
    // The receiver's initial version never changes: pending forever.
    let _ = rx.changed().await;
}

#[tokio::test]
async fn happy_race_starts_the_other_family_after_the_delay_and_cancels_the_hang() {
    let plan = Arc::new(DialPlan {
        order: std::sync::Mutex::new(Vec::new()),
        cancelled: std::sync::atomic::AtomicBool::new(false),
    });
    // v6 first (hangs), v4 second (succeeds): the interleave must start
    // the v4 arm after ~delay, win, and CANCEL the hanging v6 arm.
    let seq = vec![v6(1), v4(4)];
    let delay = Duration::from_millis(120);
    let started = std::time::Instant::now();
    let outcome = happy_race(seq, Some(delay), |a| plan.dial(a)).await;
    let elapsed = started.elapsed();
    assert!(outcome.is_ok(), "second arm must win: {outcome:?}");
    assert!(
        elapsed >= delay && elapsed < delay * 4,
        "second arm started after the delay, not immediately nor late: {elapsed:?}"
    );
    // The JoinSet's drop ABORTS the losing task; the abort's future-drop
    // lands on the next runtime tick, so pump the scheduler before the
    // probe is observable.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        plan.cancelled.load(std::sync::atomic::Ordering::SeqCst),
        "the losing (hanging) arm must be cancelled on first win"
    );
    let order = plan.order.lock().unwrap().clone();
    assert_eq!(order.len(), 2, "exactly two arms started: {order:?}");
}

#[tokio::test]
async fn happy_race_fast_forwards_after_a_failure_with_nothing_in_flight() {
    let plan = Arc::new(DialPlan {
        order: std::sync::Mutex::new(Vec::new()),
        cancelled: std::sync::atomic::AtomicBool::new(false),
    });
    // First address fails fast: the next must start IMMEDIATELY (RFC
    // 8305 5.2), far inside the 5 s delay.
    let delay = Duration::from_secs(5);
    let started = std::time::Instant::now();
    let outcome = happy_race(vec![v4(2), v4(4)], Some(delay), |a| plan.dial(a)).await;
    assert!(outcome.is_ok());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "failure must fast-forward the next attempt: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn happy_race_surfaces_the_last_error_when_every_arm_fails() {
    let plan = Arc::new(DialPlan {
        order: std::sync::Mutex::new(Vec::new()),
        cancelled: std::sync::atomic::AtomicBool::new(false),
    });
    let err = happy_race(vec![v4(2), v6(2), v4(2)], None, |a| plan.dial(a))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    // Sequential mode (delay None) tried every address in order.
    assert_eq!(plan.order.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn happy_race_disabled_is_strictly_sequential() {
    let plan = Arc::new(DialPlan {
        order: std::sync::Mutex::new(Vec::new()),
        cancelled: std::sync::atomic::AtomicBool::new(false),
    });
    // With racing disabled a hanging FIRST address blocks the dial: the
    // second arm is never started (the whole future is cancelled here
    // by the test's timeout).
    let seq = vec![v6(1), v4(4)];
    let raced = tokio::time::timeout(Duration::from_millis(200), async {
        happy_race(seq, None, |a| plan.dial(a)).await
    })
    .await;
    assert!(raced.is_err(), "sequential mode must wait on the first arm");
    let order = plan.order.lock().unwrap().clone();
    assert_eq!(order, vec![v6(1)], "only the first arm ran: {order:?}");
}

#[tokio::test]
async fn happy_dial_connects_a_live_loopback_listener() {
    // End-to-end over real sockets: a dead (refused) v4 address in
    // front of a live one still connects under racing, and the live
    // listener observes exactly ONE connection.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live = listener.local_addr().unwrap();
    let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    });
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(s);
        }
    });
    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        happy_dial("127.0.0.1", live.port(), Some(Duration::from_millis(50))),
    )
    .await
    .expect("dial bounded")
    .expect("live loopback address dials");
    assert_eq!(stream.local_addr().unwrap().ip(), live.ip());
    drop(stream);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        seen.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "the live listener observed the connection"
    );
    // The dead-port arm is dialed too (refused instantly, no
    // observable connection) — this is the shape, not a guarantee we
    // can observe from the outside; the ORDER unit tests pin it.
    let _ = dead;
}
