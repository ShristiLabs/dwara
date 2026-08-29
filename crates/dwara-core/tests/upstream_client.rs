//! Integration tests for DW-008 upstream client pools (`upstream.rs`).
//!
//! Complements the in-module unit tests with local TCP/TLS servers:
//! pool sharing semantics, connection-cap edge cases (including
//! permit-release on error and non-starvation with idle connections),
//! connect timeout during the TLS handshake, ALPN mismatch, expired
//! server certificates, and schema validation for the new fields.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use support::*;

use bytes::Bytes;
use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, Timeouts, Upstream as ConfigUpstream, UpstreamProtocol,
};
use dwara_core::snapshot::ConfigState;
use dwara_core::upstream::{
    UpstreamError, UpstreamRegistry, DEFAULT_CONNECTION_CAP, DEFAULT_CONNECT_TIMEOUT_MS,
};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

/// Upper bound for any single send in these tests; generous enough to be
/// flake-free on a loaded CI runner, small enough to catch hangs.
const SEND_BOUND: Duration = Duration::from_secs(8);

fn gateway_with(upstreams: Vec<ConfigUpstream>) -> Arc<dwara_core::snapshot::Snapshot> {
    dwara_core::tls::install_aws_lc_rs_provider();
    let gw = Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams,
        consumers: vec![],
        policies: vec![],
        global_policies: Vec::new(),
        authorization: None,
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        // Genuinely zero-route: upstream connector/pool behavior, not
        // routing (#129 opt-in).
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
    };
    let state = ConfigState::new();
    state.compile_and_publish(&gw).expect("publish");
    state.snapshot()
}

fn upstream(
    name: &str,
    address: &str,
    port: u16,
    protocol: UpstreamProtocol,
    cap: Option<u32>,
    connect_ms: Option<u64>,
) -> ConfigUpstream {
    ConfigUpstream {
        name: name.into(),
        load_balancer: LoadBalancer::RoundRobin,
        protocol,
        endpoints: vec![Endpoint {
            address: address.into(),
            port,
            weight: 1,
        }],
        connection_cap: cap,
        slow_start_ms: None,
        health: None,
        active_health: None,
        retries: None,
        timeouts: connect_ms.map(|connect_ms| Timeouts {
            happy_eyeballs_ms: None,
            connect_ms: Some(connect_ms),
            read_ms: None,
            write_ms: None,
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

/// Plaintext auto (h1/h2) server: counts accepted connections, tracks the
/// request-concurrency high-water mark, delays each response by `delay`.
async fn serve(
    listener: TcpListener,
    accepted: Arc<AtomicU64>,
    max_concurrent: Arc<AtomicU64>,
    delay: Duration,
) {
    // Live request counter; `max_concurrent` is the never-decremented peak.
    let current = Arc::new(AtomicU64::new(0));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        let current = Arc::clone(&current);
        let peak = Arc::clone(&max_concurrent);
        let service = service_fn(move |_req: Request<Incoming>| {
            let current = Arc::clone(&current);
            let max_concurrent = Arc::clone(&peak);
            let delay = delay;
            async move {
                let active = current.fetch_add(1, Ordering::SeqCst) + 1;
                max_concurrent.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                current.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
            }
        });
        tokio::spawn(async move {
            let _ = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// Server that drops the FIRST accepted connection (simulating an upstream
/// accepting TCP then immediately resetting), then serves normally.
async fn serve_drop_first(listener: TcpListener, accepted: Arc<AtomicU64>) {
    let mut first = true;
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        if first {
            first = false;
            drop(stream); // RST/FIN before any HTTP bytes
            continue;
        }
        let service = service_fn(|_req: Request<Incoming>| async {
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
        });
        tokio::spawn(async move {
            let _ = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// TLS server with configurable ALPN offer.
async fn serve_tls_alpn(
    listener: TcpListener,
    cert: rcgen::CertifiedKey,
    alpn: &'static [&'static [u8]],
    accepted: Arc<AtomicU64>,
) {
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                cert.key_pair.serialize_der(),
            )),
        )
        .expect("server cert");
    server_cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
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

/// TCP server that accepts connections but never speaks: TLS-handshake
/// stall (and, for plaintext, an HTTP stall).
async fn serve_stall(listener: TcpListener, accepted: Arc<AtomicU64>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        // Hold the stream open forever without reading or writing.
        tokio::spawn(async move {
            let _stream = stream;
            std::future::pending::<()>().await;
        });
    }
}

async fn bound_send(
    handle: &dwara_core::upstream::UpstreamHandle,
    path: &str,
) -> Result<Response<dwara_core::upstream::UpstreamBody>, UpstreamError> {
    match tokio::time::timeout(SEND_BOUND, handle.send(get_request(path))).await {
        Ok(r) => r,
        Err(_) => panic!(
            "send to {} did not complete within {SEND_BOUND:?}",
            handle.name()
        ),
    }
}

// --- 1. POOL SHARING -------------------------------------------------

#[tokio::test]
async fn different_upstreams_use_independent_pools() {
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port1 = l1.local_addr().unwrap().port();
    let port2 = l2.local_addr().unwrap().port();
    let acc1 = Arc::new(AtomicU64::new(0));
    let acc2 = Arc::new(AtomicU64::new(0));
    let zero = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve(
        l1,
        Arc::clone(&acc1),
        Arc::clone(&zero),
        Duration::ZERO,
    ));
    tokio::spawn(serve(l2, Arc::clone(&acc2), zero, Duration::ZERO));

    let snap = gateway_with(vec![
        upstream(
            "alpha",
            "127.0.0.1",
            port1,
            UpstreamProtocol::Http1,
            None,
            None,
        ),
        upstream(
            "beta",
            "127.0.0.1",
            port2,
            UpstreamProtocol::Http1,
            None,
            None,
        ),
    ]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    assert_eq!(registry.names(), vec!["alpha", "beta"]);

    for name in ["alpha", "beta"] {
        let handle = registry.get(name).expect("handle");
        for _ in 0..3 {
            let resp = bound_send(&handle, "/x").await.expect("sent");
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }
    // Each upstream pooled onto its own server: one connection per server.
    assert_eq!(acc1.load(Ordering::SeqCst), 1, "alpha pool reused one conn");
    assert_eq!(acc2.load(Ordering::SeqCst), 1, "beta pool reused one conn");
    assert_eq!(
        registry.get("alpha").unwrap().connections_opened(),
        1,
        "no cross-upstream connection sharing"
    );
}

#[tokio::test]
async fn same_handle_from_two_tasks_shares_one_pool() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let zero = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve(listener, Arc::clone(&accepted), zero, Duration::ZERO));

    let snap = gateway_with(vec![upstream(
        "backend",
        "127.0.0.1",
        port,
        UpstreamProtocol::Http1,
        None,
        None,
    )]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");

    let h1 = Arc::clone(&handle);
    let t1 = tokio::spawn(async move {
        let resp = bound_send(&h1, "/a").await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
    });
    t1.await.expect("task1");
    // Sequential send from a DIFFERENT task must land on the same pool.
    let h2 = Arc::clone(&handle);
    let t2 = tokio::spawn(async move {
        let resp = bound_send(&h2, "/b").await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
    });
    t2.await.expect("task2");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "shared pool, one connection"
    );
    assert_eq!(handle.connections_opened(), 1);
    assert_eq!(handle.requests_sent(), 2);
}

// --- 2. CAP SEMANTICS -------------------------------------------------

#[tokio::test]
async fn cap_one_serializes_concurrent_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let max_concurrent = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve(
        listener,
        Arc::clone(&accepted),
        Arc::clone(&max_concurrent),
        Duration::from_millis(100),
    ));

    let snap = gateway_with(vec![upstream(
        "backend",
        "127.0.0.1",
        port,
        UpstreamProtocol::Http1,
        Some(1),
        None,
    )]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");
    assert_eq!(handle.cap(), 1);

    let mut tasks = Vec::new();
    for i in 0..3 {
        let h = Arc::clone(&handle);
        tasks.push(tokio::spawn(async move {
            let resp = bound_send(&h, "/slow").await.expect("sent");
            assert_eq!(resp.status(), StatusCode::OK);
            i
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }
    assert_eq!(
        max_concurrent.load(Ordering::SeqCst),
        1,
        "server never saw concurrent requests with cap=1"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "one connection sufficed"
    );
}

#[tokio::test]
async fn idle_connection_does_not_starve_later_concurrent_sends() {
    // Sequential requests leave ONE idle pooled connection (which holds a
    // cap permit). A subsequent concurrent burst of cap-size must still
    // complete promptly: pool reuse does not consume permits, so a permit
    // leak (or idle-holds-cap starvation) would make this time out.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let max_concurrent = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve(
        listener,
        Arc::clone(&accepted),
        Arc::clone(&max_concurrent),
        Duration::from_millis(80),
    ));

    let snap = gateway_with(vec![upstream(
        "backend",
        "127.0.0.1",
        port,
        UpstreamProtocol::Http1,
        Some(4),
        None,
    )]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");

    for _ in 0..4 {
        let resp = bound_send(&handle, "/warm").await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "warmup reused one conn");

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let h = Arc::clone(&handle);
        tasks.push(tokio::spawn(async move {
            let resp = bound_send(&h, "/burst").await.expect("sent");
            assert_eq!(resp.status(), StatusCode::OK);
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }
    assert!(
        accepted.load(Ordering::SeqCst) <= 4,
        "never exceeded cap-many connections, got {}",
        accepted.load(Ordering::SeqCst)
    );
    assert!(
        max_concurrent.load(Ordering::SeqCst) <= 4,
        "server concurrency within cap"
    );
}

#[tokio::test]
async fn permit_released_when_connection_errors() {
    // The server drops the first TCP connection before speaking HTTP. The
    // failed connection's permit must be released so a later connect (same
    // cap slot) still succeeds; a leaked permit would starve the retry
    // with cap=1.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve_drop_first(listener, Arc::clone(&accepted)));

    let snap = gateway_with(vec![upstream(
        "backend",
        "127.0.0.1",
        port,
        UpstreamProtocol::Http1,
        Some(1),
        None,
    )]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");

    let first = bound_send(&handle, "/doomed").await;
    assert!(first.is_err(), "reset connection must fail the request");

    let resp = bound_send(&handle, "/retry")
        .await
        .expect("permit freed after errored connection");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

// --- 3. CONNECT TIMEOUT ------------------------------------------------

#[tokio::test]
async fn connect_timeout_fires_during_stalled_tls_handshake() {
    // TCP accepted, TLS handshake never progresses: the timeout must wrap
    // dial AND handshake and surface ConnectTimeout.
    dwara_core::tls::install_aws_lc_rs_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve_stall(listener, Arc::clone(&accepted)));

    let snap = gateway_with(vec![upstream(
        "backend",
        "localhost",
        port,
        UpstreamProtocol::Https,
        None,
        Some(300),
    )]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");

    let started = std::time::Instant::now();
    let err = bound_send(&handle, "/stalled")
        .await
        .expect_err("must time out");
    match err {
        UpstreamError::ConnectTimeout { after } => {
            assert_eq!(after, Duration::from_millis(300));
        }
        other => panic!("expected ConnectTimeout, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "timed out promptly, took {:?}",
        started.elapsed()
    );
    assert!(accepted.load(Ordering::SeqCst) >= 1, "TCP was accepted");
    assert_eq!(handle.connections_opened(), 0, "no connection established");
}

#[tokio::test]
async fn default_connect_timeout_is_five_seconds() {
    dwara_core::tls::install_aws_lc_rs_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve_stall(listener, Arc::new(AtomicU64::new(0))));

    let snap = gateway_with(vec![upstream(
        "backend",
        "localhost",
        port,
        UpstreamProtocol::Https,
        None,
        None, // no timeouts block: default applies
    )]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");
    assert_eq!(
        handle.connect_timeout(),
        Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
    );

    let started = std::time::Instant::now();
    let err = bound_send(&handle, "/stalled")
        .await
        .expect_err("must time out");
    match err {
        UpstreamError::ConnectTimeout { after } => {
            assert_eq!(after, Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS));
        }
        other => panic!("expected ConnectTimeout, got {other:?}"),
    }
    assert!(
        started.elapsed() >= Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
        "default 5s honored, fired after {:?}",
        started.elapsed()
    );
}

// --- 4. TLS --------------------------------------------------------------

#[tokio::test]
async fn http2_client_fails_cleanly_on_alpn_mismatch() {
    // Server offers only http/1.1; client is locked to h2 ALPN. rustls
    // fails the handshake (no application protocol) — the client must get
    // an error, not a hang.
    dwara_core::tls::install_aws_lc_rs_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let root = cert.cert.der().clone();
    tokio::spawn(serve_tls_alpn(
        listener,
        cert,
        &[b"http/1.1"],
        Arc::clone(&accepted),
    ));

    let snap = gateway_with(vec![upstream(
        "backend",
        "localhost",
        port,
        UpstreamProtocol::Http2,
        None,
        None,
    )]);
    let registry =
        UpstreamRegistry::with_root_certificates(&snap, &[root]).expect("roots accepted");
    let handle = registry.get("backend").expect("handle");

    let started = std::time::Instant::now();
    let result = bound_send(&handle, "/mismatch").await;
    assert!(result.is_err(), "ALPN mismatch must fail the request");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "failed fast, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn expired_server_certificate_is_rejected() {
    dwara_core::tls::install_aws_lc_rs_provider();
    // Self-signed cert with validity entirely in the past. rcgen exposes
    // date_time_ymd so we do not need the `time` crate as a dependency.
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let certified = rcgen::CertifiedKey { cert, key_pair };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = certified.cert.der().clone();
    tokio::spawn(serve_tls_alpn(
        listener,
        certified,
        &[b"h2", b"http/1.1"],
        Arc::new(AtomicU64::new(0)),
    ));

    let snap = gateway_with(vec![upstream(
        "backend",
        "localhost",
        port,
        UpstreamProtocol::Https,
        None,
        None,
    )]);
    // Even with the cert itself trusted as a root, expiry must reject.
    let registry =
        UpstreamRegistry::with_root_certificates(&snap, &[root]).expect("roots accepted");
    let handle = registry.get("backend").expect("handle");

    let result = bound_send(&handle, "/expired").await;
    assert!(
        result.is_err(),
        "expired server certificate must be rejected"
    );
    assert_eq!(handle.connections_opened(), 0, "TLS never established");
}

// --- 5. VALIDATION ---------------------------------------------------------

#[test]
fn validate_rejects_zero_in_each_timeout_field_independently() {
    // One issue at a time so each field's zero-check fires on its own.
    let cases: [(&str, Timeouts); 3] = [
        (
            "timeouts.connect_ms",
            Timeouts {
                happy_eyeballs_ms: None,
                connect_ms: Some(0),
                read_ms: Some(50),
                write_ms: Some(50),
            },
        ),
        (
            "timeouts.read_ms",
            Timeouts {
                happy_eyeballs_ms: None,
                connect_ms: Some(50),
                read_ms: Some(0),
                write_ms: Some(50),
            },
        ),
        (
            "timeouts.write_ms",
            Timeouts {
                happy_eyeballs_ms: None,
                connect_ms: Some(50),
                read_ms: Some(50),
                write_ms: Some(0),
            },
        ),
    ];
    for (field, timeouts) in cases {
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
                connection_cap: Some(8),
                slow_start_ms: None,
                health: None,
                active_health: None,
                retries: None,
                timeouts: Some(timeouts),
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
            // Zero-route: the exact-count assertion scopes to the one
            // timeout field under test (#129 opt-in).
            allow_empty_routes: true,
            hmac_auth: None,
            webhooks: Vec::new(),
        });
        let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
        assert_eq!(fields, vec![field], "exactly {field} flagged");
    }
}

#[test]
fn validate_accepts_positive_connection_cap_and_timeouts() {
    let issues = dwara_core::snapshot::validate(&Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams: vec![ConfigUpstream {
            name: "u".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http2,
            endpoints: vec![Endpoint {
                address: "127.0.0.1".into(),
                port: 9001,
                weight: 1,
            }],
            connection_cap: Some(1),
            slow_start_ms: None,
            health: None,
            active_health: None,
            retries: None,
            timeouts: Some(Timeouts {
                happy_eyeballs_ms: None,
                connect_ms: Some(1),
                read_ms: Some(1),
                write_ms: Some(1),
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
        // Zero-route (#129 opt-in): must validate clean, so the routes
        // guard itself must not fire here.
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
    });
    assert!(issues.is_empty(), "positive values valid: {issues:?}");
}

#[tokio::test]
async fn absent_fields_default_to_cap_64_and_connect_5000() {
    let snap = gateway_with(vec![upstream(
        "backend",
        "127.0.0.1",
        9, // never dialed in this test
        UpstreamProtocol::Http1,
        None,
        None,
    )]);
    let registry = UpstreamRegistry::from_snapshot(&snap);
    let handle = registry.get("backend").expect("handle");
    assert_eq!(handle.cap(), DEFAULT_CONNECTION_CAP);
    assert_eq!(
        handle.connect_timeout(),
        Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
    );
}

// ---------------------------------------------------------------------------
// DW-030: happy-eyeballs upstream dialing (RFC 8305). A dual-stack
// hostname endpoint ("localhost" resolves to ::1 AND 127.0.0.1) must
// reach a backend listening on ONE family: whichever arm of the
// interleave finds it wins. The strict family-alternation order and the
// delay/cancellation semantics are pinned deterministically by the
// happy_race/interleave_order unit tests (tests/unit/upstream.rs); these
// end-to-end cases pin that the dial composes with the pool, the connect
// timeout, and real getaddrinfo resolution.
// ---------------------------------------------------------------------------

async fn happy_yaml(endpoint_address: &str, backend_port: u16, happy: Option<&str>) -> String {
    let timeouts = match happy {
        Some(ms) => format!("  timeouts:\n    happy_eyeballs_ms: {ms}\n"),
        None => String::new(),
    };
    format!(
        "routes:\n\
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
         \x20   - address: {endpoint_address}\n\
         \x20     port: {backend_port}\n{timeouts}"
    )
}

#[tokio::test]
async fn dual_stack_hostname_reaches_a_v4_only_backend_under_racing() {
    // ::1 is attempted first on hosts that prefer v6 (macOS default) and
    // refused fast; the interleaved v4 arm wins. On v4-first hosts the
    // first arm simply wins. Either way: ONE success, one upstream hit.
    let (port, count) = support_like_backend().await;
    let dp = dwara_core::proxy::DataPlane::new(state_from(
        &happy_yaml("localhost", port, Some("250")).await,
    ));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::get(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dual_stack_hostname_reaches_a_v4_only_backend_with_racing_disabled() {
    // happy_eyeballs_ms: 0 = strict resolver order: the refused ::1
    // fails fast and the sequential v4 arm still connects.
    let (port, count) = support_like_backend().await;
    let dp = dwara_core::proxy::DataPlane::new(state_from(
        &happy_yaml("localhost", port, Some("0")).await,
    ));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::get(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn v6_loopback_backend_is_reached_by_the_dual_stack_hostname() {
    // The v6 arm can win too: a backend on [::1] is reached through the
    // same hostname endpoint (on v4-first hosts the refused v4 arm fails
    // fast and v6 wins; on v6-first hosts the first arm wins).
    let listener = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("::1 bind");
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        hyper::service::service_fn(move |_req: Request<Incoming>| {
                            let counter = Arc::clone(&counter);
                            async move {
                                counter.fetch_add(1, Ordering::SeqCst);
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::new(),
                                )))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    let dp =
        dwara_core::proxy::DataPlane::new(state_from(&happy_yaml("localhost", port, None).await));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::get(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

/// Plain counting HTTP backend (the support module's shape, local to
/// this suite because the shared one binds v4 only by design).
async fn support_like_backend() -> (u16, Arc<AtomicU64>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        hyper::service::service_fn(move |_req: Request<Incoming>| {
                            let counter = Arc::clone(&counter);
                            async move {
                                counter.fetch_add(1, Ordering::SeqCst);
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::new(),
                                )))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, count)
}
