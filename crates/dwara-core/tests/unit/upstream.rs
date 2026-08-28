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
