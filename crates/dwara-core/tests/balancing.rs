//! Load-balancing integration tests (DW-011).
//!
//! End-to-end: real HTTP through the proxy dataplane against recording
//! backends — weighted round-robin distribution and interleave, least-conn
//! avoiding a slow backend, ip_hash stickiness per client IP (raw sockets
//! bound to distinct loopback source IPs), slow-start ramping, hot weight
//! swaps with no dropped requests and no leaked in-flight counters, and
//! Host rewritten to the PICKED endpoint's authority.
//!
//! Unit-level here (the dev suite in src/balance.rs covers the core
//! algorithms): ketama determinism across builds, weight-skew remap
//! minimality, ip_hash key-less fallback equaling the WRR sequence,
//! random-2 tie-break pinning, single-endpoint degeneracy, passthrough
//! resolution now following the balancer, and slow_start_ms validation.

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dwara_core::balance::UpstreamLb;
use dwara_core::config::{parse_gateway, Endpoint, ListenerTls, LoadBalancer, SniRoute, TlsMode};
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use dwara_core::tls::resolve_passthrough;
use dwara_core::upstream::UpstreamRegistry;
use http_body_util::Full;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

mod support;

use support::{body_text, h1_client, state_from, uri};

// --- infrastructure (mirrors tests/proxy.rs) -----------------------------

async fn spawn_gateway(dp: Arc<DataPlane>) -> u16 {
    spawn_gateway_on(dp, "127.0.0.1").await
}

/// Gateway on a bare bind IP with an ephemeral port; returns the port
/// (the caller already knows the host it asked for).
async fn spawn_gateway_on(dp: Arc<DataPlane>, bind: &str) -> u16 {
    support::spawn_gateway_on(dp, &format!("{bind}:0")).await.1
}

/// Recording backend: increments `hits` and answers
/// `id=<id>|host=<observed Host>` (optionally sleeping first).
async fn spawn_recording_backend(id: usize, hits: Arc<AtomicU64>, delay_ms: u64) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let hits = Arc::clone(&hits);
                            async move {
                                if delay_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
                                hits.fetch_add(1, Ordering::Relaxed);
                                let host = req
                                    .headers()
                                    .get(HOST)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("-")
                                    .to_string();
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                                    "id={id}|host={host}"
                                )))))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    port
}

async fn spawn_backends(specs: &[(u64, u64)]) -> (Vec<Arc<AtomicU64>>, Vec<u16>) {
    let mut counters = Vec::new();
    let mut ports = Vec::new();
    for (i, &(id, delay)) in specs.iter().enumerate() {
        let hits = Arc::new(AtomicU64::new(0));
        let port = spawn_recording_backend(id as usize, Arc::clone(&hits), delay).await;
        counters.push(hits);
        ports.push(port);
        let _ = i;
    }
    (counters, ports)
}

/// YAML: route everything to upstream `up` with the given algorithm,
/// endpoint weights, and optional slow_start_ms.
fn lb_yaml(algorithm: &str, weights: &[u32], ports: &[u16], slow_start_ms: Option<u64>) -> String {
    let mut eps = String::new();
    for (w, p) in weights.iter().zip(ports) {
        eps.push_str(&format!(
            "  - address: 127.0.0.1\n    port: {p}\n    weight: {w}\n"
        ));
    }
    let slow = match slow_start_ms {
        Some(ms) => format!("  slow_start_ms: {ms}\n"),
        None => String::new(),
    };
    format!(
        "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: regex\n\
         \x20     value: /.*\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 load_balancer: {algorithm}\n\
         \x20 endpoints:\n\
         {eps}\
         {slow}"
    )
}

/// One raw HTTP/1.1 request from a chosen loopback source IP (ip_hash keys
/// on the connection peer, which the hyper client cannot pin). Returns the
/// response body text.
async fn raw_get_from(source_ip: &str, port: u16, path: &str) -> String {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(format!("{source_ip}:0").parse().unwrap())
        .unwrap();
    let stream = sock
        .connect(format!("127.0.0.1:{port}").parse().unwrap())
        .await
        .unwrap();
    raw_get(stream, path).await
}

/// IPv6-loopback variant: source IP ::1 (a distinct ip_hash key).
async fn raw_get_v6(port: u16, path: &str) -> String {
    let sock = tokio::net::TcpSocket::new_v6().unwrap();
    let stream = sock
        .connect(format!("[::1]:{port}").parse().unwrap())
        .await
        .unwrap();
    raw_get(stream, path).await
}

async fn raw_get(stream: TcpStream, path: &str) -> String {
    let (r, mut w) = tokio::io::split(stream);
    let mut r = BufReader::new(r);
    w.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: gw.test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    w.flush().await.unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    body.trim_end_matches('\0').to_string()
}

// --- end-to-end: weighted round-robin -------------------------------------

#[tokio::test]
async fn round_robin_weights_2_1_1_distribute_and_interleave_over_real_http() {
    let (hits, ports) = spawn_backends(&[(0, 0), (1, 0), (2, 0)]).await;
    let dp = DataPlane::new(state_from(&lb_yaml(
        "round_robin",
        &[2, 1, 1],
        &ports,
        None,
    )));
    let port = spawn_gateway(dp).await;

    let client = h1_client();
    let mut order = Vec::new();
    for _ in 0..200 {
        let body = body_text(client.get(uri(port, "/x")).await.unwrap().into_body()).await;
        let (id, host) = parse_id_host(&body);
        order.push(id);
        // Host must be the PICKED endpoint's authority, never the first
        // endpoint's (checked per request, not just in aggregate).
        assert_eq!(host, format!("127.0.0.1:{}", ports[id]), "host for {body}");
    }
    let counts: Vec<u64> = hits.iter().map(|h| h.load(Ordering::Relaxed)).collect();
    assert_eq!(counts, vec![100, 50, 50], "smooth WRR is exact per period");
    // Deterministic interleave: weights {2,1,1} produce period a b c a.
    assert_eq!(&order[0..4], &[0, 1, 2, 0]);
    assert_eq!(&order[4..8], &[0, 1, 2, 0]);
}

fn parse_id_host(body: &str) -> (usize, String) {
    let id = body.split('|').next().unwrap().strip_prefix("id=").unwrap();
    let host = body
        .split_once("host=")
        .map(|(_, h)| h.to_string())
        .unwrap_or_default();
    (id.parse().unwrap(), host)
}

// --- end-to-end: least_requests --------------------------------------------

#[tokio::test]
async fn least_requests_sends_fewest_requests_to_the_slow_backend() {
    // Backend 0 sleeps 150ms; 1 and 2 answer immediately.
    let (hits, ports) = spawn_backends(&[(0, 150), (1, 0), (2, 0)]).await;
    let dp = DataPlane::new(state_from(&lb_yaml(
        "least_requests",
        &[1, 1, 1],
        &ports,
        None,
    )));
    let port = spawn_gateway(dp).await;

    let client = h1_client();
    let mut tasks = Vec::new();
    for _ in 0..18 {
        let c = client.clone();
        tasks.push(tokio::spawn(async move {
            let resp = c.get(uri(port, "/x")).await.unwrap();
            assert_eq!(resp.status(), hyper::StatusCode::OK);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let counts: Vec<u64> = hits.iter().map(|h| h.load(Ordering::Relaxed)).collect();
    assert_eq!(counts.iter().sum::<u64>(), 18);
    assert!(
        counts[0] <= 6,
        "slow backend got {counts:?}; least-conn should avoid it"
    );
    assert!(counts[1] >= 5, "fast backends absorb the load: {counts:?}");
    assert!(counts[2] >= 5, "fast backends absorb the load: {counts:?}");
}

// --- end-to-end: ip_hash ----------------------------------------------------

#[tokio::test]
async fn ip_hash_same_client_ip_is_sticky_across_connections() {
    let (hits, ports) = spawn_backends(&[(0, 0), (1, 0), (2, 0)]).await;
    let dp = DataPlane::new(state_from(&lb_yaml("ip_hash", &[1, 1, 1], &ports, None)));
    let port = spawn_gateway(dp).await;

    // 50 fresh connections, all from 127.0.0.1: every request must land on
    // the SAME backend (stickiness), and it need not be index 0.
    let mut owners = std::collections::HashSet::new();
    for _ in 0..50 {
        let body = raw_get_from("127.0.0.1", port, "/x").await;
        owners.insert(parse_id_host(&body).0);
    }
    assert_eq!(owners.len(), 1, "one client IP, one backend: {owners:?}");
    let counts: Vec<u64> = hits.iter().map(|h| h.load(Ordering::Relaxed)).collect();
    assert_eq!(counts.iter().sum::<u64>(), 50);
}

#[tokio::test]
async fn ip_hash_distinct_client_ips_spread_across_backends() {
    // macOS here refuses binding arbitrary 127/8 source addresses, so the
    // two client IPs are the two loopback families: 127.0.0.1 (v4) and ::1
    // (v6), each dialing its own listener on the SAME dataplane. The ring
    // depends on the ephemeral backend ports, so first deterministically
    // pick backend ports whose ring separates the two keys (checked via
    // the public UpstreamLb API), then assert it end-to-end.
    let (hits, ports) = loop {
        let (hits, ports) = spawn_backends(&[(0, 0), (1, 0), (2, 0)]).await;
        let eps: Vec<Endpoint> = ports
            .iter()
            .map(|&p| Endpoint {
                address: "127.0.0.1".into(),
                port: p,
                weight: 1,
            })
            .collect();
        let probe = UpstreamLb::new(&eps, LoadBalancer::IpHash, Duration::ZERO);
        let a = probe.pick(Some("127.0.0.1")).unwrap();
        let b = probe.pick(Some("::1")).unwrap();
        if a != b {
            break (hits, ports);
        }
    };
    let dp = DataPlane::new(state_from(&lb_yaml("ip_hash", &[1, 1, 1], &ports, None)));
    let v4 = spawn_gateway_on(Arc::clone(&dp), "127.0.0.1").await;
    let v6 = spawn_gateway_on(Arc::clone(&dp), "::1").await;

    let body4 = raw_get_from("127.0.0.1", v4, "/x").await;
    let body6 = raw_get_v6(v6, "/x").await;
    let owner4 = parse_id_host(&body4).0;
    let owner6 = parse_id_host(&body6).0;
    assert!(
        owner4 != owner6,
        "distinct client IPs ({owner4} vs {owner6}) should spread"
    );
    // Repeat each family: still sticky per IP.
    assert_eq!(
        parse_id_host(&raw_get_from("127.0.0.1", v4, "/x").await).0,
        owner4
    );
    assert_eq!(parse_id_host(&raw_get_v6(v6, "/x").await).0, owner6);
    let counts: Vec<u64> = hits.iter().map(|h| h.load(Ordering::Relaxed)).collect();
    assert_eq!(counts.iter().sum::<u64>(), 4);
}

// --- end-to-end: slow start --------------------------------------------------

#[tokio::test]
async fn slow_start_ramps_new_endpoints_from_even_split_to_configured_weights() {
    // Weights (5,1) with a 400ms window. All endpoints enter NOW, so an
    // immediate burst sees both at the weight floor (1) -> an even 3/3 over
    // 6 requests; after the window a burst sees the configured 5:1 -> an
    // exact 10/2 over 12. Time is not injectable (noted gap); localhost
    // latency makes the first burst finish well inside the window.
    let (hits, ports) = spawn_backends(&[(0, 0), (1, 0)]).await;
    let dp = DataPlane::new(state_from(&lb_yaml(
        "round_robin",
        &[5, 1],
        &ports,
        Some(400),
    )));
    let port = spawn_gateway(dp).await;

    let client = h1_client();
    let base = [
        hits[0].load(Ordering::Relaxed),
        hits[1].load(Ordering::Relaxed),
    ];
    for _ in 0..6 {
        let resp = client.get(uri(port, "/x")).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }
    let early = [
        hits[0].load(Ordering::Relaxed) - base[0],
        hits[1].load(Ordering::Relaxed) - base[1],
    ];
    assert!(
        early[0] <= 4 && early[1] >= 2,
        "during the ramp the weights are ~even: {early:?}"
    );

    tokio::time::sleep(Duration::from_millis(450)).await;
    for _ in 0..12 {
        let resp = client.get(uri(port, "/x")).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }
    let late = [
        hits[0].load(Ordering::Relaxed) - base[0],
        hits[1].load(Ordering::Relaxed) - base[1],
    ];
    assert_eq!(
        [late[0] - early[0], late[1] - early[1]],
        [10, 2],
        "past the window, configured weights apply exactly: {late:?}"
    );
}

// --- end-to-end: hot swap -----------------------------------------------------

#[tokio::test]
async fn weight_hot_swap_shifts_distribution_without_drops_or_leaked_inflight() {
    // Backends delay 80ms so requests are observably in-flight across the
    // config swap. Regression for the double-counted-inflight bug: after a
    // rebuild while requests are in-flight, the counters must return to 0.
    let (hits, ports) = spawn_backends(&[(0, 80), (1, 80)]).await;
    let state = state_from(&lb_yaml("round_robin", &[1, 1], &ports, None));
    let dp = DataPlane::new(Arc::clone(&state));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let client = h1_client();
    let mut tasks = Vec::new();
    for _ in 0..24 {
        let c = client.clone();
        tasks.push(tokio::spawn(async move {
            let resp = c.get(uri(port, "/x")).await.unwrap();
            assert_eq!(resp.status(), hyper::StatusCode::OK);
        }));
    }
    // Swap mid-traffic: publish weights (2,1) and refresh, exactly like the
    // binary's reload path.
    tokio::time::sleep(Duration::from_millis(10)).await;
    let gateway = parse_gateway(&lb_yaml("round_robin", &[2, 1], &ports, None)).unwrap();
    state.compile_and_publish(&gateway).expect("publish B");
    dp.refresh();

    for t in tasks {
        t.await.unwrap(); // no request may fail across the swap
    }
    let served: u64 = hits.iter().map(|h| h.load(Ordering::Relaxed)).sum();
    assert_eq!(served, 24, "no dropped requests across the swap");

    // In-flight counters must have fully drained despite the rebuild
    // happening while guards were live (regression: double-counting).
    tokio::time::sleep(Duration::from_millis(50)).await;
    let handle = dp.registry().get("up").unwrap();
    let lb = handle.lb();
    assert_eq!(lb.inflight(0), 0, "inflight 0 drained post-swap");
    assert_eq!(lb.inflight(1), 0, "inflight 1 drained post-swap");

    // Steady state now follows the NEW weights: 12 requests = 2 periods of
    // (2+1) -> exactly [8,4] relative.
    let base = [
        hits[0].load(Ordering::Relaxed),
        hits[1].load(Ordering::Relaxed),
    ];
    for _ in 0..12 {
        let resp = client.get(uri(port, "/x")).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }
    assert_eq!(
        [
            hits[0].load(Ordering::Relaxed) - base[0],
            hits[1].load(Ordering::Relaxed) - base[1]
        ],
        [8, 4],
        "new weights take effect without restart"
    );
}

// --- unit: passthrough SNI now follows the balancer -------------------------

#[tokio::test]
async fn passthrough_sni_resolution_alternates_endpoints_via_registry() {
    let yaml = lb_yaml("round_robin", &[1, 1], &[9001, 9002], None);
    let gateway = parse_gateway(&yaml).unwrap();
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    let dp = DataPlane::new(state);
    let registry: Arc<UpstreamRegistry> = dp.registry();

    let tls = ListenerTls {
        mode: TlsMode::Passthrough,
        client_ca_file: None,
        cert_file: None,
        key_file: None,
        certificates: vec![],
        sni_routes: vec![SniRoute {
            server_names: vec!["a.example.com".into()],
            upstream: "up".into(),
        }],
    };
    let hosts: Vec<String> = {
        // The dataplane's resolver: pick through the registry's balancers
        // (no hash key — same as the bin's passthrough listener).
        let pick = |name: &str| {
            registry
                .get(name)
                .and_then(|h| h.lb().pick_endpoint(None).map(|(_, a, p)| (a, p)))
        };
        (0..4)
            .map(|_| {
                match resolve_passthrough(
                    Some("a.example.com"),
                    &tls.sni_routes,
                    &gateway,
                    Some(&pick),
                ) {
                    dwara_core::tls::PassthroughAction::Forward { host, port } => {
                        format!("{host}:{port}")
                    }
                    other => panic!("expected forward, got {other:?}"),
                }
            })
            .collect()
    };
    assert_eq!(
        hosts,
        vec![
            "127.0.0.1:9001",
            "127.0.0.1:9002",
            "127.0.0.1:9001",
            "127.0.0.1:9002",
        ],
        "passthrough picks follow the upstream's balancer"
    );
}

// --- unit: single-endpoint degeneracy ----------------------------------------

#[test]
fn every_algorithm_degenerates_to_index_zero_with_one_endpoint() {
    for algo in [
        LoadBalancer::RoundRobin,
        LoadBalancer::LeastRequests,
        LoadBalancer::Random,
        LoadBalancer::IpHash,
    ] {
        let lb = UpstreamLb::new(
            &[Endpoint {
                address: "10.0.0.1".into(),
                port: 80,
                weight: 7, // weight is irrelevant with one endpoint
            }],
            algo,
            Duration::from_secs(10),
        );
        for _ in 0..10 {
            assert_eq!(lb.pick(Some("198.51.100.7")), Some(0), "{algo:?}");
            assert_eq!(lb.pick(None), Some(0), "{algo:?}");
        }
    }
}

// --- unit: random-2 tie-break pinning -----------------------------------------

#[test]
fn random_two_ties_break_to_the_lowest_index_of_the_pair() {
    // With exactly two endpoints at equal in-flight counts, the drawn pair
    // is always {0,1} and the tie rule (lower index of the pair) pins 0.
    // The rng seed is process-derived (not injectable), so assert the
    // invariant over many draws rather than a fixed sequence.
    let lb = UpstreamLb::new(
        &[
            Endpoint {
                address: "a".into(),
                port: 1,
                weight: 1,
            },
            Endpoint {
                address: "b".into(),
                port: 2,
                weight: 1,
            },
        ],
        LoadBalancer::Random,
        Duration::ZERO,
    );
    for _ in 0..500 {
        assert_eq!(
            lb.pick(None),
            Some(0),
            "equal-inflight pair tie -> lower index"
        );
    }
}

// --- unit: ketama properties beyond the dev suite ------------------------------

fn endpoints(specs: &[(&str, u32)]) -> Vec<Endpoint> {
    specs
        .iter()
        .map(|&(a, w)| Endpoint {
            address: a.into(),
            port: 80,
            weight: w,
        })
        .collect()
}

#[test]
fn ketama_ring_is_deterministic_across_builds() {
    let spec = endpoints(&[("10.0.0.1", 3), ("10.0.0.2", 1), ("10.0.0.3", 1)]);
    let a = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
    let b = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
    for i in 0..300 {
        let key = format!("203.0.113.{i}");
        assert_eq!(
            a.pick(Some(&key)),
            b.pick(Some(&key)),
            "same config, same ring, key {key}"
        );
    }
}

#[test]
fn ketama_heavy_endpoint_addition_takes_its_share_and_remaps_minimally() {
    // Two equal endpoints; then a weight-8 third endpoint joins. It should
    // receive roughly its share (8/10) of keys, and keys must move only to
    // the NEW endpoint — old endpoints must not swap keys between each
    // other (that is the minimality property of consistent hashing).
    let spec = endpoints(&[("10.0.0.1", 1), ("10.0.0.2", 1)]);
    let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
    let keys: Vec<String> = (0..400).map(|i| format!("192.0.2.{i}")).collect();
    let before: Vec<usize> = keys
        .iter()
        .map(|k| lb.pick(Some(k.as_str())).unwrap())
        .collect();

    let mut grown = spec.clone();
    grown.push(Endpoint {
        address: "10.0.0.3".into(),
        port: 80,
        weight: 8,
    });
    lb.rebuild(&grown, LoadBalancer::IpHash, Duration::ZERO);
    let after: Vec<usize> = keys
        .iter()
        .map(|k| lb.pick(Some(k.as_str())).unwrap())
        .collect();

    let to_new = before.iter().zip(&after).filter(|(_, &b)| b == 2).count();
    let moved_between_old = before
        .iter()
        .zip(&after)
        .filter(|(&x, &y)| x != y && y != 2)
        .count();
    let new_share = to_new as f64 / keys.len() as f64;
    assert!(
        (0.55..0.95).contains(&new_share),
        "heavy newcomer took {new_share:.3}, expected ~0.8"
    );
    // Per-unit vnodes (post-fix): each endpoint's vnode positions are
    // independent of the others' weights, so a heavy addition never moves
    // an existing endpoint's vnodes. Stricter minimality is pinned by
    // ketama_heavy_addition_leaves_old_endpoint_keys_in_place below.
    assert!(
        moved_between_old <= 40,
        "old endpoints exchanged {moved_between_old} keys"
    );
}

#[test]
fn ip_hash_without_key_falls_back_to_the_weighted_round_robin_sequence() {
    let spec = endpoints(&[("10.0.0.1", 2), ("10.0.0.2", 1), ("10.0.0.3", 1)]);
    let ip_lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
    let rr_lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    for _ in 0..8 {
        assert_eq!(
            ip_lb.pick(None),
            rr_lb.pick(None),
            "key-less ip_hash must equal the smooth-WRR sequence"
        );
    }
}

// --- validation ----------------------------------------------------------------

#[test]
fn slow_start_ms_above_ten_minutes_is_rejected() {
    let yaml = lb_yaml("round_robin", &[1], &[80], Some(600_001));
    let gateway = parse_gateway(&yaml).unwrap();
    let issues = dwara_core::snapshot::validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "slow_start_ms"),
        "expected slow_start_ms bound issue in {issues:?}"
    );
    let ok = lb_yaml("round_robin", &[1], &[80], Some(600_000));
    let issues = dwara_core::snapshot::validate(&parse_gateway(&ok).unwrap());
    assert!(
        !issues.iter().any(|i| i.field == "slow_start_ms"),
        "600000 is valid: {issues:?}"
    );
}

// --- loop-1 additions: post-fix regressions and validation bounds -----------

/// Minimal full-config YAML for validation tests with arbitrary upstream
/// endpoint lists (address, port, weight) — avoids the shared-address
/// assumption baked into `lb_yaml` (which exists for live backends).
type UpsSpec<'a> = (&'a str, &'a str, &'a [(&'a str, u16, u32)]);

fn upstreams_yaml(ups: &[UpsSpec]) -> String {
    let mut s = String::from("routes: []\nservices: []\nupstreams:\n");
    for (name, algo, eps) in ups {
        s.push_str(&format!(
            "- name: {name}\n  load_balancer: {algo}\n  endpoints:\n"
        ));
        for (a, p, w) in *eps {
            s.push_str(&format!(
                "  - address: {a}\n    port: {p}\n    weight: {w}\n"
            ));
        }
    }
    s
}

#[test]
fn duplicate_address_port_is_rejected_per_upstream_but_distinct_ports_and_cross_upstream_repeat_are_fine(
) {
    // Same address:port twice in ONE upstream: rejected at endpoints[1].
    let yaml = upstreams_yaml(&[(
        "up",
        "round_robin",
        &[("10.0.0.1", 80, 1), ("10.0.0.1", 80, 2)],
    )]);
    let issues = dwara_core::snapshot::validate(&parse_gateway(&yaml).unwrap());
    let hits: Vec<_> = issues
        .iter()
        .filter(|i| i.field == "endpoints[1].address")
        .collect();
    assert_eq!(hits.len(), 1, "one issue at the duplicate: {issues:?}");
    assert!(
        hits[0].message.contains("unique within an upstream"),
        "message names the rule: {hits:?}"
    );

    // Same address, DIFFERENT port: two distinct targets — accepted.
    let yaml = upstreams_yaml(&[(
        "up",
        "round_robin",
        &[("10.0.0.1", 80, 1), ("10.0.0.1", 8080, 1)],
    )]);
    let issues = dwara_core::snapshot::validate(&parse_gateway(&yaml).unwrap());
    assert!(
        !issues.iter().any(|i| i.field.contains("address")),
        "same address different port is fine: {issues:?}"
    );

    // Same address:port in two DIFFERENT upstreams: independent balancer
    // states, no shared-counter hazard — accepted.
    let yaml = upstreams_yaml(&[
        ("up-a", "round_robin", &[("10.0.0.1", 80, 1)]),
        ("up-b", "round_robin", &[("10.0.0.1", 80, 1)]),
    ]);
    let issues = dwara_core::snapshot::validate(&parse_gateway(&yaml).unwrap());
    assert!(
        !issues.iter().any(|i| i.field.contains("address")),
        "cross-upstream repeat is fine: {issues:?}"
    );
}

#[test]
fn shrink_rebuild_while_dispatch_held_drains_inflight_without_panic() {
    // Regression for the shrink race: a Dispatch pins the SNAPSHOT it was
    // picked from, so rebuilding to a SMALLER endpoint set while the guard
    // is held must not panic (index into the old set) and must decrement
    // the counter of the state it came from — observable via the carried
    // live counter of a surviving endpoint.
    for i in 0..200 {
        let four: Vec<Endpoint> = (0..4)
            .map(|n| Endpoint {
                address: format!("10.4.0.{n}"),
                port: 80,
                weight: 1,
            })
            .collect();
        let lb = UpstreamLb::new(&four, LoadBalancer::RoundRobin, Duration::ZERO);
        let d = lb.pick_for_dispatch(None).expect("pick on full set");
        assert!(d.idx < 4, "iteration {i}: idx {} of 4", d.idx);
        let old_inflight = lb.inflight(d.idx);
        assert_eq!(old_inflight, 1, "iteration {i}: guard counted");

        // Hot-swap shrink to endpoints 0 and 1 (drop 2 and 3). The held
        // guard still references the old snapshot.
        let two: Vec<Endpoint> = four[..2].to_vec();
        lb.rebuild(&two, LoadBalancer::RoundRobin, Duration::ZERO);
        assert_eq!(lb.len(), 2);

        // Every pick on the NEW state resolves inside the new set.
        for _ in 0..4 {
            let d2 = lb.pick_for_dispatch(None).expect("pick on shrunk set");
            assert!(d2.idx < 2, "iteration {i}: new-state idx {}", d2.idx);
            assert!(lb.endpoint(d2.idx).is_some());
            d2.release(); // must not panic against either state
        }

        // If the guard's endpoint survived the shrink, its LIVE counter was
        // carried into the new state: still 1 before release, 0 after —
        // proof the decrement lands on the snapshot it came from.
        if d.idx < 2 {
            assert_eq!(lb.inflight(d.idx), 1, "iteration {i}: carried counter");
            let idx = d.idx;
            d.release();
            assert_eq!(lb.inflight(idx), 0, "iteration {i}: drained");
        } else {
            // Removed endpoint: release touches only the pinned old
            // snapshot — no index into the new state, no panic.
            d.release();
        }
        // All surviving endpoints drained.
        for idx in 0..lb.len() {
            assert_eq!(lb.inflight(idx), 0, "iteration {i}: ep {idx} leaked");
        }
    }
}

#[test]
fn ketama_heavy_addition_leaves_old_endpoint_keys_in_place() {
    // Per-unit vnodes: an endpoint's vnode positions depend only on its
    // own address:port and weight, so adding a weight-8 endpoint to two
    // weight-1 endpoints never moves an old endpoint's vnodes. A key can
    // only change owner by being captured by the NEWCOMER; keys that still
    // map to an old endpoint must map to the SAME one (>= 95% of all keys
    // stay on their pre-addition old endpoint's side — the measured
    // exchange between old endpoints is ~0).
    let spec = endpoints(&[("10.5.0.1", 1), ("10.5.0.2", 1)]);
    let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
    let keys: Vec<String> = (0..300).map(|i| format!("198.51.100.{i}")).collect();
    let before: Vec<usize> = keys
        .iter()
        .map(|k| lb.pick(Some(k.as_str())).unwrap())
        .collect();

    let mut grown = spec.clone();
    grown.push(Endpoint {
        address: "10.5.0.3".into(),
        port: 80,
        weight: 8,
    });
    lb.rebuild(&grown, LoadBalancer::IpHash, Duration::ZERO);
    let after: Vec<usize> = keys
        .iter()
        .map(|k| lb.pick(Some(k.as_str())).unwrap())
        .collect();

    let moved_between_old = before
        .iter()
        .zip(&after)
        .filter(|(&x, &y)| x != y && y != 2)
        .count();
    assert!(
        moved_between_old * 20 <= keys.len(), // <= 5% of keys
        "old endpoints exchanged {moved_between_old}/{} keys; per-unit \
         vnodes should make this ~0",
        keys.len()
    );
    // Same config rebuilt into a FRESH instance must reproduce the picks
    // exactly (FNV stability: no process-state dependence).
    let fresh = UpstreamLb::new(&grown, LoadBalancer::IpHash, Duration::ZERO);
    for (k, &y) in keys.iter().zip(&after) {
        assert_eq!(fresh.pick(Some(k.as_str())).unwrap(), y, "key {k}");
    }
}

#[test]
fn ip_hash_ring_size_above_cap_is_rejected_at_the_bound() {
    // MAX_RING_VNODES = 65536 = 160 * 409.6, so a total weight of 410
    // crosses the cap and 409 stays just under.
    let over = upstreams_yaml(&[("up", "ip_hash", &[("10.6.0.1", 80, 410)])]);
    let issues = dwara_core::snapshot::validate(&parse_gateway(&over).unwrap());
    let hits: Vec<_> = issues
        .iter()
        .filter(|i| i.field == "endpoints.weight")
        .collect();
    assert_eq!(hits.len(), 1, "one ring-size issue: {issues:?}");
    assert!(
        hits[0].message.contains("65536"),
        "message names the bound: {hits:?}"
    );

    let under = upstreams_yaml(&[("up", "ip_hash", &[("10.6.0.1", 80, 409)])]);
    let issues = dwara_core::snapshot::validate(&parse_gateway(&under).unwrap());
    assert!(
        !issues.iter().any(|i| i.field == "endpoints.weight"),
        "409 * 160 = 65440 <= cap: {issues:?}"
    );
    // The cap binds only ip_hash: the same weights elsewhere are fine.
    let other = upstreams_yaml(&[("up", "round_robin", &[("10.6.0.1", 80, 410)])]);
    let issues = dwara_core::snapshot::validate(&parse_gateway(&other).unwrap());
    assert!(
        !issues.iter().any(|i| i.field == "endpoints.weight"),
        "ring cap is ip_hash-only: {issues:?}"
    );
}
