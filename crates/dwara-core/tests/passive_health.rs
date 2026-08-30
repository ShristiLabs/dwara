//! Passive health / outlier detection integration (DW-012).
//!
//! Two layers:
//!
//! - balancer-level tests drive the trackers through real picks with an
//!   injected clock (`set_health_clock`, the rate limiter's DW-004
//!   pattern), proving the pick-path state machine: ejection removes an
//!   endpoint from every algorithm's candidate set, all-ejected fails
//!   open (counted), and half-open recovery returns the endpoint to
//!   rotation;
//! - handle-level tests run real HTTP against two local endpoints, one of
//!   which serves 5xx, and prove the full observation wire: fails-over to
//!   the healthy endpoint, recovers via a half-open probe after
//!   `eject_ms`, and honors the volume threshold before ratio ejection.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use dwara_core::balance::UpstreamLb;
use dwara_core::config::{
    parse_gateway, Endpoint, Gateway, LoadBalancer, PassiveHealth, Upstream as ConfigUpstream,
    UpstreamProtocol,
};
use dwara_core::health::{EndpointHealth, HealthParams};
use dwara_core::snapshot::{validate, ConfigState};
use dwara_core::upstream::UpstreamRegistry;

// --- deterministic clock for balancer-level tests -------------------------

thread_local! {
    static TIME: std::cell::Cell<u64> = const { std::cell::Cell::new(1_000_000) };
}

fn tick(advance_ms: u64) {
    TIME.with(|t| t.set(t.get() + advance_ms));
}

fn eps(specs: &[(&str, u16)]) -> Vec<Endpoint> {
    specs
        .iter()
        .map(|&(a, p)| Endpoint {
            address: a.to_string(),
            port: p,
            weight: 1,
        })
        .collect()
}

fn health_cfg(consecutive_failures: u32, failure_min_volume: u32) -> PassiveHealth {
    PassiveHealth {
        window_ms: 60_000,
        consecutive_failures,
        failure_ratio: 0.5,
        failure_min_volume,
        eject_ms: 5_000,
        half_open_probes: 1,
    }
}

/// Fully parameterized health config for the edge-case tests below.
#[allow(clippy::too_many_arguments)]
fn health_full(
    window_ms: u64,
    consecutive_failures: u32,
    failure_ratio: f64,
    failure_min_volume: u32,
    eject_ms: u64,
    half_open_probes: u32,
) -> PassiveHealth {
    PassiveHealth {
        window_ms,
        consecutive_failures,
        failure_ratio,
        failure_min_volume,
        eject_ms,
        half_open_probes,
    }
}

/// Report `n` observations of `is_failure` for endpoint `idx` through real
/// picks; the other endpoint is fed successes so it stays healthy.
fn observe(lb: &Arc<UpstreamLb>, idx: usize, n: u32, is_failure: bool) {
    let mut seen = 0;
    while seen < n {
        let d = lb.pick_for_dispatch(None).expect("pick");
        let health = d.health.as_ref().expect("health configured");
        if d.idx == idx {
            health.report(lb.now_ms(), is_failure);
            seen += 1;
        } else {
            health.report(lb.now_ms(), false);
        }
        d.release();
    }
}

/// Report `n` failures to endpoint `idx` through real picks (the only way
/// to reach a tracker from outside), keeping the OTHER endpoint's tracker
/// fed successes so it stays healthy.
fn fail_endpoint(lb: &Arc<UpstreamLb>, idx: usize, n: u32) {
    observe(lb, idx, n, true);
}

#[test]
fn ejected_endpoint_leaves_picks_until_half_open_recovery() {
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_cfg(3, 20)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));

    fail_endpoint(&lb, 0, 3);
    for _ in 0..10 {
        assert_eq!(lb.pick(None), Some(1), "endpoint 0 is ejected");
    }

    // Ejection expires: endpoint 0 re-enters the candidate set as
    // half-open; keep picking until the probe lands on it (WRR phase may
    // still favor endpoint 1 for a pick or two).
    tick(5_001);
    let mut probed = false;
    for _ in 0..20 {
        let d = lb.pick_for_dispatch(None).expect("probe pick");
        let ok = d.idx == 0;
        d.health.as_ref().unwrap().report(lb.now_ms(), !ok);
        d.release();
        if ok {
            probed = true;
            break;
        }
    }
    assert!(probed, "endpoint 0 received its half-open probe");

    // Successful probe: both endpoints back in rotation.
    let mut seen = [false; 2];
    for _ in 0..10 {
        seen[lb.pick(None).unwrap()] = true;
    }
    assert!(seen[0] && seen[1], "distribution resumes after recovery");
}

#[test]
fn failed_half_open_probe_re_ejects() {
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_cfg(3, 20)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));

    fail_endpoint(&lb, 0, 3);
    tick(5_001);
    let mut probed = 0;
    for _ in 0..20 {
        let d = lb.pick_for_dispatch(None).expect("pick");
        let to_a = d.idx == 0;
        d.health.as_ref().unwrap().report(lb.now_ms(), to_a);
        d.release();
        if to_a {
            probed += 1;
            break;
        }
    }
    assert_eq!(probed, 1, "failed probe: endpoint 0 saw the probe");
    for _ in 0..10 {
        assert_eq!(lb.pick(None), Some(1), "re-ejected after failed probe");
    }

    // Second window expires: another probe attempt is granted.
    tick(5_001);
    let mut probed_again = false;
    for _ in 0..20 {
        let d = lb.pick_for_dispatch(None).expect("pick");
        let to_a = d.idx == 0;
        d.health.as_ref().unwrap().report(lb.now_ms(), !to_a);
        d.release();
        if to_a {
            probed_again = true;
            break;
        }
    }
    assert!(
        probed_again,
        "second probe attempt granted after re-ejection"
    );
}

#[test]
fn all_ejected_fails_open_on_the_full_set() {
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_cfg(3, 20)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));

    fail_endpoint(&lb, 0, 3);
    fail_endpoint(&lb, 1, 3);
    assert_eq!(lb.fail_open_picks(), 0);
    // Every endpoint is ejected: picks fall back to the full set rather
    // than blackholing (fail-open), and the fallback is counted.
    let picks: Vec<usize> = (0..4).map(|_| lb.pick(None).unwrap()).collect();
    // WRR phase carries over from the fail_endpoint picks, so the leading
    // endpoint is unspecified; what matters is that BOTH endpoints serve
    // (no blackhole) and the sequence keeps alternating.
    assert_eq!(picks[0], picks[2]);
    assert_eq!(picks[1], picks[3]);
    assert_ne!(picks[0], picks[1], "full-set WRR under fail-open");
    assert_eq!(lb.fail_open_picks(), 4);
}

#[test]
fn rebuild_carries_live_health_trackers_for_unchanged_addresses() {
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_cfg(3, 20)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));
    fail_endpoint(&lb, 0, 2); // streak of 2 toward the threshold of 3

    // Same endpoint set, new algorithm: the LIVE tracker (streak 2)
    // survives the rebuild; one more failure ejects.
    lb.rebuild_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::LeastRequests,
        Duration::ZERO,
        Some(&health_cfg(3, 20)),
    );
    fail_endpoint(&lb, 0, 1);
    for _ in 0..5 {
        assert_eq!(lb.pick(None), Some(1), "carried streak ejected endpoint 0");
    }
}

// --- window expiry -----------------------------------------------------------

#[test]
fn stale_window_history_does_not_eject_after_expiry() {
    // Ratio 0.75 with volume gate 8: six failures at t0 stay below the
    // volume gate, so the endpoint is healthy but carries a poisoned
    // window. After the window expires, a fresh burst of successes plus a
    // few failures must NOT eject on the stale history (if expiry were
    // broken, volume 10 / failures 8 >= 0.75 would eject).
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_full(1_000, 100, 0.75, 8, 5_000, 1)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));

    fail_endpoint(&lb, 0, 6);
    // Window boundary: one tick past window_ms (expiry is inclusive: an
    // observation aged >= window_ms leaves).
    tick(1_001);
    observe(&lb, 0, 2, false); // fresh successes flush the stale failures
    observe(&lb, 0, 2, true); // a few fresh failures: 2-of-4 < 0.75
    let mut saw_zero = false;
    for _ in 0..10 {
        if lb.pick(None) == Some(0) {
            saw_zero = true;
        }
    }
    assert!(saw_zero, "endpoint 0 survived on expired history");
}

#[test]
fn a_success_anywhere_in_the_streak_resets_it() {
    // Streak threshold 3, ratio path fully disabled: the F-F-S pattern
    // repeats forever without ever ejecting — a success observed anywhere
    // resets the consecutive counter (dev-pinned semantics).
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_full(60_000, 3, 1.0, 1_000_000, 5_000, 1)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));
    for _ in 0..20 {
        observe(&lb, 0, 2, true);
        observe(&lb, 0, 1, false);
    }
    let mut saw_zero = false;
    for _ in 0..10 {
        if lb.pick(None) == Some(0) {
            saw_zero = true;
        }
    }
    assert!(saw_zero, "interleaved failures never reached a 3-streak");
}

// --- ratio edges (tracker-level, public API) ----------------------------------

fn edge_params(failure_ratio: f64, failure_min_volume: u32) -> HealthParams {
    HealthParams {
        window_ms: 60_000,
        consecutive_failures: u32::MAX, // streak path disabled
        failure_ratio,
        failure_min_volume,
        eject_ms: 1_000,
        half_open_probes: 1,
    }
}

#[test]
fn ratio_exactly_at_threshold_with_exact_volume_ejects() {
    // Volume 4 (== min_volume), failures 2 (== ratio 0.5 * 4), and the
    // triggering observation is itself a failure (ejection is only
    // evaluated on failure reports): the >= semantics must eject exactly
    // at both thresholds.
    let p = edge_params(0.5, 4);
    let t = EndpointHealth::new();
    t.report(&p, 1_000, true);
    t.report(&p, 1_000, false);
    t.report(&p, 1_000, false);
    assert!(t.is_available(1_000), "volume 3 below the gate");
    t.report(&p, 1_000, true); // 4th observation: 2F/2S at volume 4
    assert!(
        !t.is_available(1_000),
        "failures 2 >= ratio*volume 2.0 at exact volume: ejected"
    );
}

#[test]
fn volume_one_below_threshold_never_ejects_even_at_full_failure() {
    // Three observations, all failures (ratio 1.0): volume 3 < 4 gates the
    // ejection regardless of how bad the share is.
    let p = edge_params(0.99, 4);
    let t = EndpointHealth::new();
    for _ in 0..3 {
        t.report(&p, 1_000, true);
    }
    assert!(t.is_available(1_000), "100% ratio with volume 3 stays in");
}

#[test]
fn ratio_just_below_threshold_with_huge_volume_stays_in() {
    // Volume 8, failures 5: share 0.625 < 0.75 — no ejection no matter how
    // much traffic backs the sub-threshold ratio.
    let p = edge_params(0.75, 4);
    let t = EndpointHealth::new();
    for is_failure in [true, true, false, true, false, true, false, false] {
        t.report(&p, 1_000, is_failure);
    }
    assert!(t.is_available(1_000), "5 of 8 below the 0.75 threshold");
}

// --- half-open probe budget under sequential dispatch ------------------------

#[test]
fn half_open_probe_budget_bounds_sequential_dispatches() {
    // 2 probes, 5 sequential dispatches after the ejection expires with NO
    // outcome reported in between: at most `half_open_probes` dispatches
    // reach the recovering endpoint; the rest go to the healthy one. The
    // budget is documented best-effort under CONCURRENT picks (see
    // EndpointHealth::consume_probe); this pins the SERIAL guarantee.
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_full(60_000, 3, 0.5, 1_000, 5_000, 2)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));
    fail_endpoint(&lb, 0, 3);
    tick(5_001);

    let mut on_recovering = 0;
    let mut on_healthy = 0;
    for _ in 0..5 {
        let d = lb.pick_for_dispatch(None).expect("pick");
        if d.idx == 0 {
            on_recovering += 1;
        } else {
            on_healthy += 1;
        }
        d.release(); // no report: the probe slots must bound on their own
    }
    assert_eq!(on_recovering, 2, "exactly the 2-probe budget reached ep 0");
    assert_eq!(on_healthy, 3, "the healthy endpoint took the remainder");
}

// --- health + ip_hash interaction ---------------------------------------------

#[test]
fn ip_hash_key_falls_back_to_next_healthy_owner_and_returns_after_recovery() {
    let lb = UpstreamLb::new_with_health(
        &eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]),
        LoadBalancer::IpHash,
        Duration::ZERO,
        Some(&health_cfg(3, 1_000)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));

    // Find a key whose ring owner is endpoint 0.
    let key = (0..1_000)
        .map(|i| format!("203.0.113.{i}"))
        .find(|k| lb.pick(Some(k)) == Some(0))
        .expect("some key owns endpoint 0");
    assert_eq!(lb.pick(Some(&key)), Some(0), "sticky while healthy");

    // Owner ejected: the key walks forward to the next healthy ring owner
    // (endpoint 1) and STAYS there while the owner is out.
    fail_endpoint(&lb, 0, 3);
    for _ in 0..10 {
        assert_eq!(
            lb.pick(Some(&key)),
            Some(1),
            "sticky to the fallback owner while 0 is ejected"
        );
    }

    // Ejection expires: the key's owner returns as half-open, takes its
    // probe, and — once the probe succeeds — owns the key again.
    tick(5_001);
    let d = lb.pick_for_dispatch(Some(&key)).expect("probe pick");
    assert_eq!(d.idx, 0, "half-open owner receives the key's probe");
    d.health.as_ref().unwrap().report(lb.now_ms(), false);
    d.release();
    for _ in 0..10 {
        assert_eq!(
            lb.pick(Some(&key)),
            Some(0),
            "key returns to its original owner after recovery"
        );
    }
}

// --- hot reload of health parameters ------------------------------------------

#[test]
fn hot_reload_tightens_and_loosens_the_consecutive_threshold() {
    // Tighten 5 -> 2 mid-stream: the carried streak (4) plus ONE new
    // failure under the new parameters ejects — new params apply to new
    // observations, the streak survives the reload.
    let spec = eps(&[("10.0.0.1", 80), ("10.0.0.2", 80)]);
    let lb = UpstreamLb::new_with_health(
        &spec,
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_cfg(5, 1_000)),
    );
    lb.set_health_clock(|| TIME.with(|t| t.get()));
    fail_endpoint(&lb, 0, 4); // streak 4 under threshold 5: healthy
    let mut saw_zero = false;
    for _ in 0..10 {
        if lb.pick(None) == Some(0) {
            saw_zero = true;
        }
    }
    assert!(saw_zero, "streak 4 below threshold 5 stays in rotation");

    lb.rebuild_with_health(
        &spec,
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_cfg(2, 1_000)),
    );
    fail_endpoint(&lb, 0, 1); // one NEW failure under the tightened params
    for _ in 0..10 {
        assert_eq!(lb.pick(None), Some(1), "ejected at 2 under new params");
    }

    // Loosen 2 -> 5 after recovery: the same carried history must NOT
    // eject at the old threshold anymore.
    tick(5_001);
    let mut probed = false;
    for _ in 0..20 {
        let d = lb.pick_for_dispatch(None).expect("pick");
        let ok = d.idx == 0;
        d.health.as_ref().unwrap().report(lb.now_ms(), !ok);
        d.release();
        if ok {
            probed = true;
            break;
        }
    }
    assert!(probed, "recovery probe reached endpoint 0");
    lb.rebuild_with_health(
        &spec,
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health_cfg(5, 1_000)),
    );
    fail_endpoint(&lb, 0, 4); // streak 4 under the loosened threshold 5
    let mut saw_zero = false;
    for _ in 0..10 {
        if lb.pick(None) == Some(0) {
            saw_zero = true;
        }
    }
    assert!(saw_zero, "streak 4 below reloaded threshold 5 stays in");
}

// --- handle-level tests against real endpoints -----------------------------

/// One local origin: counts requests, serves 500 while `fail` is set.
async fn serve(listener: TcpListener, hits: Arc<AtomicU64>, fail: Arc<AtomicBool>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let hits = Arc::clone(&hits);
        let fail = Arc::clone(&fail);
        let service = service_fn(move |_req: Request<Incoming>| {
            let hits = Arc::clone(&hits);
            let fail = fail.load(Ordering::SeqCst);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let status = if fail {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::OK
                };
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new()))).map(
                    |mut r| {
                        *r.status_mut() = status;
                        r
                    },
                )
            }
        });
        tokio::spawn(async move {
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

struct TestPool {
    a_hits: Arc<AtomicU64>,
    b_hits: Arc<AtomicU64>,
    a_fail: Arc<AtomicBool>,
    handle: Arc<dwara_core::upstream::UpstreamHandle>,
}

async fn pool_with_health(health: PassiveHealth) -> TestPool {
    let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a_port, b_port) = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    let a_hits = Arc::new(AtomicU64::new(0));
    let b_hits = Arc::new(AtomicU64::new(0));
    let a_fail = Arc::new(AtomicBool::new(false));
    tokio::spawn(serve(a, Arc::clone(&a_hits), Arc::clone(&a_fail)));
    tokio::spawn(serve(
        b,
        Arc::clone(&b_hits),
        Arc::new(AtomicBool::new(false)),
    ));

    let gw = Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams: vec![ConfigUpstream {
            name: "pool".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: vec![
                Endpoint {
                    address: "127.0.0.1".into(),
                    port: a_port,
                    weight: 1,
                },
                Endpoint {
                    address: "127.0.0.1".into(),
                    port: b_port,
                    weight: 1,
                },
            ],
            connection_cap: None,
            slow_start_ms: None,
            active_health: None,
            retries: None,
            health: Some(health),
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
        // Genuinely zero-route: this suite exercises upstream passive
        // health, not routing (#129 opt-in).
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
    };
    let state = ConfigState::new();
    state.compile_and_publish(&gw).expect("publish");
    let registry = UpstreamRegistry::from_snapshot(&state.snapshot());
    TestPool {
        a_hits,
        b_hits,
        a_fail,
        handle: registry.get("pool").expect("handle"),
    }
}

fn get_request(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .body(Full::new(Bytes::new()))
        .expect("request")
}

#[tokio::test]
async fn consecutive_failures_eject_failover_and_half_open_recovery() {
    // Short real-time ejection window; the deterministic-clock state
    // machine is covered by the balancer-level tests above.
    let pool = pool_with_health(PassiveHealth {
        consecutive_failures: 3,
        eject_ms: 150,
        ..PassiveHealth::default()
    })
    .await;
    let h = &pool.handle;

    // A fails everything; WRR alternates A,B,A,B,A -> A's third failure
    // ejects it; everything after that lands on B.
    pool.a_fail.store(true, Ordering::SeqCst);
    let mut last = StatusCode::OK;
    for _ in 0..8 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        last = resp.status();
    }
    assert_eq!(pool.a_hits.load(Ordering::SeqCst), 3, "A hit 3 times");
    assert_eq!(pool.b_hits.load(Ordering::SeqCst), 5, "B took over");
    assert_eq!(last, StatusCode::OK, "client saw only B after ejection");
    // One more burst while the ejection stands: still only B.
    for _ in 0..4 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(pool.a_hits.load(Ordering::SeqCst), 3);

    // Recovery: A is fixed; after eject_ms the next request to A is the
    // half-open probe and its success puts A back in rotation.
    pool.a_fail.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let a_before = pool.a_hits.load(Ordering::SeqCst);
    let mut a_probed = false;
    for _ in 0..20 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
        if pool.a_hits.load(Ordering::SeqCst) > a_before {
            a_probed = true;
            break;
        }
    }
    assert!(a_probed, "A received its half-open probe");

    // A is healthy again: traffic distributes across both endpoints.
    let (a0, b0) = (
        pool.a_hits.load(Ordering::SeqCst),
        pool.b_hits.load(Ordering::SeqCst),
    );
    for _ in 0..10 {
        h.send(get_request("/x")).await.expect("sent");
    }
    let a_gain = pool.a_hits.load(Ordering::SeqCst) - a0;
    let b_gain = pool.b_hits.load(Ordering::SeqCst) - b0;
    assert!(
        a_gain >= 3 && b_gain >= 3,
        "distribution resumed: a +{a_gain}, b +{b_gain}"
    );
}

#[tokio::test]
async fn volume_threshold_gates_ratio_ejection() {
    // Consecutive ejection effectively disabled (100); ratio 0.5 with a
    // minimum volume of 4 decides.
    let pool = pool_with_health(PassiveHealth {
        consecutive_failures: 100,
        failure_ratio: 0.5,
        failure_min_volume: 4,
        eject_ms: 60_000,
        ..PassiveHealth::default()
    })
    .await;
    let h = &pool.handle;
    pool.a_fail.store(true, Ordering::SeqCst);

    // Sends alternate A,B. After three A failures (volume 3 < 4) A is NOT
    // ejected: the seventh send still reaches A (its 4th observation).
    for i in 0..7 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert_eq!(
            resp.status(),
            if i % 2 == 0 {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            },
            "WRR alternates A (5xx) and B (200) until the ratio fires"
        );
    }
    assert_eq!(
        pool.a_hits.load(Ordering::SeqCst),
        4,
        "volume below threshold: A kept receiving traffic"
    );
    // The 4th failure (volume 4, failures 4, ratio 1.0 >= 0.5) ejected A.
    for _ in 0..6 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK, "only B serves now");
    }
    assert_eq!(pool.a_hits.load(Ordering::SeqCst), 4, "A stays ejected");
}

// --- extra e2e pools (single endpoint / fixed status) -------------------------

/// One local origin that ALWAYS serves `status` (classification tests).
async fn serve_status(listener: TcpListener, hits: Arc<AtomicU64>, status: StatusCode) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let hits = Arc::clone(&hits);
        let service = service_fn(move |_req: Request<Incoming>| {
            let hits = Arc::clone(&hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new()))).map(
                    |mut r| {
                        *r.status_mut() = status;
                        r
                    },
                )
            }
        });
        tokio::spawn(async move {
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn upstream_cfg(
    endpoints: Vec<Endpoint>,
    load_balancer: LoadBalancer,
    health: PassiveHealth,
) -> ConfigUpstream {
    ConfigUpstream {
        name: "pool".into(),
        load_balancer,
        protocol: UpstreamProtocol::Http1,
        endpoints,
        connection_cap: None,
        slow_start_ms: None,
        active_health: None,
        retries: None,
        health: Some(health),
        timeouts: None,
        breaker: None,
        max_pending: None,
        trusted_ca_file: None,
        oauth2_client_credentials: None,
    }
}

fn publish_registry(upstreams: Vec<ConfigUpstream>) -> UpstreamRegistry {
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
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
    };
    let state = ConfigState::new();
    state.compile_and_publish(&gw).expect("publish");
    UpstreamRegistry::from_snapshot(&state.snapshot())
}

/// Single-endpoint pool whose only origin serves 500 while `fail` is set.
async fn single_pool_with_health(
    health: PassiveHealth,
) -> (
    Arc<AtomicU64>,
    Arc<AtomicBool>,
    Arc<dwara_core::upstream::UpstreamHandle>,
) {
    let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = a.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU64::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    {
        let hits = Arc::clone(&hits);
        let fail = Arc::clone(&fail);
        tokio::spawn(async move {
            // same semantics as `serve`: 500 while `fail`, else 200
            let listener = a;
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let hits = Arc::clone(&hits);
                let fail = Arc::clone(&fail);
                let service = service_fn(move |_req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    let fail = fail.load(Ordering::SeqCst);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let status = if fail {
                            StatusCode::INTERNAL_SERVER_ERROR
                        } else {
                            StatusCode::OK
                        };
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
                            .map(|mut r| {
                                *r.status_mut() = status;
                                r
                            })
                    }
                });
                tokio::spawn(async move {
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
    }
    let registry = publish_registry(vec![upstream_cfg(
        vec![Endpoint {
            address: "127.0.0.1".into(),
            port,
            weight: 1,
        }],
        LoadBalancer::RoundRobin,
        health,
    )]);
    let handle = registry.get("pool").expect("handle");
    (hits, fail, handle)
}

/// Two-endpoint pool where A ALWAYS serves `a_status` and B serves 200.
async fn status_pool_with_health(
    a_status: StatusCode,
    health: PassiveHealth,
) -> (
    Arc<AtomicU64>,
    Arc<AtomicU64>,
    Arc<dwara_core::upstream::UpstreamHandle>,
) {
    let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a_port, b_port) = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    let a_hits = Arc::new(AtomicU64::new(0));
    let b_hits = Arc::new(AtomicU64::new(0));
    tokio::spawn(serve_status(a, Arc::clone(&a_hits), a_status));
    tokio::spawn(serve_status(b, Arc::clone(&b_hits), StatusCode::OK));
    let registry = publish_registry(vec![upstream_cfg(
        vec![
            Endpoint {
                address: "127.0.0.1".into(),
                port: a_port,
                weight: 1,
            },
            Endpoint {
                address: "127.0.0.1".into(),
                port: b_port,
                weight: 1,
            },
        ],
        LoadBalancer::RoundRobin,
        health,
    )]);
    let handle = registry.get("pool").expect("handle");
    (a_hits, b_hits, handle)
}

#[tokio::test]
async fn single_endpoint_pool_fails_open_and_recovers_through_fail_open_traffic() {
    // One endpoint, consecutive_failures 2, long eject_ms so recovery can
    // only happen through the fail-open path (no half-open during the
    // test): while ejected, requests STILL reach the endpoint (fail-open,
    // counted), and its first success restores health.
    let (hits, fail, h) = single_pool_with_health(PassiveHealth {
        consecutive_failures: 2,
        eject_ms: 600_000,
        ..PassiveHealth::default()
    })
    .await;

    fail.store(true, Ordering::SeqCst);
    for _ in 0..5 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        5,
        "fail-open kept traffic flowing"
    );
    assert!(
        h.lb().fail_open_picks() >= 3,
        "fail-open fallbacks are counted"
    );

    // The endpoint is ejected but still the only choice; fix it: the next
    // request's success (observed on an EJECTED endpoint) restores health.
    fail.store(false, Ordering::SeqCst);
    let resp = h.send(get_request("/x")).await.expect("sent");
    assert_eq!(resp.status(), StatusCode::OK);
    let counted = h.lb().fail_open_picks();
    // Healthy again: further picks are ordinary (the fail-open counter
    // stops growing) and traffic keeps flowing.
    for _ in 0..3 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 9);
    assert_eq!(
        h.lb().fail_open_picks(),
        counted,
        "no fail-open picks once the endpoint recovered"
    );
}

#[tokio::test]
async fn persistent_404s_keep_the_endpoint_healthy() {
    // 404 is a success for passive health (1xx-4xx classify as successes):
    // an endpoint serving ONLY 404s never ejects and keeps its share of
    // traffic no matter how many requests it answers.
    let (a_hits, _b_hits, h) = status_pool_with_health(
        StatusCode::NOT_FOUND,
        PassiveHealth {
            consecutive_failures: 3,
            ..PassiveHealth::default()
        },
    )
    .await;

    let mut saw_404 = false;
    for _ in 0..10 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        saw_404 |= resp.status() == StatusCode::NOT_FOUND;
    }
    assert!(saw_404, "A answered some of the traffic with 404s");
    assert!(a_hits.load(Ordering::SeqCst) >= 4, "A stayed in rotation");
    let before = a_hits.load(Ordering::SeqCst);
    for _ in 0..6 {
        h.send(get_request("/x")).await.expect("sent");
    }
    assert!(
        a_hits.load(Ordering::SeqCst) > before,
        "A still receives traffic after 16 straight 404s"
    );
}

#[tokio::test]
async fn persistent_503s_eject_the_endpoint() {
    // 503 is a 5xx failure: three in a row eject A and B takes everything.
    let (a_hits, _b_hits, h) = status_pool_with_health(
        StatusCode::SERVICE_UNAVAILABLE,
        PassiveHealth {
            consecutive_failures: 3,
            eject_ms: 600_000,
            ..PassiveHealth::default()
        },
    )
    .await;

    for _ in 0..8 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(a_hits.load(Ordering::SeqCst), 3, "A ejected after 3 x 503");
    for _ in 0..5 {
        let resp = h.send(get_request("/x")).await.expect("sent");
        assert_eq!(resp.status(), StatusCode::OK, "only B serves now");
    }
    assert_eq!(a_hits.load(Ordering::SeqCst), 3, "A stays ejected");
}

// --- validation of health knobs ------------------------------------------------

fn gateway_with_health(h: PassiveHealth) -> Gateway {
    Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams: vec![ConfigUpstream {
            name: "pool".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: vec![Endpoint {
                address: "127.0.0.1".into(),
                port: 9_000,
                weight: 1,
            }],
            connection_cap: None,
            slow_start_ms: None,
            active_health: None,
            retries: None,
            health: Some(h),
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
        // Zero-route: validates health knobs only; the opt-in keeps the
        // suite's issue assertions scoped to the upstream entity (#129).
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
    }
}

fn fields_rejected(gw: &Gateway) -> Vec<String> {
    validate(gw)
        .into_iter()
        .filter(|i| i.entity == "upstream")
        .map(|i| i.field)
        .collect()
}

#[test]
fn zero_or_negative_health_knobs_are_rejected() {
    // Every knob must be > 0. u64/u32 cannot go negative in the config
    // type; 0 is the representable floor and must be rejected per knob.
    let cases = [
        ("health.window_ms", health_full(0, 3, 0.5, 4, 1_000, 1)),
        (
            "health.consecutive_failures",
            health_full(1_000, 0, 0.5, 4, 1_000, 1),
        ),
        (
            "health.failure_ratio",
            health_full(1_000, 3, 0.0, 4, 1_000, 1),
        ),
        (
            "health.failure_min_volume",
            health_full(1_000, 3, 0.5, 0, 1_000, 1),
        ),
        ("health.eject_ms", health_full(1_000, 3, 0.5, 4, 0, 1)),
        (
            "health.half_open_probes",
            health_full(1_000, 3, 0.5, 4, 1_000, 0),
        ),
    ];
    for (field, h) in cases {
        let fields = fields_rejected(&gateway_with_health(h));
        assert!(
            fields.iter().any(|f| f == field),
            "expected {field} to be rejected, got {fields:?}"
        );
    }
}

#[test]
fn failure_ratio_out_of_unit_range_is_rejected() {
    // Above the unit range, and the NaN/inf floats that compare false
    // everywhere (and would silently disable ejection).
    for bad in [1.5, f64::INFINITY, f64::NAN] {
        let fields = fields_rejected(&gateway_with_health(health_full(
            1_000, 3, bad, 4, 1_000, 1,
        )));
        assert!(
            fields.iter().any(|f| f == "health.failure_ratio"),
            "ratio {bad} rejected"
        );
    }
    // Boundary ratios 1.0 and a small positive value are fine.
    for good in [1.0, 0.001] {
        let fields = fields_rejected(&gateway_with_health(health_full(
            1_000, 3, good, 4, 1_000, 1,
        )));
        assert!(
            fields.iter().all(|f| f != "health.failure_ratio"),
            "ratio {good} must be accepted, got {fields:?}"
        );
    }
}

#[test]
fn failure_ratio_nan_string_is_rejected_at_the_schema_level() {
    // A quoted string where a float is expected never deserializes; the
    // bare YAML .nan literal DOES parse as f64::NAN and is then rejected
    // by validation (covered structurally above); pinned here at the text
    // level both ways.
    let base = "listeners: []\nroutes: []\nservices: []\nconsumers: []\npolicies: []\nallow_empty_routes: true\nupstreams:\n  - name: pool\n    load_balancer: round_robin\n    protocol: http1\n    endpoints:\n      - address: 127.0.0.1\n        port: 9000\n    health:\n";
    assert!(
        parse_gateway(&format!("{base}      failure_ratio: \"NaN\"\n")).is_err(),
        "string ratio rejected at parse time"
    );
    let parsed = parse_gateway(&format!("{base}      failure_ratio: .nan\n"))
        .expect("YAML .nan parses as f64::NAN");
    let issues = validate(&parsed);
    assert!(
        issues.iter().any(|i| i.field == "health.failure_ratio"),
        "NaN float rejected by validation"
    );
}
