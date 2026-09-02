//! Unit tests for `dataplane::balance` (relocated from src; the
//! slow-start ramp test that inspects private balancer state stays in
//! src).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;

use dwara_core::config::{
    Endpoint, Gateway, LoadBalancer, PassiveHealth, Timeouts, Upstream as ConfigUpstream,
    UpstreamProtocol,
};
use dwara_core::dataplane::balance::UpstreamLb;
use dwara_core::dataplane::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;

fn eps(specs: &[(&str, u16, u32)]) -> Vec<Endpoint> {
    specs
        .iter()
        .map(|&(a, p, w)| Endpoint {
            address: a.to_string(),
            port: p,
            weight: w,
        })
        .collect()
}

/// Endpoints `prefix{i}` (i = 0..n) with the given weights.
fn eps_from_weights(prefix: &str, weights: &[u32]) -> Vec<Endpoint> {
    weights
        .iter()
        .enumerate()
        .map(|(i, &w)| Endpoint {
            address: format!("{prefix}{i}"),
            port: 80,
            weight: w,
        })
        .collect()
}

// --- smooth weighted round-robin --------------------------------------

#[test]
fn smooth_rr_classic_5_1_interleave() {
    // The canonical nginx example: a(5) b(1) c(1) -> a a b a c a a.
    let lb = UpstreamLb::new(
        &eps(&[
            ("10.0.0.1", 80, 5),
            ("10.0.0.2", 80, 1),
            ("10.0.0.3", 80, 1),
        ]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
    );
    let picks: Vec<usize> = (0..7).map(|_| lb.pick(None).unwrap()).collect();
    assert_eq!(picks, vec![0, 0, 1, 0, 2, 0, 0]);
}

proptest! {
    #[test]
    fn smooth_rr_period_counts_match_weights(
        weights in prop::collection::vec(1u32..=5, 2..=6)
    ) {
        let total: u32 = weights.iter().sum();
        let lb = UpstreamLb::new(
            &eps_from_weights("10.0.0.", &weights),
            LoadBalancer::RoundRobin,
            Duration::ZERO,
        );
        let mut counts = vec![0u32; weights.len()];
        for _ in 0..total {
            counts[lb.pick(None).unwrap()] += 1;
        }
        prop_assert_eq!(counts, weights);
    }

    #[test]
    fn smooth_rr_deterministic_sequence(
        weights in prop::collection::vec(1u32..=4, 2..=5)
    ) {
        let total: u32 = weights.iter().sum();
        let a = UpstreamLb::new(
            &eps_from_weights("10.1.0.", &weights),
            LoadBalancer::RoundRobin,
            Duration::ZERO,
        );
        let b = UpstreamLb::new(
            &eps_from_weights("10.1.0.", &weights),
            LoadBalancer::RoundRobin,
            Duration::ZERO,
        );
        let sa: Vec<usize> = (0..total).map(|_| a.pick(None).unwrap()).collect();
        let sb: Vec<usize> = (0..total).map(|_| b.pick(None).unwrap()).collect();
        prop_assert_eq!(sa, sb);
    }
}

// --- least connections --------------------------------------------------

#[test]
fn least_conn_picks_minimal_inflight_with_lowest_index_ties() {
    let lb = UpstreamLb::new(
        &eps(&[("a", 1, 1), ("b", 2, 1), ("c", 3, 1)]),
        LoadBalancer::LeastRequests,
        Duration::ZERO,
    );
    let _g0 = lb.acquire_inflight(0).unwrap();
    let _g2 = lb.acquire_inflight(2).unwrap();
    let _g2b = lb.acquire_inflight(2).unwrap();
    assert_eq!(lb.pick(None), Some(1), "endpoint 1 has zero inflight");
    drop(_g0);
    drop(_g2b);
    assert_eq!(lb.pick(None), Some(0), "0 and 2 tie at 1; lowest index");
    drop(_g2);
    // All-zero tie: lowest index, and guards returned to zero.
    assert_eq!(lb.inflight(2), 0);
    assert_eq!(lb.pick(None), Some(0));
}

proptest! {
    #[test]
    fn least_conn_always_minimal(
        inflight in prop::collection::vec(0u64..=7, 2..=6)
    ) {
        let n = inflight.len();
        let list = eps_from_weights("ep-", &vec![1u32; n]);
        let lb = UpstreamLb::new(&list, LoadBalancer::LeastRequests, Duration::ZERO);
        let guards: Vec<_> = (0..inflight.len()).flat_map(|i| {
            (0..inflight[i]).map(|_| lb.acquire_inflight(i).unwrap()).collect::<Vec<_>>()
        }).collect();
        let want = inflight.iter().enumerate().min_by_key(|(i, &v)| (v, *i)).unwrap().0;
        for _ in 0..20 {
            prop_assert_eq!(lb.pick(None), Some(want));
        }
        drop(guards);
    }
}

// --- random-2 -----------------------------------------------------------

#[test]
fn random_two_picks_lower_inflight_of_two_endpoints() {
    let lb = UpstreamLb::new(
        &eps(&[("a", 1, 1), ("b", 2, 1)]),
        LoadBalancer::Random,
        Duration::ZERO,
    );
    let g = lb.acquire_inflight(1).unwrap();
    for _ in 0..200 {
        assert_eq!(lb.pick(None), Some(0), "endpoint 0 has lower inflight");
    }
    drop(g);
}

// --- ketama / ip_hash ---------------------------------------------------

fn owned_keys(lb: &UpstreamLb, keys: &[String]) -> Vec<usize> {
    keys.iter()
        .map(|k| lb.pick(Some(k.as_str())).unwrap())
        .collect()
}

proptest! {
    #[test]
    fn ketama_remap_on_addition_is_minimal(n in 2usize..=6) {
        let keys: Vec<String> = (0..400).map(|i| format!("203.0.113.{i}")).collect();
        let spec = eps_from_weights("10.2.0.", &vec![1u32; n]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
        let before = owned_keys(&lb, &keys);
        // Add one endpoint: only keys whose ring segment was taken by
        // the newcomer (~1/(n+1)) may remap.
        let mut grown = spec.clone();
        grown.push(Endpoint {
            address: format!("10.2.0.{n}"),
            port: 80,
            weight: 1,
        });
        lb.rebuild(&grown, LoadBalancer::IpHash, Duration::ZERO);
        let after = owned_keys(&lb, &keys);
        let remapped = before.iter().zip(&after).filter(|(a, b)| a != b).count();
        let bound = (keys.len() * 2 / (n + 1)).max(8);
        prop_assert!(
            remapped <= bound,
            "remapped {remapped} of {} adding 1 to {n}",
            keys.len()
        );
    }

    #[test]
    fn ketama_distribution_uniform_within_tolerance(n in 2usize..=4) {
        let keys: Vec<String> = (0..800).map(|i| format!("198.51.100.{i}")).collect();
        let spec = eps_from_weights("10.3.0.", &vec![1u32; n]);
        let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
        let owners = owned_keys(&lb, &keys);
        let ideal = 1.0f64 / n as f64;
        for i in 0..n {
            let share =
                owners.iter().filter(|&&o| o == i).count() as f64 / keys.len() as f64;
            prop_assert!(
                (share - ideal).abs() < 0.2,
                "endpoint {i} share {share:.3} vs ideal {ideal:.3}"
            );
        }
    }
}

#[test]
fn ketama_same_key_is_sticky_and_weights_skew_distribution() {
    let spec = eps(&[("a", 1, 1), ("b", 2, 3)]);
    let lb = UpstreamLb::new(&spec, LoadBalancer::IpHash, Duration::ZERO);
    let first = lb.pick(Some("203.0.113.9"));
    assert_eq!(lb.pick(Some("203.0.113.9")), first);
    // Weighted vnodes: the weight-3 endpoint should own the clear
    // majority of keys.
    let keys: Vec<String> = (0..300).map(|i| format!("192.0.2.{i}")).collect();
    let owned_b = owned_keys(&lb, &keys).iter().filter(|&&o| o == 1).count();
    assert!(owned_b > 150, "weight-3 endpoint owned only {owned_b}/300");
}

// --- slow start (the ramp test stays in src: private state) ------------

// --- hot swap / carry-over ----------------------------------------------

#[test]
fn rebuild_carries_wrr_phase_and_inflight_for_unchanged_addresses() {
    let spec = eps(&[("a", 1, 2), ("b", 2, 1)]);
    let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    // Fresh sequence for (2,1): a b a | a b a.
    assert_eq!(lb.pick(None), Some(0));
    let guard = lb.acquire_inflight(0).unwrap();
    // Same-set rebuild: phase and inflight carry; the next picks must
    // CONTINUE the sequence (b a), not restart it (a b).
    lb.rebuild(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    assert_eq!(lb.inflight(0), 1);
    assert_eq!(lb.pick(None), Some(1));
    assert_eq!(lb.pick(None), Some(0));
    drop(guard);
    assert_eq!(lb.inflight(0), 0);
}

/// #128: a rebuild must not reset the WRR phase SEQUENCE. The pick
/// sequence of a balancer that was rebuilt mid-period equals the
/// uninterrupted sequence of a fresh one (the in-flight/shared-cell half
/// of the fix is pinned white-box in src/dataplane/balance.rs).
#[test]
fn rebuild_does_not_reset_the_wrr_phase_sequence() {
    let spec = eps(&[("a", 1, 3), ("b", 2, 2)]);
    let baseline = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    // One full period (weights 3+2 = 5 picks) without interruption.
    let uninterrupted: Vec<usize> = (0..5).map(|_| baseline.pick(None).unwrap()).collect();

    let reloaded = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    let mut across_reload = Vec::with_capacity(5);
    for _ in 0..2 {
        across_reload.push(reloaded.pick(None).unwrap());
    }
    // Reload mid-period (same endpoint set, as a config-only reload does).
    reloaded.rebuild(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    while across_reload.len() < 5 {
        across_reload.push(reloaded.pick(None).unwrap());
    }
    assert_eq!(
        across_reload, uninterrupted,
        "picks across a rebuild must continue the uninterrupted WRR sequence"
    );
}

#[test]
fn rebuild_with_new_weights_takes_effect_immediately() {
    let spec = eps(&[("a", 1, 2), ("b", 2, 1)]);
    let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    let _ = lb.pick(None);
    let reweighted = eps(&[("a", 1, 1), ("b", 2, 2)]);
    lb.rebuild(&reweighted, LoadBalancer::RoundRobin, Duration::ZERO);
    let mut counts = [0u32; 2];
    for _ in 0..3 {
        counts[lb.pick(None).unwrap()] += 1;
    }
    assert_eq!(counts, [1, 2], "new weights apply without restart");
}

#[test]
fn rebuild_resets_state_for_removed_and_readded_endpoints() {
    let spec = eps(&[("a", 1, 1), ("b", 2, 1)]);
    let lb = UpstreamLb::new(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    let _ = lb.pick(None);
    let _g = lb.acquire_inflight(1).unwrap();
    // Drop endpoint b (its inflight leaves with it), re-add later: fresh.
    lb.rebuild(
        &eps(&[("a", 1, 1)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
    );
    assert_eq!(lb.len(), 1);
    assert_eq!(lb.pick(None), Some(0));
    lb.rebuild(&spec, LoadBalancer::RoundRobin, Duration::ZERO);
    assert_eq!(lb.inflight(1), 0, "re-added endpoint starts fresh");
}

// --- passive health: single-candidate half-open (reviewer pin) ---------

#[test]
fn single_candidate_half_open_consumes_probe_budget() {
    use std::sync::atomic::AtomicU64;

    // Deterministic clock: the closure is a plain fn pointer, so the
    // "now" lives in a test-local static.
    static NOW_MS: AtomicU64 = AtomicU64::new(100_000);
    let health = PassiveHealth {
        window_ms: 60_000,
        consecutive_failures: 2,
        failure_ratio: 0.5,
        failure_min_volume: 1000, // isolate the consecutive-failure path
        eject_ms: 1_000,
        half_open_probes: 2,
    };
    let lb = UpstreamLb::new_with_health(
        &eps(&[("solo", 80, 1)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
        Some(&health),
    );
    lb.set_health_clock(|| NOW_MS.load(Ordering::Relaxed));
    let now = || NOW_MS.load(Ordering::Relaxed);

    // Eject the sole endpoint: two consecutive reported failures.
    for _ in 0..2 {
        let d = lb.pick_for_dispatch(None).unwrap();
        d.health.as_ref().unwrap().report(now(), true);
    }
    // Inside the ejection window the single candidate is unavailable:
    // the pick fail-opens to the full (sole-endpoint) set.
    assert_eq!(lb.pick(None), Some(0));
    assert_eq!(lb.fail_open_picks(), 1, "ejected sole endpoint fail-opens");

    // Ejection expired: the endpoint re-enters half-open with a budget
    // of 2 probes, and EVERY single-candidate pick consumes one slot.
    NOW_MS.store(101_001, Ordering::Relaxed);
    let probe1 = lb.pick_for_dispatch(None).unwrap();
    assert_eq!(lb.fail_open_picks(), 1, "half-open pick is a real pick");
    let _probe2 = lb.pick_for_dispatch(None).unwrap();
    // Budget exhausted: both probes were consumed by the two picks, so
    // the tracker gates further picks until one probe resolves.
    assert!(!probe1
        .health
        .as_ref()
        .unwrap()
        .tracker()
        .is_available(now()));
    assert_eq!(lb.pick(None), Some(0));
    assert_eq!(lb.fail_open_picks(), 2, "exhausted budget fail-opens");

    // A successful probe restores health; picks return to normal.
    probe1.health.as_ref().unwrap().report(now(), false);
    assert_eq!(lb.pick(None), Some(0));
    assert_eq!(lb.fail_open_picks(), 2, "healthy pick is not fail-open");
}

// --- integration through DataPlane (weights change via publish) ---------

fn upstream_with_weights(w: (u32, u32)) -> ConfigUpstream {
    ConfigUpstream {
        name: "pool".into(),
        load_balancer: LoadBalancer::RoundRobin,
        protocol: UpstreamProtocol::Http1,
        endpoints: vec![
            Endpoint {
                address: "10.9.0.1".into(),
                port: 80,
                weight: w.0,
            },
            Endpoint {
                address: "10.9.0.2".into(),
                port: 80,
                weight: w.1,
            },
        ],
        connection_cap: None,
        timeouts: Some(Timeouts {
            connect_ms: Some(60000),
            read_ms: None,
            write_ms: None,
            happy_eyeballs_ms: None,
        }),
        slow_start_ms: None,
        health: None,
        active_health: None,
        retries: None,
        breaker: None,
        max_pending: None,
        trusted_ca_file: None,
        oauth2_client_credentials: None,
        dns_discovery: None,
        peak_ewma: None,
    }
}

#[tokio::test]
async fn dataplane_reload_changes_weights_without_restart() {
    let st = Arc::new(ConfigState::new());
    let mut g = Gateway {
        trusted_proxies: vec![],
        listeners: vec![],
        routes: vec![],
        services: vec![],
        upstreams: vec![upstream_with_weights((2, 1))],
        consumers: vec![],
        policies: vec![],
        global_policies: Vec::new(),
        authorization: None,
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        // Genuinely zero-route: LB weight behavior, not routing (#129).
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
        oidc_providers: Vec::new(),
        redis_rate_limiter: None,
        config_convergence: None,
        plugins: Vec::new(),
        ai: None,
    };
    st.compile_and_publish(&g).expect("publish A");
    let dp = DataPlane::new(Arc::clone(&st));
    let h = dp.registry().get("pool").unwrap();
    let mut c1 = [0u32; 2];
    for _ in 0..3 {
        c1[h.lb().pick(None).unwrap()] += 1;
    }
    assert_eq!(c1, [2, 1], "original weights");

    // The reload flow: publish new weights on the SAME state, then
    // refresh the dataplane (what dwara-bin's reload path does).
    g.upstreams = vec![upstream_with_weights((1, 2))];
    st.compile_and_publish(&g).expect("publish B");
    dp.refresh();
    let h2 = dp.registry().get("pool").unwrap();
    let mut c2 = [0u32; 2];
    for _ in 0..3 {
        c2[h2.lb().pick(None).unwrap()] += 1;
    }
    assert_eq!(c2, [1, 2], "weights changed without restart");
}
