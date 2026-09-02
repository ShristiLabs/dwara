//! Integration tests for Peak-EWMA latency-aware load balancing (DW-090).
//!
//! These tests exercise the balancer's `peak_ewma` algorithm through the
//! public API: `UpstreamLb::new`, `pick`, `record_latency`, and
//! `peak_ewma_cost`. They verify the Finagle-style peak-EWMA formula
//! (peak replacement, exponential decay, `cost * (inflight + 1)` scoring)
//! and the carry-across-rebuild invariant for the latency tracker.

use std::time::Duration;

use dwara_core::config::{Endpoint, LoadBalancer, PeakEwmaConfig};
use dwara_core::dataplane::balance::UpstreamLb;

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

#[test]
fn peak_ewma_initial_cost_is_default_rtt() {
    // The initial cost for a fresh tracker is `default_rtt_ms` in
    // nanoseconds. With the default 250 ms, that's 250_000_000 ns.
    let lb = UpstreamLb::new(
        &eps(&[("a", 80, 1), ("b", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
    );
    let cost0 = lb.peak_ewma_cost(0).expect("tracker exists for peak_ewma");
    let cost1 = lb.peak_ewma_cost(1).expect("tracker exists for peak_ewma");
    // Both start at the default initial cost (250 ms = 250_000_000 ns).
    assert_eq!(cost0, 250_000_000);
    assert_eq!(cost1, 250_000_000);
}

#[test]
fn peak_ewma_custom_initial_cost() {
    // A custom default_rtt_ms sets the initial cost.
    let cfg = PeakEwmaConfig {
        decay_ms: Some(10_000),
        default_rtt_ms: Some(100),
    };
    let lb = UpstreamLb::new_with_health(
        &eps(&[("a", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
        None,
    );
    // We need to use new_with_health_and_events to pass the peak_ewma
    // config. The new() path doesn't pass it.
    let lb2 = UpstreamLb::new_with_health_and_events(
        &eps(&[("a", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
        None,
        None,
        Some(&cfg),
    );
    let cost = lb2.peak_ewma_cost(0).expect("tracker exists");
    // 100 ms = 100_000_000 ns
    assert_eq!(cost, 100_000_000);
    // The lb without config uses the default 250 ms.
    let cost_default = lb.peak_ewma_cost(0).expect("tracker exists");
    assert_eq!(cost_default, 250_000_000);
}

#[test]
fn peak_ewma_peak_replacement() {
    // When a recorded latency EXCEEDS the current cost, the cost is
    // replaced outright (the "peak").
    let cfg = PeakEwmaConfig {
        decay_ms: Some(10_000),
        default_rtt_ms: Some(100),
    };
    let lb = UpstreamLb::new_with_health_and_events(
        &eps(&[("a", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
        None,
        None,
        Some(&cfg),
    );
    // Initial cost: 100 ms = 100_000_000 ns.
    assert_eq!(lb.peak_ewma_cost(0).unwrap(), 100_000_000);
    // Record a latency of 500 ms (exceeds the current cost).
    lb.record_latency(0, Duration::from_millis(500));
    // The cost should now be 500 ms = 500_000_000 ns (peak replacement).
    assert_eq!(lb.peak_ewma_cost(0).unwrap(), 500_000_000);
}

#[test]
fn peak_ewma_decay_toward_lower_rtt() {
    // When a recorded latency is BELOW the current cost, the cost
    // decays toward the new RTT. With a large decay window (tau) and
    // a small time delta, the weight w is close to 1, so the cost
    // barely moves. With a small tau and a large time delta, w
    // approaches 0 and the cost approaches the new RTT.
    let cfg = PeakEwmaConfig {
        decay_ms: Some(10_000), // 10s tau
        default_rtt_ms: Some(500),
    };
    let lb = UpstreamLb::new_with_health_and_events(
        &eps(&[("a", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
        None,
        None,
        Some(&cfg),
    );
    // Initial cost: 500 ms.
    assert_eq!(lb.peak_ewma_cost(0).unwrap(), 500_000_000);
    // Record a latency of 100 ms (below the current cost). The time
    // delta is near-zero (same instant), so w ~ 1 and the cost barely
    // moves. The new cost should be slightly below 500 ms but well
    // above 100 ms.
    lb.record_latency(0, Duration::from_millis(100));
    let cost = lb.peak_ewma_cost(0).unwrap();
    assert!(
        cost > 400_000_000,
        "cost should barely decay with near-zero time delta, got {cost}"
    );
    assert!(
        cost < 500_000_000,
        "cost should decay at least slightly, got {cost}"
    );
}

#[test]
fn peak_ewma_picks_lowest_score() {
    // With two endpoints at the same initial cost, the one with fewer
    // in-flight requests wins (lower `cost * (inflight + 1)` score).
    let lb = UpstreamLb::new(
        &eps(&[("a", 80, 1), ("b", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
    );
    // Acquire inflight on endpoint 0 (inflight = 1).
    let _guard = lb.acquire_inflight(0).expect("endpoint exists");
    // Pick should select endpoint 1 (inflight 0, score = cost * 1)
    // over endpoint 0 (inflight 1, score = cost * 2).
    let idx = lb.pick(None).unwrap();
    assert_eq!(idx, 1, "should pick the endpoint with fewer in-flight");
}

#[test]
fn peak_ewma_picks_faster_endpoint_after_latency() {
    // After recording a high latency on endpoint 0, the balancer
    // should prefer endpoint 1 (lower cost).
    let cfg = PeakEwmaConfig {
        decay_ms: Some(10_000),
        default_rtt_ms: Some(100),
    };
    let lb = UpstreamLb::new_with_health_and_events(
        &eps(&[("a", 80, 1), ("b", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
        None,
        None,
        Some(&cfg),
    );
    // Record a slow latency on endpoint 0 (peak replacement to 500 ms).
    lb.record_latency(0, Duration::from_millis(500));
    // Both have 0 in-flight. Endpoint 0 cost = 500M, endpoint 1 cost =
    // 100M. Endpoint 1 has the lower score.
    let idx = lb.pick(None).unwrap();
    assert_eq!(idx, 1, "should pick the faster endpoint");
}

#[test]
fn peak_ewma_tracker_carries_across_rebuild() {
    // The peak-EWMA tracker is carried across a rebuild for unchanged
    // addresses (the live cost history survives the swap).
    let cfg = PeakEwmaConfig {
        decay_ms: Some(10_000),
        default_rtt_ms: Some(100),
    };
    let lb = UpstreamLb::new_with_health_and_events(
        &eps(&[("a", 80, 1), ("b", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
        None,
        None,
        Some(&cfg),
    );
    // Record a high latency on endpoint 0.
    lb.record_latency(0, Duration::from_millis(500));
    assert_eq!(lb.peak_ewma_cost(0).unwrap(), 500_000_000);
    // Rebuild with the same endpoints. The tracker should carry.
    lb.rebuild_with_health_and_events(
        &eps(&[("a", 80, 1), ("b", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
        None,
        None,
        Some(&cfg),
    );
    // The cost should be unchanged (the tracker was carried, not reset).
    assert_eq!(
        lb.peak_ewma_cost(0).unwrap(),
        500_000_000,
        "peak-EWMA cost must survive a rebuild for unchanged addresses"
    );
}

#[test]
fn peak_ewma_no_op_for_other_algorithms() {
    // record_latency is a no-op when the algorithm is not peak_ewma
    // (the tracker is absent).
    let lb = UpstreamLb::new(
        &eps(&[("a", 80, 1)]),
        LoadBalancer::RoundRobin,
        Duration::ZERO,
    );
    // No tracker -> peak_ewma_cost returns None.
    assert!(lb.peak_ewma_cost(0).is_none());
    // record_latency should not panic.
    lb.record_latency(0, Duration::from_millis(100));
    assert!(lb.peak_ewma_cost(0).is_none());
}

#[test]
fn peak_ewma_out_of_range_index_is_safe() {
    // record_latency and peak_ewma_cost with an out-of-range index
    // are safe (no panic).
    let lb = UpstreamLb::new(
        &eps(&[("a", 80, 1)]),
        LoadBalancer::PeakEwma,
        Duration::ZERO,
    );
    lb.record_latency(99, Duration::from_millis(100));
    assert!(lb.peak_ewma_cost(99).is_none());
}
