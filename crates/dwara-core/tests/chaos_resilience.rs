//! Chaos / end-to-end resilience fault-injection suite (REL-02, #173).
//!
//! The resilience features (circuit breaker, outlier ejection, retry
//! budgets, load shedding, zero-dropped across reload) are each pinned by
//! focused integration suites (`breaker_caps`, `passive_health`,
//! `retries_timeouts`, `load_shedding`, and `zero_downtime_upgrade` in
//! dwara-bin). This suite is the CONTINUOUSLY-VERIFIED promise layer: it
//! drives REAL fault injection (killed backends, injected 5xx, induced
//! latency, mid-stream config reload) through the full proxy path and
//! asserts the resilience machinery behaves end to end, not in isolation.
//!
//! What makes this a chaos suite vs the focused suites:
//! - faults are injected on LIVE traffic against real in-process backends
//!   (a backend flips to 500 mid-run, an endpoint is killed, latency is
//!   injected, the config is hot-reloaded under load);
//! - each test crosses feature boundaries (breaker + health, retries +
//!   ejection, shedding + reload) the way a real outage would;
//! - assertions observe BOTH the client-visible behavior (status codes,
//!   zero drops) AND the internal state machines (`Breaker::state`,
//!   `EndpointHealth::ejections`, `RetryBudget::retries`,
//!   `PriorityCounters`) so a silent regression in either layer is caught.
//!
//! Determinism: every backend binds an ephemeral loopback port (unique by
//! construction), timing windows are tiny with generous margins, and
//! readiness is bounded-polled. Breaker cooldowns use bounded state polling
//! (`wait_for_breaker_cooldown`) and traffic establishment uses counter
//! polling (`wait_for_traffic`). The remaining fixed waits are real-clock
//! duration windows (ejection cooldowns, traffic-through-reload windows,
//! slow-request saturation) that are inherent to the fault-injection
//! timing and documented inline.
//!
//! The suite is gated to a SEPARATE CI job (`.github/workflows/chaos.yml`,
//! scheduled + dispatch only) because the fault-injection timing makes it
//! slower than the per-PR gate; it is NOT part of ci.yml.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::dataplane::proxy::{DataPlane, DEFAULT_PRIORITY};
use dwara_core::resilience::breaker::BreakerState;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

mod support;

use support::{dataplane_from, envelope_code, h1_client, spawn_gateway, state_from, uri};

// --- shared infrastructure ---------------------------------------------------

/// Gateway YAML: one `/api` route to one upstream, with `upstream_extra`
/// spliced into the upstream block and `gateway_extra` prepended as
/// gateway-level keys.
fn gateway_yaml(backend_port: u16, upstream_extra: &str, gateway_extra: &str) -> String {
    support::gateway_yaml(gateway_extra, backend_port, None, upstream_extra)
}

/// Gateway YAML with TWO endpoints (for outlier-ejection failover tests).
fn two_endpoint_gateway_yaml(
    backend_port: u16,
    backend_port2: u16,
    upstream_extra: &str,
    gateway_extra: &str,
) -> String {
    support::gateway_yaml(
        gateway_extra,
        backend_port,
        Some(backend_port2),
        upstream_extra,
    )
}

/// A backend whose health can be flipped at runtime via an `AtomicBool`
/// (true = 200, false = 500). Returns the bound port and the switch.
async fn spawn_flipping_backend() -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let healthy = Arc::new(AtomicBool::new(true));
    let switch = Arc::clone(&healthy);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let healthy = Arc::clone(&healthy);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_req: Request<Incoming>| {
                            let healthy = Arc::clone(&healthy);
                            async move {
                                let status = if healthy.load(Ordering::Relaxed) {
                                    StatusCode::OK
                                } else {
                                    StatusCode::INTERNAL_SERVER_ERROR
                                };
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, switch)
}

/// A backend that serves 200 after a per-request `delay`. Returns the
/// bound port (used to saturate the gateway cap deterministically).
async fn spawn_slow_backend(delay: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let delay = delay;
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_req: Request<Incoming>| async move {
                            tokio::time::sleep(delay).await;
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                        }),
                    )
                    .await;
            });
        }
    });
    port
}

/// A backend that counts every hit and serves 200 for the first `warmup`
/// requests, then 503 forever after. Used to grow the retry-budget
/// denominator before injecting failures.
async fn spawn_warmup_then_fail_backend(warmup: u64) -> (u16, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let counter = Arc::clone(&counter);
                            async move {
                                let _ = req.into_body().collect().await;
                                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                                let status = if n <= warmup {
                                    StatusCode::OK
                                } else {
                                    StatusCode::SERVICE_UNAVAILABLE
                                };
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (port, count)
}

async fn body_full<B>(resp: Response<B>) -> (StatusCode, Bytes)
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, bytes)
}

/// Like [`body_full`] but also returns the response headers (needed for
/// the breaker's Retry-After assertion).
async fn body_full_with_headers<B>(resp: Response<B>) -> (StatusCode, Bytes, hyper::HeaderMap)
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::fmt::Debug + Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, bytes, parts.headers)
}

/// Bounded readiness poll: a single GET against the gateway until it
/// answers 200 (or any non-connection-error), with a deadline. Never a
/// sleep used as synchronization.
async fn wait_for_gateway(client: &Client<HttpConnector, Full<Bytes>>, gw: u16, deadline: Instant) {
    while Instant::now() < deadline {
        if client.get(uri(gw, "/api/ready")).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("gateway on port {gw} did not become ready by the deadline");
}

/// Poll a closure until it returns true or the deadline expires. Replaces
/// fixed cooldown sleeps with bounded state polling.
async fn wait_until<F: Fn() -> bool>(cond: F, deadline: Instant) {
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not met by the deadline");
}

/// Poll until at least `min` requests have been served (counter-based
/// traffic establishment, replacing fixed sleep-as-synchronization).
async fn wait_for_traffic(total: &AtomicUsize, min: usize, deadline: Instant) {
    wait_until(|| total.load(Ordering::Relaxed) >= min, deadline).await;
}

/// Poll the breaker state until its cooldown has elapsed (the `until_ms`
/// in the `Open` state is in the past). This is a bounded poll, not a
/// fixed sleep — it adapts to the actual cooldown duration.
async fn wait_for_breaker_cooldown(
    handle: &dwara_core::dataplane::upstream::UpstreamHandle,
    deadline: Instant,
) {
    let now_ms = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    };
    wait_until(
        || match handle.breaker().state() {
            BreakerState::Open { until_ms } => now_ms() >= until_ms,
            _ => true,
        },
        deadline,
    )
    .await;
}

// ============================================================================
// 1. Breaker transitions: open -> half-open -> close under live fault injection
// ============================================================================

/// Inject upstream 5xx by flipping a live backend to failing, verify the
/// breaker OPENS (fail-fast 503 + Retry-After, no backend attempt), then
/// flip the backend back to healthy, wait past `open_ms`, and verify the
/// half-open probe CLOSES the breaker (subsequent traffic flows 200). The
/// internal `Breaker::state` is inspected at each transition so a silent
/// state-machine regression is caught alongside the client-visible behavior.
#[tokio::test]
async fn breaker_open_half_open_close_under_live_fault_injection() {
    let (port, healthy) = spawn_flipping_backend().await;
    // consecutive_failures 3, short open_ms so the half-open probe arrives
    // quickly (deterministic: the cool-off is real-clock but tiny).
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 3\n    open_ms: 400\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    wait_for_gateway(&client, gw, Instant::now() + Duration::from_secs(5)).await;

    // Inject the fault: flip the backend to failing.
    healthy.store(false, Ordering::Relaxed);

    // Drive three failures through the real proxy to trip the breaker.
    for _ in 0..3 {
        let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // The breaker is now OPEN: the 4th request fails fast (503 +
    // Retry-After) with no backend attempt. Inspect the state machine.
    let handle = dp.registry().get("up").expect("upstream handle");
    assert!(
        matches!(handle.breaker().state(), BreakerState::Open { .. }),
        "breaker must be Open after consecutive failures"
    );
    let started = Instant::now();
    let (status, body, headers) =
        body_full_with_headers(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert!(
        headers.get("retry-after").is_some(),
        "open breaker must advertise Retry-After"
    );
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "fail-fast must not wait on the upstream, took {:?}",
        started.elapsed()
    );

    // Recover the fault: flip the backend back to healthy.
    healthy.store(true, Ordering::Relaxed);

    // Wait for the breaker cooldown to elapse (bounded poll of the
    // breaker's `until_ms`, not a fixed sleep). The next request is
    // admitted as a half-open probe and CLOSES the breaker.
    wait_for_breaker_cooldown(&handle, Instant::now() + Duration::from_secs(5)).await;
    let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "half-open probe closes the breaker");

    // Closed: traffic flows and the state machine confirms it.
    let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        matches!(handle.breaker().state(), BreakerState::Closed { .. }),
        "breaker must be Closed after a successful probe"
    );
}

/// A half-open probe that FAILS (the backend is still broken) must RE-OPEN
/// the breaker, failing fast again. The full open -> half-open -> re-open
/// cycle under live fault injection.
#[tokio::test]
async fn breaker_half_open_failure_reopens_under_live_fault() {
    let (port, healthy) = spawn_flipping_backend().await;
    let yaml = gateway_yaml(
        port,
        "  breaker:\n    consecutive_failures: 2\n    open_ms: 300\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    wait_for_gateway(&client, gw, Instant::now() + Duration::from_secs(5)).await;

    // Fault: backend fails and STAYS failing (no recovery).
    healthy.store(false, Ordering::Relaxed);
    for _ in 0..2 {
        let _ = client.get(uri(gw, "/api/x")).await.unwrap();
    }
    assert!(
        matches!(
            dp.registry().get("up").unwrap().breaker().state(),
            BreakerState::Open { .. }
        ),
        "breaker open after two failures"
    );

    // Cool off: wait for the breaker cooldown to elapse (bounded poll).
    // The next request is a half-open probe. The backend is still
    // failing, so the probe sees a real 500 (not a fail-fast) and
    // RE-OPENS the breaker.
    let handle = dp.registry().get("up").expect("upstream handle");
    wait_for_breaker_cooldown(&handle, Instant::now() + Duration::from_secs(5)).await;
    let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "half-open probe passes through to the still-failing backend"
    );

    // Re-opened: the very next request fails fast again.
    let (status, body, _) =
        body_full_with_headers(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert!(
        matches!(
            dp.registry().get("up").unwrap().breaker().state(),
            BreakerState::Open { .. }
        ),
        "breaker re-opened after a failed probe"
    );
}

// ============================================================================
// 2. Outlier ejection: inject failures on one endpoint, verify ejection +
//    failover, then recovery via half-open probe
// ============================================================================

/// Two endpoints: one always healthy, one flippable. Inject failures on the
/// flippable endpoint via real traffic; verify it is EJECTED (ejections > 0)
/// and traffic fails over to the healthy endpoint (every request still
/// succeeds). Then flip the bad endpoint back to healthy and verify it
/// RECOVERS via a half-open probe after `eject_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outlier_ejection_then_failover_then_recovery_e2e() {
    let (good_port, _good_switch) = spawn_flipping_backend().await;
    let (bad_port, bad_healthy) = spawn_flipping_backend().await;
    // Eject after 3 consecutive failures; short eject_ms so recovery is
    // observable quickly. Round-robin so both endpoints receive traffic.
    let yaml = two_endpoint_gateway_yaml(
        good_port,
        bad_port,
        "  load_balancer: round_robin\n  health:\n    consecutive_failures: 3\n    failure_ratio: 0.99\n    failure_min_volume: 1000\n    window_ms: 60000\n    eject_ms: 400\n    half_open_probes: 1\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    wait_for_gateway(&client, gw, Instant::now() + Duration::from_secs(5)).await;

    // Inject the fault: the bad endpoint starts failing.
    bad_healthy.store(false, Ordering::Relaxed);

    // Drive enough traffic to land 3 consecutive failures on the bad
    // endpoint (round-robin alternates, so ~6 requests guarantees it).
    // Every request must still SUCCEED via failover to the good endpoint.
    let mut ok = 0;
    for _ in 0..8 {
        let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        if status == StatusCode::OK {
            ok += 1;
        }
    }
    assert!(
        ok >= 5,
        "failover must keep traffic succeeding during ejection: {ok}/8 OK"
    );

    // Inspect the state machine: the bad endpoint was ejected at least once.
    let handle = dp.registry().get("up").expect("upstream handle");
    let mut bad_ejections = 0u64;
    for (_addr, port, health) in handle.lb().health_targets() {
        if port == bad_port {
            if let Some(h) = health {
                bad_ejections = h.ejections();
            }
        }
    }
    assert!(
        bad_ejections >= 1,
        "the failing endpoint must be ejected (got {bad_ejections} ejections)"
    );

    // Recover the fault: flip the bad endpoint back to healthy.
    bad_healthy.store(true, Ordering::Relaxed);

    // Wait past eject_ms so the next pick arms a half-open probe on the
    // recovered endpoint. This is a real-clock wait for the ejection
    // cooldown (the ejection timer is wall-clock based, like the breaker).
    // Drive traffic: the probe succeeds and the endpoint returns to
    // rotation (no new ejections).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let ejects_before = bad_ejections;
    let mut ok = 0;
    for _ in 0..10 {
        let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        if status == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 10, "all traffic succeeds after recovery");

    // No NEW ejections during the recovery window (the probe closed it).
    let mut bad_ejections_after = 0u64;
    for (_addr, port, health) in handle.lb().health_targets() {
        if port == bad_port {
            if let Some(h) = health {
                bad_ejections_after = h.ejections();
            }
        }
    }
    assert_eq!(
        bad_ejections_after, ejects_before,
        "no new ejections after a successful recovery probe"
    );
}

// ============================================================================
// 3. Retry budgets: inject intermittent failures, verify retries stay
//    within the budget invariant
// ============================================================================

/// Configure a retry budget at a low percent with a high attempt cap (so
/// the BUDGET, not the attempt count, is the binding constraint). Warm up
/// the budget denominator with successful requests, then inject a burst of
/// failing requests and verify the in-window retry count NEVER exceeds the
/// budget invariant `retries * 100 <= percent * requests` (where
/// `requests = totals - retries`). Both the client-visible behavior (503
/// fail-through once the budget is exhausted) and the internal
/// `RetryBudget` state are inspected.
#[tokio::test]
async fn retry_budget_bounds_retries_under_intermittent_failures_e2e() {
    const WARMUP: u64 = 20;
    const FAIL_REQUESTS: u64 = 40;
    const PERCENT: u64 = 10;

    let (port, hits) = spawn_warmup_then_fail_backend(WARMUP).await;
    let retries_yaml = format!(
        "  retries:\n\
         \x20   attempts: 10\n\
         \x20   retry_post: false\n\
         \x20   backoff_base_ms: 1\n\
         \x20   backoff_cap_ms: 2\n\
         \x20   budget_percent: {PERCENT}\n\
         \x20   buffer_max_bytes: 65536\n"
    );
    let dp = dataplane_from(&gateway_yaml(port, &retries_yaml, ""));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    // No readiness poll here: it would consume the warmup 200s (the
    // backend flips to 503 after `WARMUP` hits). The gateway is ready as
    // soon as spawn_gateway returns (listener bound), matching the
    // existing retries_timeouts suite pattern.
    let mut warmed = 0u64;
    while warmed < WARMUP {
        let (status, _) = body_full(client.get(uri(gw, "/api/w")).await.unwrap()).await;
        if status == StatusCode::OK {
            warmed += 1;
        }
    }

    // Inject the fault: the backend now returns 503 for every request.
    // Drive a burst; the budget must bound the retry blast radius.
    for _ in 0..FAIL_REQUESTS {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri(gw, "/api/f"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Once the budget is exhausted, 503 fails through to the client.
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = resp.into_body().collect().await;
    }

    // Client-visible: the backend was hit more than FAIL_REQUESTS (retries
    // happened) but the budget bounded them.
    let attempts = hits.load(Ordering::SeqCst);
    let total_requests = WARMUP + FAIL_REQUESTS;
    let retries = attempts - total_requests;
    assert!(
        retries * 100 <= PERCENT * total_requests,
        "budget invariant violated: {retries} retries for {total_requests} \
         requests at {PERCENT}% ({attempts} backend attempts)"
    );
    assert!(
        retries >= 1,
        "the budget must allow some retries before exhausting: got {retries}"
    );

    // Internal state: the in-window retry count is consistent with the
    // client-observed blast radius (the budget is the authoritative cap).
    let handle = dp.registry().get("up").unwrap();
    let budget = handle.retry_budget();
    let in_window_retries = budget.retries() as u64;
    let in_window_totals = budget.totals() as u64;
    let in_window_requests = in_window_totals - in_window_retries;
    assert!(
        in_window_retries * 100 <= PERCENT * in_window_requests,
        "RetryBudget state violates the invariant: {in_window_retries} retries \
         / {in_window_requests} requests ({in_window_totals} totals) at {PERCENT}%"
    );
    assert!(
        in_window_retries >= 1,
        "RetryBudget must record the retries that happened"
    );
}

// ============================================================================
// 4. Load shedding: overload the gateway cap, verify shedding kicks in
//    immediately while admitted traffic succeeds
// ============================================================================

/// Configure `max_concurrent_requests` at a small cap with a slow backend.
/// Overload the gateway with concurrent requests beyond the cap: the
/// excess must be SHED immediately (503 gateway_saturated) while the
/// admitted requests complete 200. The internal `PriorityCounters` confirm
/// the shed/admit accounting, and a follow-up request after the slow ones
/// drain proves slots are released (no permanent lock-up under overload).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_shedding_kicks_in_under_overload_e2e() {
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = gateway_yaml(backend, "", "max_concurrent_requests: 2\n");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Overload: 5 concurrent requests against a cap of 2. Exactly 2 must
    // be admitted (200); 3 must be shed immediately (503).
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let resp = c.get(uri(gw, "/api/slow")).await.unwrap();
            let elapsed = started.elapsed();
            let (status, body) = body_full(resp).await;
            (elapsed, status, body)
        }));
    }

    let mut oks = 0;
    let mut sheds = 0;
    let mut shed_elapsed = Vec::new();
    for t in tasks {
        let (elapsed, status, body) = t.await.unwrap();
        match status {
            StatusCode::OK => oks += 1,
            StatusCode::SERVICE_UNAVAILABLE => {
                sheds += 1;
                assert_eq!(envelope_code(&body), "gateway_saturated");
                shed_elapsed.push(elapsed);
            }
            s => panic!("unexpected status {s} under overload"),
        }
    }
    assert_eq!(oks, 2, "exactly the cap-many requests admitted");
    assert_eq!(sheds, 3, "the excess over the cap is shed");
    for e in &shed_elapsed {
        assert!(
            *e < Duration::from_millis(300),
            "shed must be immediate, took {e:?}"
        );
    }

    // Internal accounting: the default-priority class recorded the
    // admits and sheds.
    assert_eq!(dp.priority_counters().admitted_at(DEFAULT_PRIORITY), 2);
    assert_eq!(dp.priority_counters().shed_at(DEFAULT_PRIORITY), 3);

    // Slots released on completion: a follow-up request flows again (no
    // permanent lock-up from the overload).
    let client = h1_client();
    let (status, _) = body_full(client.get(uri(gw, "/api/after")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}

// ============================================================================
// 5. Zero-dropped across config reload: ongoing traffic through an
//    in-process hot reload, no request fails
// ============================================================================

/// Start the gateway, establish steady concurrent traffic, trigger an
/// in-process config hot reload (compile_and_publish + refresh, the same
/// path SIGHUP / file-watch drives) mid-stream, and verify ZERO requests
/// are dropped or failed across the generation swap. In-flight requests
/// keep their old generation; new requests see the new one. The binary
/// upgrade path (SIGUSR2) is covered by dwara-bin's zero_downtime_upgrade
/// suite; this pins the in-process reload seam.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_dropped_across_in_process_config_reload_e2e() {
    let backend = spawn_slow_backend(Duration::from_millis(50)).await;
    // Two configs that share the same route prefix (/api) and proxy to
    // the same healthy backend: the reload swaps the snapshot, but both
    // proxy to the same healthy backend, so every request must succeed
    // regardless of generation. The v2 config only adds a breaker block
    // (an additive change that does not affect routing).
    let yaml_v1 = gateway_yaml(backend, "", "");
    let state = state_from(&yaml_v1);
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Steady concurrent traffic: 4 driver tasks loop GETs against the
    // gateway until `stop` is set, counting any non-200 as a failure.
    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let mut drivers = Vec::new();
    for _ in 0..4 {
        let c = h1_client();
        let stop = Arc::clone(&stop);
        let failures = Arc::clone(&failures);
        let total = Arc::clone(&total);
        drivers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let resp = c.get(uri(gw, "/api/x")).await.unwrap();
                let (status, _body) = body_full(resp).await;
                if status != StatusCode::OK {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
                total.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Let steady traffic establish on generation 1 (bounded poll on the
    // served counter, not a fixed sleep).
    wait_for_traffic(&total, 1, Instant::now() + Duration::from_secs(5)).await;
    let served_before = total.load(Ordering::Relaxed);
    assert!(
        served_before > 0,
        "steady traffic must be flowing before the reload"
    );

    // Trigger the in-process hot reload: publish a new generation and
    // refresh the dataplane. This is the file-watch/SIGHUP seam. The new
    // generation keeps the SAME routed prefix (/api) and proxies to the
    // SAME healthy backend -- it only ADDS a breaker block (an additive
    // change that does not affect routing) -- so every request, whether
    // it lands on the old or new generation, still resolves and succeeds.
    // This isolates the zero-DROPPED property of the snapshot swap from
    // routing changes (a separate concern).
    let yaml_v2 = gateway_yaml(
        backend,
        "  breaker:\n    consecutive_failures: 5\n    open_ms: 60000\n",
        "",
    );
    let reloaded = parse_gateway(&yaml_v2).expect("reloaded config parses");
    state.compile_and_publish(&reloaded).expect("publish");
    dp.refresh();

    // Keep traffic flowing THROUGH the generation swap (the zero-dropped
    // window under test). In-flight requests keep their old generation;
    // new requests resolve against the new one. Both route /api to the
    // same healthy backend, so none can fail on the swap itself. This is
    // a real duration window (not sleep-as-synchronization): the test
    // must observe traffic crossing the generation boundary.
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.store(true, Ordering::Relaxed);
    for d in drivers {
        d.await.unwrap();
    }

    let served = total.load(Ordering::Relaxed);
    let failure_count = failures.load(Ordering::Relaxed);
    assert!(
        served > served_before,
        "traffic must continue across the reload: {served} total, {served_before} before"
    );
    assert_eq!(
        failure_count, 0,
        "dropped/failed requests across the in-process reload: {failure_count} \
         (served {served})"
    );
}

// ============================================================================
// 6. Combined fault: breaker + outlier ejection under concurrent load
//    (a real outage shape: a failing endpoint trips the breaker while the
//    healthy endpoint keeps serving)
// ============================================================================

/// A combined fault scenario closer to a real outage: two endpoints, one
/// fails. Passive health ejects the bad endpoint (failover to the good
/// one) AND the breaker -- gating the WHOLE upstream -- must NOT open
/// while the good endpoint keeps the upstream healthy (the breaker is a
/// per-upstream layer above per-endpoint ejection; a single healthy
/// endpoint keeps it closed). This pins the layer independence under live
/// fault injection, the regression the focused `breaker_open_period_ejects_no_endpoints`
/// test guards from the other direction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaker_stays_closed_while_outlier_ejection_failovers_e2e() {
    let (good_port, _good) = spawn_flipping_backend().await;
    let (bad_port, bad_healthy) = spawn_flipping_backend().await;
    // Breaker trips on 5 consecutive failures; passive health ejects
    // after 3. With one healthy endpoint, the breaker's failure streak
    // resets on every successful good-endpoint request, so it must NEVER
    // open while the good endpoint is up.
    let yaml = two_endpoint_gateway_yaml(
        good_port,
        bad_port,
        "  load_balancer: round_robin\n  breaker:\n    consecutive_failures: 5\n    open_ms: 60000\n  health:\n    consecutive_failures: 3\n    failure_ratio: 0.99\n    failure_min_volume: 1000\n    window_ms: 60000\n    eject_ms: 60000\n    half_open_probes: 1\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    wait_for_gateway(&client, gw, Instant::now() + Duration::from_secs(5)).await;

    // Inject the fault on the bad endpoint.
    bad_healthy.store(false, Ordering::Relaxed);

    // Drive traffic: every request must succeed via failover, and the
    // breaker must stay CLOSED (the good endpoint keeps the upstream
    // healthy).
    let handle = dp.registry().get("up").expect("upstream handle");
    let mut ok = 0;
    for _ in 0..12 {
        let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        if status == StatusCode::OK {
            ok += 1;
        }
        // The breaker must not have opened at any point during the
        // failover storm.
        assert!(
            matches!(handle.breaker().state(), BreakerState::Closed { .. }),
            "breaker must stay closed while a healthy endpoint serves"
        );
    }
    assert!(ok >= 8, "failover must keep traffic succeeding: {ok}/12 OK");

    // The bad endpoint was ejected (outlier detection fired).
    let mut bad_ejections = 0u64;
    for (_addr, port, health) in handle.lb().health_targets() {
        if port == bad_port {
            if let Some(h) = health {
                bad_ejections = h.ejections();
            }
        }
    }
    assert!(
        bad_ejections >= 1,
        "the failing endpoint must be ejected while the breaker stays closed"
    );
}

// ============================================================================
// 7. Edge case: ALL endpoints down -- the breaker opens and fail-fasts so
//    the gateway does not storm dead backends with retries
// ============================================================================

/// Every endpoint is down (no healthy peer to fail over to). Drive enough
/// requests to trip the per-upstream breaker; once OPEN, subsequent
/// requests fail fast (503 + upstream_circuit_open + Retry-After) with
/// ZERO backend contact -- the breaker is the storm-prevention layer when
/// there is nothing to fail over to. The combined retry-budget + breaker
/// blast radius is bounded: backend hits do not grow at all while the
/// breaker is open. This is the edge case the ejection failover tests
/// (which keep one healthy endpoint) deliberately do not cover.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_endpoints_down_breaker_fail_fasts_no_backend_storm_e2e() {
    // Two always-failing endpoints (warmup 0 -> 503 from the first hit),
    // each counting its hits so the storm bound is observable.
    let (port1, hits1) = spawn_warmup_then_fail_backend(0).await;
    let (port2, hits2) = spawn_warmup_then_fail_backend(0).await;
    // Retries ON (attempts 2, budget 100) so pre-open requests DO retry
    // across both dead endpoints; the breaker trips after 3 consecutive
    // failed send outcomes. open_ms is large so the breaker STAYS open for
    // the duration of the test (the storm bound is what we assert, not
    // recovery -- recovery is pinned by test 1 above).
    let yaml = two_endpoint_gateway_yaml(
        port1,
        port2,
        "  load_balancer: round_robin\n\
         \x20 breaker:\n    consecutive_failures: 3\n    open_ms: 60000\n\
         \x20 retries:\n    attempts: 2\n    retry_post: false\n\
         \x20   backoff_base_ms: 1\n    backoff_cap_ms: 2\n\
         \x20   budget_percent: 100\n    buffer_max_bytes: 65536\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    // Readiness on the reserved /healthz path: it does NOT route to the
    // backend (so it does not consume a failure streak or a backend hit),
    // only confirms the listener is accepting connections.
    let ready = Instant::now() + Duration::from_secs(5);
    while Instant::now() < ready {
        if client.get(uri(gw, "/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Drive three requests to trip the breaker. Each fails (every endpoint
    // is down); the breaker records one failed outcome per send.
    for _ in 0..3 {
        let resp = client.get(uri(gw, "/api/x")).await.unwrap();
        let _ = resp.into_body().collect().await;
    }
    let handle = dp.registry().get("up").expect("upstream handle");
    assert!(
        matches!(handle.breaker().state(), BreakerState::Open { .. }),
        "breaker must open when every endpoint is down"
    );

    // Snapshot the backend hit count: this is the pre-open blast radius
    // (retries happened, but bounded by the budget + attempt cap).
    let hits_before = hits1.load(Ordering::SeqCst) + hits2.load(Ordering::SeqCst);
    assert!(
        hits_before > 0,
        "pre-open requests must have contacted the backends (got {hits_before})"
    );

    // While the breaker is OPEN, the next requests fail fast with NO
    // backend contact -- the storm against dead backends is bounded.
    for _ in 0..5 {
        let started = Instant::now();
        let (status, body, headers) =
            body_full_with_headers(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(envelope_code(&body), "upstream_circuit_open");
        assert!(
            headers.get("retry-after").is_some(),
            "open breaker must advertise Retry-After"
        );
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "fail-fast must not contact the upstream, took {:?}",
            started.elapsed()
        );
    }
    let hits_after = hits1.load(Ordering::SeqCst) + hits2.load(Ordering::SeqCst);
    assert_eq!(
        hits_after, hits_before,
        "no new backend contact while the breaker is open \
         (before {hits_before}, after {hits_after})"
    );
}

// ============================================================================
// 8. Breaker state preserved across an in-process config reload: the open
//    state (and its fail-fast) survives a snapshot swap, then recovery
//    closes it -- crossing the breaker state machine with the reload seam
// ============================================================================

/// The per-upstream breaker state is carried across reloads (DW-015: the
/// state object survives a snapshot swap; only the PARAMETERS apply from
/// the new config). Open the breaker via live faults, trigger an
/// in-process hot reload that KEEPS the breaker config identical (an
/// additive second route is the only change, so the upstream `up` is
/// unchanged and its breaker carries), and verify the breaker is STILL
/// open and fail-fasts immediately after the reload. Then recover the
/// backend and verify a half-open probe CLOSES the carried breaker. This
/// pins the breaker-state-across-reload promise the focused reload suites
/// do not assert alongside an open breaker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaker_state_preserved_across_in_process_reload_e2e() {
    let (port, healthy) = spawn_flipping_backend().await;
    let breaker_yaml = "  breaker:\n    consecutive_failures: 2\n    open_ms: 500\n";
    // v1: one /api route to the upstream with the breaker block.
    let yaml_v1 = gateway_yaml(port, breaker_yaml, "");
    let state = state_from(&yaml_v1);
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    wait_for_gateway(&client, gw, Instant::now() + Duration::from_secs(5)).await;

    // Inject the fault and trip the breaker.
    healthy.store(false, Ordering::Relaxed);
    for _ in 0..2 {
        let _ = client.get(uri(gw, "/api/x")).await.unwrap();
    }
    let handle = dp.registry().get("up").expect("upstream handle");
    assert!(
        matches!(handle.breaker().state(), BreakerState::Open { .. }),
        "breaker open before the reload"
    );

    // Trigger the in-process hot reload: publish a new generation that
    // ADDS a second route (/extra) but keeps the upstream `up` and its
    // breaker config byte-identical, so the breaker STATE object carries
    // (only the route table changes). This is the file-watch/SIGHUP seam.
    let yaml_v2 = gateway_yaml_with_extra_route(port, None, breaker_yaml, "");
    let reloaded = parse_gateway(&yaml_v2).expect("reloaded config parses");
    state.compile_and_publish(&reloaded).expect("publish");
    dp.refresh();

    // The carried breaker is STILL open: a request fails fast with no
    // backend contact, and the state machine confirms Open.
    let reloaded_handle = dp
        .registry()
        .get("up")
        .expect("upstream handle after reload");
    assert!(
        matches!(reloaded_handle.breaker().state(), BreakerState::Open { .. }),
        "breaker state must carry across the reload (still Open)"
    );
    let started = Instant::now();
    let (status, body, headers) =
        body_full_with_headers(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "upstream_circuit_open");
    assert!(
        headers.get("retry-after").is_some(),
        "carried-open breaker must still advertise Retry-After"
    );
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "fail-fast must not contact the upstream after reload, took {:?}",
        started.elapsed()
    );

    // Recover the fault and wait for the breaker cooldown to elapse
    // (bounded poll): the next request is a half-open probe on the
    // CARRIED breaker; it sees the now-healthy backend and CLOSES the
    // breaker.
    healthy.store(true, Ordering::Relaxed);
    wait_for_breaker_cooldown(&handle, Instant::now() + Duration::from_secs(5)).await;
    let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "half-open probe closes the carried breaker"
    );
    assert!(
        matches!(
            reloaded_handle.breaker().state(),
            BreakerState::Closed { .. }
        ),
        "carried breaker must Close after a successful probe"
    );
}

// ============================================================================
// 9. Zero-dropped across reload WITH live failover: a failing endpoint is
//    ejected while a healthy peer keeps serving, and an in-process reload
//    lands mid-stream -- no request is dropped across either event
// ============================================================================

/// A combined reload + ejection + failover scenario: two endpoints, one
/// always failing (passive health ejects it), one always healthy. First
/// drive SERIAL traffic until the bad endpoint is EJECTED (every request
/// still succeeds via retry-to-good). Once the bad endpoint is out of
/// rotation, start CONCURRENT traffic and land an in-process hot reload
/// mid-stream: the ejection state carries with the load-balancer for the
/// unchanged endpoint addresses, so all picks keep going to the good
/// endpoint and ZERO requests drop across the generation swap. This is a
/// strictly stronger zero-dropped property than test 5 (which reloaded
/// against a fully healthy backend): here a fault is LIVE and the
/// resilience state machine must survive the snapshot swap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_dropped_across_reload_with_failover_under_live_fault_e2e() {
    let (good_port, _good) = spawn_flipping_backend().await;
    let (bad_port, bad_healthy) = spawn_flipping_backend().await;
    // Bad endpoint fails from the first hit; ejection after 3 consecutive
    // failures. eject_ms is LARGE so the bad endpoint stays ejected for the
    // whole test (no half-open probe re-introduces it during the measured
    // reload window). Retries (attempts 2, budget 100) cover the bad picks
    // during the serial warmup before ejection.
    let upstream_yaml = "  load_balancer: round_robin\n\
         \x20 health:\n    consecutive_failures: 3\n    failure_ratio: 0.99\n\
         \x20   failure_min_volume: 1000\n    window_ms: 60000\n\
         \x20   eject_ms: 60000\n    half_open_probes: 1\n\
         \x20 retries:\n    attempts: 2\n    retry_post: false\n\
         \x20   retry_statuses: [500, 502, 503, 504]\n\
         \x20   backoff_base_ms: 1\n    backoff_cap_ms: 2\n\
         \x20   budget_percent: 100\n    buffer_max_bytes: 65536\n";
    let yaml_v1 = two_endpoint_gateway_yaml(good_port, bad_port, upstream_yaml, "");
    let state = state_from(&yaml_v1);
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();
    wait_for_gateway(&client, gw, Instant::now() + Duration::from_secs(5)).await;

    // Inject the fault: the bad endpoint fails from the first hit. The
    // good endpoint stays healthy. (Readiness above hit a healthy backend
    // via round-robin, before the fault was injected.)
    bad_healthy.store(false, Ordering::Relaxed);

    // Serial warmup: drive requests until the bad endpoint is ejected.
    // Serial round-robin alternates predictably (bad pick -> retry to
    // good -> 200), so every warmup request succeeds while accumulating
    // the 3 consecutive failures on the bad endpoint that trigger ejection.
    let handle = dp.registry().get("up").expect("upstream handle");
    let eject_deadline = Instant::now() + Duration::from_secs(5);
    let mut ejected = false;
    while Instant::now() < eject_deadline {
        let (status, _) = body_full(client.get(uri(gw, "/api/x")).await.unwrap()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "serial warmup must succeed via retry-to-good before ejection"
        );
        let mut bad_ejections = 0u64;
        for (_addr, port, health) in handle.lb().health_targets() {
            if port == bad_port {
                if let Some(h) = health {
                    bad_ejections = h.ejections();
                }
            }
        }
        if bad_ejections >= 1 {
            ejected = true;
            break;
        }
    }
    assert!(
        ejected,
        "the bad endpoint must be ejected before the reload window"
    );

    // Measured window: concurrent traffic now flows entirely to the good
    // endpoint (the bad one is ejected). 4 driver tasks loop GETs until
    // `stop` is set, counting any non-200 as a failure.
    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let mut drivers = Vec::new();
    for _ in 0..4 {
        let c = h1_client();
        let stop = Arc::clone(&stop);
        let failures = Arc::clone(&failures);
        let total = Arc::clone(&total);
        drivers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let resp = c.get(uri(gw, "/api/x")).await.unwrap();
                let (status, _body) = body_full(resp).await;
                if status != StatusCode::OK {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
                total.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Let steady traffic establish on generation 1 (bounded poll on the
    // served counter, not a fixed sleep).
    wait_for_traffic(&total, 1, Instant::now() + Duration::from_secs(5)).await;
    let served_before = total.load(Ordering::Relaxed);
    assert!(
        served_before > 0,
        "steady traffic must be flowing before the reload"
    );
    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "traffic must be green before the reload (bad endpoint ejected)"
    );

    // Trigger the in-process hot reload: publish a new generation that
    // ADDS a second route (/extra) but keeps the upstream `up` and its
    // health/retry config identical, so the ejection state and retry
    // budget carry with the load-balancer for the unchanged endpoints.
    let yaml_v2 = two_endpoint_gateway_with_extra_route(good_port, bad_port, upstream_yaml, "");
    let reloaded = parse_gateway(&yaml_v2).expect("reloaded config parses");
    state.compile_and_publish(&reloaded).expect("publish");
    dp.refresh();

    // The ejection state CARRIED: the bad endpoint is still ejected after
    // the snapshot swap (no reset, no re-introduction into rotation).
    let reloaded_handle = dp
        .registry()
        .get("up")
        .expect("upstream handle after reload");
    let mut bad_ejections_after = 0u64;
    for (_addr, port, health) in reloaded_handle.lb().health_targets() {
        if port == bad_port {
            if let Some(h) = health {
                bad_ejections_after = h.ejections();
            }
        }
    }
    assert!(
        bad_ejections_after >= 1,
        "ejection state must carry across the reload (bad still ejected)"
    );

    // Keep traffic flowing THROUGH the generation swap (real duration
    // window, not sleep-as-synchronization: the test must observe
    // traffic crossing the generation boundary while the ejection state
    // is active).
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.store(true, Ordering::Relaxed);
    for d in drivers {
        d.await.unwrap();
    }

    let served = total.load(Ordering::Relaxed);
    let failure_count = failures.load(Ordering::Relaxed);
    assert!(
        served > served_before,
        "traffic must continue across the reload: {served} total, {served_before} before"
    );
    assert_eq!(
        failure_count, 0,
        "dropped/failed requests across reload + failover: {failure_count} (served {served})"
    );
}

// ============================================================================
// 10. Priority-aware load shedding under overload + injected latency: the
//     reserved high-priority bucket survives while normal traffic is shed
//     -- the priority dimension test 4 (default priority only) did not cover
// ============================================================================

/// Overload the gateway cap with TWO route priorities and a slow backend
/// (injected latency). The general allowance fills with slow normal
/// (default-priority) requests; a high-priority (9) request draws the
/// reserved sub-allowance and survives, while a further normal request is
/// shed immediately (503 gateway_saturated). The internal PriorityCounters
/// confirm the per-class admit/shed accounting. This adds the priority
/// dimension the developer's shedding test (default priority only) did not
/// exercise, crossing shedding + priority + latency injection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priority_aware_load_shedding_survives_high_priority_under_overload_e2e() {
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    // cap 3: reserved bucket = max(1, 3/10) = 1, general = 2. Two slow
    // normal requests fill the general allowance; a priority-9 request
    // draws the reserved bucket and survives; a third normal request is
    // shed.
    let yaml = priority_shedding_yaml(backend, "max_concurrent_requests: 3\n", Some(9));
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Two slow normal (/api) requests fill the general allowance. Let them
    // claim their slots before the shed probe arrives (the admission
    // decision is racy until the slow requests are admitted).
    let n1 = tokio::spawn({
        let c = h1_client();
        async move { c.get(uri(gw, "/api/slow")).await.unwrap() }
    });
    let n2 = tokio::spawn({
        let c = h1_client();
        async move { c.get(uri(gw, "/api/slow")).await.unwrap() }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A third normal request: the general allowance is saturated and the
    // default priority cannot draw the reserved bucket, so it is shed
    // immediately (503 gateway_saturated, no Retry-After).
    let shed_client = h1_client();
    let started = Instant::now();
    let shed_resp = shed_client.get(uri(gw, "/api/normal")).await.unwrap();
    assert_eq!(shed_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !shed_resp.headers().contains_key("retry-after"),
        "load shed must not advertise Retry-After"
    );
    let (shed_status, shed_body) = body_full(shed_resp).await;
    assert_eq!(shed_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&shed_body), "gateway_saturated");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "shed must be immediate, took {:?}",
        started.elapsed()
    );

    // A high-priority (/hi, priority 9) request: admitted through the
    // reserved bucket and survives the overload.
    let hi_client = h1_client();
    let (hi_status, _) = body_full(hi_client.get(uri(gw, "/hi/critical")).await.unwrap()).await;
    assert_eq!(
        hi_status,
        StatusCode::OK,
        "priority-9 must survive overload"
    );

    // The two slow normal requests complete 200.
    let (s1, _) = body_full(n1.await.unwrap()).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = body_full(n2.await.unwrap()).await;
    assert_eq!(s2, StatusCode::OK);

    // Internal accounting: the default-priority class recorded the two
    // admits and the shed; the priority-9 class recorded its admit.
    assert_eq!(dp.priority_counters().admitted_at(DEFAULT_PRIORITY), 2);
    assert_eq!(dp.priority_counters().shed_at(DEFAULT_PRIORITY), 1);
    assert_eq!(dp.priority_counters().admitted_at(9), 1);
    assert_eq!(dp.priority_counters().shed_at(9), 0);
}

// --- suite-local YAML helpers for the gap tests -----------------------------

/// Like [`gateway_yaml`] but with an ADDITIONAL `/extra` route to the same
/// service. Used by the reload tests to force a snapshot change (new route
/// table) while keeping the upstream `up` byte-identical, so per-upstream
/// breaker / load-balancer / retry-budget state CARRIES across the reload.
fn gateway_yaml_with_extra_route(
    backend_port: u16,
    backend_port2: Option<u16>,
    upstream_extra: &str,
    gateway_extra: &str,
) -> String {
    let second = match backend_port2 {
        Some(p) => format!(
            "\x20   - address: 127.0.0.1\n\
             \x20     port: {p}\n"
        ),
        None => String::new(),
    };
    format!(
        "{gateway_extra}routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         - name: extra\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /extra\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n{second}{upstream_extra}"
    )
}

/// Two-endpoint variant of [`gateway_yaml_with_extra_route`] (the reload
/// failover test keeps both endpoints across the generation swap).
fn two_endpoint_gateway_with_extra_route(
    backend_port: u16,
    backend_port2: u16,
    upstream_extra: &str,
    gateway_extra: &str,
) -> String {
    gateway_yaml_with_extra_route(
        backend_port,
        Some(backend_port2),
        upstream_extra,
        gateway_extra,
    )
}

/// A config with one normal route (`/api`, default priority) and one
/// configurable high-priority route (`/hi`), both proxying to the SAME
/// single-endpoint upstream. `gateway_extra` prepends gateway-level keys
/// (e.g. `max_concurrent_requests`); `hi_priority` sets `/hi`'s priority
/// (None leaves the field absent).
fn priority_shedding_yaml(
    backend_port: u16,
    gateway_extra: &str,
    hi_priority: Option<u8>,
) -> String {
    let hi = match hi_priority {
        Some(p) => format!("  priority: {p}\n"),
        None => String::new(),
    };
    format!(
        "{gateway_extra}routes:\n\
         - name: normal\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         - name: critical\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /hi\n\
         \x20 action:\n\
         \x20   type: proxy\n{hi}\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n"
    )
}
