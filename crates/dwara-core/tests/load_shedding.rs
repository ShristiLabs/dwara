//! Priority-aware load shedding integration tests (DW-016, feature
//! analysis 4.11).
//!
//! Serves real in-process backends against the gateway dataplane and pins
//! the done-when surface:
//!
//! - priority is a validated 0..=10 config field on routes (and stored on
//!   consumers for the later authN wiring);
//! - under a saturated gateway cap, high-priority (>= 8) traffic survives
//!   via the reserved sub-allowance while normal traffic is shed with 503;
//! - the reserved bucket itself is bounded: exhausting it sheds even
//!   high-priority traffic;
//! - every admission/shed is counted per priority class;
//! - priority-free configs behave exactly like DW-015 (full cap, identical
//!   "gateway saturated" response);
//! - 404s resolve before admission and never consume cap slots.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::{DataPlane, DEFAULT_PRIORITY};
use dwara_core::snapshot::validate;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

mod support;

use support::{body_of, dataplane_from, envelope_code, h1_client, spawn_gateway, state_from, uri};

// --- infrastructure (mirrors breaker_caps.rs) ------------------------

/// Backend answering 200 after `delay` per request.
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

/// A config with one normal route (`/api`, default priority) and one
/// configurable high-priority route (`/hi`). `gateway_extra` prepends
/// gateway-level keys (e.g. `max_concurrent_requests`); `hi_priority`
/// sets `/hi`'s priority (None leaves the field absent).
fn shedding_yaml(backend_port: u16, gateway_extra: &str, hi_priority: Option<u8>) -> String {
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

// --- 1. config validation ---------------------------------------------------

#[test]
fn route_priority_range_is_validated() {
    for bad in [11u8, 255] {
        let yaml = shedding_yaml(1, "", Some(bad));
        let gateway = parse_gateway(&yaml).expect("parses");
        let issues = validate(&gateway);
        assert!(
            issues
                .iter()
                .any(|i| i.entity == "route" && i.name == "critical" && i.field == "priority"),
            "priority {bad} must be rejected: {issues:?}"
        );
    }
    // 0 and 10 are the inclusive bounds: valid.
    for good in [0u8, 10] {
        let yaml = shedding_yaml(1, "", Some(good));
        let gateway = parse_gateway(&yaml).expect("parses");
        assert!(
            validate(&gateway).is_empty(),
            "priority {good} must be accepted"
        );
    }
}

#[test]
fn consumer_priority_range_is_validated_and_stored() {
    let base = shedding_yaml(1, "", None);
    let yaml = format!(
        "{base}consumers:\n- name: gold\n  priority: 11\n  credentials:\n  - type: api_key\n    key: k\n"
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.entity == "consumer" && i.name == "gold" && i.field == "priority"),
        "consumer priority 11 must be rejected: {issues:?}"
    );
    // A valid value is stored (used once authN identifies the consumer).
    let yaml = format!(
        "{base}consumers:\n- name: gold\n  priority: 10\n  credentials:\n  - type: api_key\n    key: k\n"
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    assert!(validate(&gateway).is_empty());
    assert_eq!(gateway.consumers[0].priority, Some(10));
}

// --- 2. high priority survives normal saturation ---------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn high_priority_survives_while_normal_traffic_sheds() {
    // cap 3 with a priority-9 route: reserved bucket = max(1, 3/10) = 1,
    // general = 2. Two slow normal requests fill the general allowance;
    // a priority-9 request draws the reserved bucket and survives, a
    // priority-5 (default) request is shed.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = shedding_yaml(backend, "max_concurrent_requests: 3\n", Some(9));
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let c1 = h1_client();
    let c2 = h1_client();
    let n1 = tokio::spawn(async move { c1.get(uri(gw, "/api/slow")).await.unwrap() });
    let n2 = tokio::spawn(async move { c2.get(uri(gw, "/api/slow")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Normal (default priority 5): shed with the DW-015 response, no
    // Retry-After, no extra headers.
    let c3 = h1_client();
    let started = Instant::now();
    let resp = c3.get(uri(gw, "/api/slow")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!resp.headers().contains_key("retry-after"));
    let (status, body) = body_of(resp).await;
    assert_eq!(envelope_code(&body), "gateway_saturated");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "shed must be immediate, took {:?}",
        started.elapsed()
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // High priority (9): admitted through the reserved bucket.
    let c4 = h1_client();
    let (status, _) = body_of(c4.get(uri(gw, "/hi/critical")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "priority-9 must survive overload");

    // Counters: the class-5 request was shed, the class-9 admitted.
    assert_eq!(dp.priority_counters().shed_at(5), 1);
    assert_eq!(dp.priority_counters().admitted_at(9), 1);
    assert_eq!(dp.priority_counters().admitted_at(DEFAULT_PRIORITY), 2);
    assert_eq!(dp.priority_counters().shed_at(9), 0);

    // Drain the slow normal requests.
    let (s1, _) = body_of(n1.await.unwrap()).await;
    let (s2, _) = body_of(n2.await.unwrap()).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
}

// --- 3. reserved bucket exhaustion ------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_bucket_exhaustion_sheds_even_high_priority() {
    // cap 2 with a priority-9 route: bucket 1, general 1. Three
    // concurrent high-priority requests: one takes the general allowance,
    // one the reserved bucket, the third is shed — the bucket is a
    // bounded sub-allowance, not an unlimited bypass.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = shedding_yaml(backend, "max_concurrent_requests: 2\n", Some(9));
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let mut tasks = Vec::new();
    for _ in 0..3 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/hi/critical")).await.unwrap()
        }));
    }
    let mut oks = 0;
    let mut sheds = 0;
    for t in tasks {
        let (status, body) = body_of(t.await.unwrap()).await;
        match status {
            StatusCode::OK => oks += 1,
            StatusCode::SERVICE_UNAVAILABLE => {
                sheds += 1;
                assert_eq!(envelope_code(&body), "gateway_saturated");
            }
            s => panic!("unexpected status {s}"),
        }
    }
    assert_eq!(oks, 2, "cap 2 admits exactly two high-priority requests");
    assert_eq!(sheds, 1, "the third is shed once the bucket is full");
}

// --- 4. priority-free config behaves exactly as DW-015 ----------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_config_sheds_identically_to_dw015() {
    // No priority configured anywhere: no bucket is carved, so the FULL
    // cap serves all traffic equally and the shed response is identical
    // (same status, same body) to the pre-DW-016 behavior.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = shedding_yaml(backend, "max_concurrent_requests: 2\n", None);
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let mut tasks = Vec::new();
    for _ in 0..3 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/slow")).await.unwrap()
        }));
    }
    let mut oks = 0;
    let mut sheds = 0;
    for t in tasks {
        let (status, body) = body_of(t.await.unwrap()).await;
        if status == StatusCode::OK {
            oks += 1;
        } else {
            sheds += 1;
            assert_eq!(envelope_code(&body), "gateway_saturated");
        }
    }
    assert_eq!(oks, 2);
    assert_eq!(sheds, 1);
    // Everything is counted at the default class.
    assert_eq!(dp.priority_counters().admitted_at(DEFAULT_PRIORITY), 2);
    assert_eq!(dp.priority_counters().shed_at(DEFAULT_PRIORITY), 1);
}

// --- 5. 404s resolve before admission ---------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrouted_requests_never_consume_cap_slots() {
    // Route resolution moved BEFORE cap admission (DW-016): an unknown
    // path answers 404 even when the cap is fully saturated — it never
    // occupies, or queues behind, a concurrency slot.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = shedding_yaml(backend, "max_concurrent_requests: 1\n", None);
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let c0 = h1_client();
    let busy = tokio::spawn(async move { c0.get(uri(gw, "/api/slow")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let c1 = h1_client();
    let (status, body) = body_of(c1.get(uri(gw, "/nope")).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(envelope_code(&body), "no_route");

    let _ = body_of(busy.await.unwrap()).await;
}

// --- 6. bucket edge: the carve comes OUT of the cap --------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cap_one_with_high_priority_gives_normal_traffic_zero_slots() {
    // cap 1 with a high-priority route: bucket = max(1, 1/10) = 1, but the
    // bucket is carved FROM the cap, so general = 1 - 1 = 0. Consequence
    // (surprising but the documented design): NORMAL traffic is shed with
    // 503 even at ZERO load, while high-priority traffic is admitted via
    // the reserved bucket. Pinning so an operator-visible change here is
    // caught.
    let backend = spawn_slow_backend(Duration::from_millis(50)).await;
    let yaml = shedding_yaml(backend, "max_concurrent_requests: 1\n", Some(9));
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Zero in-flight requests, yet a default-priority request is shed.
    let c = h1_client();
    let (status, body) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "gateway_saturated");
    assert_eq!(dp.priority_counters().shed_at(DEFAULT_PRIORITY), 1);

    // High priority takes the whole (only) slot.
    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/hi/critical")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dp.priority_counters().admitted_at(9), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumer_only_high_priority_carves_nothing() {
    // The carve keys on ROUTE priorities only: a consumer with priority
    // >= 8 but NO high-priority route must NOT carve a reserved bucket
    // (consumer priorities are inert until authN — DW-019 — and carving
    // for them would shrink the general allowance while nothing could
    // ever draw the reserved permits). Pin: cap 1, consumer priority 9,
    // no route above default -> no carve -> the FULL cap serves normal
    // traffic, which is admitted normally at zero load (no 503s).
    // Control: `cap_one_with_high_priority_gives_normal_traffic_zero_slots`
    // pins the route-priority-9 counterpart (carve -> normals shed at
    // zero load).
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = format!(
        "{}consumers:\n\
         - name: gold\n\
         \x20 priority: 9\n\
         \x20 credentials:\n\
         \x20 - type: api_key\n\
         \x20   key: k\n",
        shedding_yaml(backend, "max_concurrent_requests: 1\n", None)
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Zero in-flight requests: normal (default-priority) traffic is
    // admitted through the uncarved, full cap — the consumer's high
    // priority never leaks into the carve decision.
    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dp.priority_counters().admitted_at(DEFAULT_PRIORITY), 1);
    assert_eq!(dp.priority_counters().shed_at(DEFAULT_PRIORITY), 0);
    // No class-9 activity: no consumer is identified without authN.
    assert_eq!(dp.priority_counters().admitted_at(9), 0);
    assert_eq!(dp.priority_counters().shed_at(9), 0);

    // A second, concurrent normal request against the now-full cap 1 is
    // shed with the standard DW-015 response — the ordinary full-cap
    // behavior, not a carve-induced one.
    let c = h1_client();
    let busy = tokio::spawn(async move { c.get(uri(gw, "/api/slow")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let c = h1_client();
    let (status, body) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(envelope_code(&body), "gateway_saturated");
    assert_eq!(dp.priority_counters().shed_at(DEFAULT_PRIORITY), 1);
    let (status, _) = body_of(busy.await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cap_ten_carves_nine_general_plus_one_reserved() {
    // cap 10 with a high-priority route: bucket = max(1, 10/10) = 1,
    // general = 9. Nine slow normal requests fill the general allowance;
    // the tenth normal request is shed; one high-priority request draws
    // the reserved bucket and survives; a second high-priority request is
    // shed (bucket exhausted).
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = shedding_yaml(backend, "max_concurrent_requests: 10\n", Some(9));
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let mut tasks = Vec::new();
    for _ in 0..9 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/slow")).await.unwrap()
        }));
    }
    tokio::time::sleep(Duration::from_millis(250)).await;

    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/api/slow")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "10th normal sheds");

    let c = h1_client();
    let hi1 = tokio::spawn(async move { c.get(uri(gw, "/hi/critical")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/hi/critical")).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "bucket holds exactly one permit at cap 10"
    );

    let (status, _) = body_of(hi1.await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    for t in tasks {
        let (status, _) = body_of(t.await.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }
}

// --- 7. reload: bucket carved in the NEW generation --------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_carves_bucket_in_new_generation_while_old_permits_hold() {
    // Start with cap 3 and NO high-priority route: one semaphore of 3.
    // One slow request acquires a permit from the OLD semaphore (the
    // permit is Arc-carried). Publish a config that adds a priority-9
    // route and refresh: the NEW generation's cap is split general 2 /
    // reserved 1. Pin the Arc-carried semantics: the in-flight request on
    // the old semaphore completes OK, and subsequent admissions see the
    // new split (2 general slots — not 3 minus the one old in-flight —
    // plus the bucket).
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let state = state_from(&shedding_yaml(
        backend,
        "max_concurrent_requests: 3\n",
        None,
    ));
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let c0 = h1_client();
    let inflight = tokio::spawn(async move { c0.get(uri(gw, "/api/slow")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Enable the high-priority route mid-run and swap generations.
    let reloaded = parse_gateway(&shedding_yaml(
        backend,
        "max_concurrent_requests: 3\n",
        Some(9),
    ))
    .expect("reloaded config parses");
    state.compile_and_publish(&reloaded).expect("publish");
    dp.refresh();

    // New split: 2 general + 1 reserved. Fill the 2 general slots.
    let mut fillers = Vec::new();
    for _ in 0..2 {
        let c = h1_client();
        fillers.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/slow")).await.unwrap()
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Normal traffic: the new general allowance (2) is full -> shed,
    // even though only 3 of the nominal 3+old permits are held across
    // generations.
    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/api/slow")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // High priority: admitted through the NEW reserved bucket.
    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/hi/critical")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);

    // The old-generation permit holder completes normally.
    let (status, _) = body_of(inflight.await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    for t in fillers {
        let (status, _) = body_of(t.await.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }
}

// --- 8. counter integrity: exact accounting ---------------------------------

/// Like `shedding_yaml` but with three routes: `/api` (default priority),
/// `/hi` (`hi_priority`, high), and `/low` (`low_priority`).
fn three_route_yaml(
    backend_port: u16,
    gateway_extra: &str,
    hi_priority: u8,
    low_priority: u8,
) -> String {
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
         \x20   type: proxy\n\
         \x20 priority: {hi_priority}\n\
         - name: bulk\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /low\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 priority: {low_priority}\n\
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scripted_sequence_has_exact_per_class_counter_accounting() {
    // cap 2 with routes at priority 9 and 0: general 1, bucket 1.
    // Scripted sequence, one request at a time:
    //   r1 /hi   -> admitted (general)          admitted[9]  = 1
    //   r2 /low  -> shed (general full, 0 < 8)  shed[0]      = 1
    //   r3 /hi   -> admitted (bucket)           admitted[9]  = 2
    //   r4 /hi   -> shed (bucket full)          shed[9]      = 1
    //   r5 /api  -> shed (general full)         shed[5]      = 1
    // Every request is accounted exactly once; nothing double-counted,
    // nothing lost.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = three_route_yaml(backend, "max_concurrent_requests: 2\n", 9, 0);
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let c = h1_client();
    let slow_hi = tokio::spawn(async move { c.get(uri(gw, "/hi/x")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/low/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // r3 goes to the bucket; probe r4/r5 while r1 and r3 still hold
    // their permits.
    let c = h1_client();
    let slow_bucket = tokio::spawn(async move { c.get(uri(gw, "/hi/x")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/hi/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/api/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, _) = body_of(slow_hi.await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = body_of(slow_bucket.await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);

    let pc = dp.priority_counters();
    assert_eq!(pc.admitted_at(9), 2);
    assert_eq!(pc.admitted_at(0), 0);
    assert_eq!(pc.admitted_at(DEFAULT_PRIORITY), 0);
    assert_eq!(pc.shed_at(9), 1);
    assert_eq!(pc.shed_at(0), 1);
    assert_eq!(pc.shed_at(DEFAULT_PRIORITY), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mixed_load_conserves_total_request_count() {
    // 10 concurrent requests across three classes against cap 3
    // (general 2, bucket 1): whatever the interleaving, every request is
    // admitted or shed exactly once, so
    // sum(admitted) + sum(shed) == 10.
    let backend = spawn_slow_backend(Duration::from_millis(300)).await;
    let yaml = three_route_yaml(backend, "max_concurrent_requests: 3\n", 9, 0);
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let paths = ["/hi/x", "/low/x", "/api/x"];
    let mut tasks = Vec::new();
    for i in 0..10 {
        let c = h1_client();
        let path = paths[i % paths.len()].to_string();
        tasks.push(tokio::spawn(
            async move { c.get(uri(gw, &path)).await.unwrap() },
        ));
    }
    for t in tasks {
        let (status, _) = body_of(t.await.unwrap()).await;
        assert!(status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE);
    }

    let pc = dp.priority_counters();
    let admitted: u64 = (0..=10u8).map(|p| pc.admitted_at(p)).sum();
    let shed: u64 = (0..=10u8).map(|p| pc.shed_at(p)).sum();
    assert_eq!(admitted + shed, 10, "no request may be unaccounted");
    assert!(
        admitted >= 1 && shed >= 1,
        "the mix must produce both outcomes"
    );
}

// --- 9. priority 0 sheds while priority 9 survives the same saturation -------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn priority_zero_sheds_first_while_high_priority_survives() {
    // Route-only resolution: cap 2, routes at 9 and 0 -> general 1,
    // bucket 1. One high-priority request holds the general slot; the
    // priority-0 route (lowest class) is shed while a second
    // high-priority request still gets through on the reserved bucket.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = three_route_yaml(backend, "max_concurrent_requests: 2\n", 9, 0);
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let c = h1_client();
    let busy = tokio::spawn(async move { c.get(uri(gw, "/hi/x")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/low/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "priority 0 sheds");
    assert_eq!(dp.priority_counters().shed_at(0), 1);

    let c = h1_client();
    let (status, _) = body_of(c.get(uri(gw, "/hi/x")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "priority 9 survives via the bucket");
    assert_eq!(dp.priority_counters().admitted_at(9), 2);

    let (status, _) = body_of(busy.await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}

// --- 10. reserved paths and 404s under FULL saturation -----------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_and_404_served_when_cap_and_bucket_are_fully_held() {
    // cap 1 with a priority-9 route: general 0, bucket 1. One slow
    // high-priority request holds the bucket -> the ENTIRE cap is
    // consumed. /healthz and 404s must still answer, immediately, without
    // needing (or consuming) a cap slot.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = shedding_yaml(backend, "max_concurrent_requests: 1\n", Some(9));
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    let c = h1_client();
    let busy = tokio::spawn(async move { c.get(uri(gw, "/hi/critical")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(dp.priority_counters().admitted_at(9), 1, "bucket is held");

    let c = h1_client();
    let started = Instant::now();
    let (status, body) = body_of(c.get(uri(gw, "/healthz")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(envelope_code(&body), "ok");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "healthz must not queue behind the cap"
    );

    let c = h1_client();
    let (status, body) = body_of(c.get(uri(gw, "/nope")).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(envelope_code(&body), "no_route");

    // Nothing above consumed a slot or was counted as admitted/shed.
    assert_eq!(dp.priority_counters().admitted_at(DEFAULT_PRIORITY), 0);
    assert_eq!(dp.priority_counters().shed_at(DEFAULT_PRIORITY), 0);

    let (status, _) = body_of(busy.await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}

// --- 11. the priority-resolver seam ------------------------------------------

#[test]
fn resolve_priority_prefers_consumer_then_route_then_default() {
    let mut route = parse_gateway(&shedding_yaml(1, "", Some(3)))
        .expect("parses")
        .routes
        .remove(0); // the /api route: no explicit priority

    // No consumer, no route priority: default.
    assert_eq!(
        dwara_core::proxy::resolve_priority(None, &route),
        DEFAULT_PRIORITY
    );

    // Route priority applies when set.
    route.priority = Some(2);
    assert_eq!(dwara_core::proxy::resolve_priority(None, &route), 2);

    // A consumer (once authN supplies one) overrides the route.
    let consumer = dwara_core::config::Consumer {
        name: "gold".to_string(),
        credentials: Vec::new(),
        policies: Vec::new(),
        priority: Some(9),
        groups: Vec::new(),
        authorization: None,
        quotas: None,
    };
    assert_eq!(
        dwara_core::proxy::resolve_priority(Some(&consumer), &route),
        9
    );
    // A consumer WITHOUT a priority falls back to the route.
    let consumer = dwara_core::config::Consumer {
        name: "plain".to_string(),
        credentials: Vec::new(),
        policies: Vec::new(),
        priority: None,
        groups: Vec::new(),
        authorization: None,
        quotas: None,
    };
    assert_eq!(
        dwara_core::proxy::resolve_priority(Some(&consumer), &route),
        2
    );
}
