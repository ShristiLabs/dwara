//! Bounded admission queue integration tests (DW-053).
//!
//! Serves real in-process backends against the gateway dataplane and
//! pins the done-when surface: "Load test shows graceful degradation
//! curve, no cliff."
//!
//! - when the cap is full and the queue is enabled, requests WAIT for a
//!   permit up to the queue timeout instead of being immediately shed;
//! - some requests are admitted immediately, some queued then admitted,
//!   some shed (timeout or queue full) — no cliff;
//! - queue-full sheds happen immediately (no waiting);
//! - timeout sheds carry a Retry-After header;
//! - per-priority splitting reserves queue capacity for high-priority
//!   so they are not starved by a low-priority queue fill;
//! - disabled = current behavior (immediate shed, same as DW-016);
//! - dry-run interaction: queue timeout still counts as dry-run.

use std::convert::Infallible;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;

mod support;

use support::{body_of, dataplane_from, envelope_code, h1_client, spawn_gateway, uri};

// --- infrastructure (mirrors load_shedding.rs) ------------------------

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
/// gateway-level keys.
fn queue_yaml(backend_port: u16, gateway_extra: &str, hi_priority: Option<u8>) -> String {
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

/// Gateway-level YAML for an enabled admission queue.
fn aq_yaml(max_queue_size: u32, queue_timeout_ms: u64, per_priority: bool) -> String {
    format!(
        "max_concurrent_requests: {{cap}}\n\
         admission_queue:\n\
         \x20 enabled: true\n\
         \x20 max_queue_size: {max_queue_size}\n\
         \x20 queue_timeout_ms: {queue_timeout_ms}\n\
         \x20 per_priority: {per_priority}\n"
    )
}

// --- 1. graceful degradation: no cliff -----------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_degradation_no_cliff() {
    // cap=2, queue_size=10, timeout=150ms. Send 20 concurrent requests
    // to a slow upstream (50ms response). With immediate shedding
    // (DW-016), the shed count would be 20 - 2 = 18 (a cliff). With
    // the queue, some queued requests get permits as the initial two
    // complete (50ms < 150ms timeout), so the shed count is LESS than
    // 18 — a graceful curve.
    let backend = spawn_slow_backend(Duration::from_millis(50)).await;
    let yaml = queue_yaml(
        backend,
        &aq_yaml(10, 150, false).replace("{cap}", "2"),
        None,
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let mut tasks = Vec::new();
    for _ in 0..20 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/x")).await.unwrap()
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
    // No cliff: the shed count is less than (total - cap) because some
    // queued requests got permits. At least some were admitted, and at
    // least some were shed (the queue cannot absorb all 18 over-cap).
    assert!(oks >= 2, "at least the cap must be admitted: {oks}");
    assert!(sheds >= 1, "some must be shed: {sheds}");
    assert!(
        sheds < 18,
        "no cliff: shed count {sheds} must be less than total - cap = 18 \
         (some queued requests got permits)"
    );
}

// --- 2. queue timeout: 503 with Retry-After ------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_timeout_sheds_with_retry_after() {
    // cap=1, queue_size=5, timeout=50ms. Send 10 concurrent requests to
    // a slow upstream (200ms). The cap holds 1; the queue holds 5; the
    // remaining 4 are shed immediately (queue_full). Of the 5 queued,
    // some get the permit when the first completes, some time out (the
    // 50ms timeout is shorter than the 200ms response). At least some
    // get 503 with a Retry-After header.
    let backend = spawn_slow_backend(Duration::from_millis(200)).await;
    let yaml = queue_yaml(backend, &aq_yaml(5, 50, false).replace("{cap}", "1"), None);
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/x")).await.unwrap()
        }));
    }
    let mut has_retry_after = false;
    let mut sheds = 0;
    for t in tasks {
        let resp = t.await.unwrap();
        if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
            sheds += 1;
            if resp.headers().contains_key("retry-after") {
                has_retry_after = true;
            }
        }
        let _ = body_of(resp).await;
    }
    assert!(sheds >= 1, "some requests must be shed");
    assert!(
        has_retry_after,
        "at least one shed response must carry Retry-After"
    );
}

// --- 3. queue full: immediate shed ---------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_full_sheds_immediately() {
    // cap=1, queue_size=2, timeout=10000ms (long). Send 10 concurrent
    // requests. cap + queue = 3; the remaining 7 are shed immediately
    // (queue_full) — they do NOT wait 10s. Verify the sheds happen fast
    // (well under the timeout) and the total is at least 7.
    let backend = spawn_slow_backend(Duration::from_millis(300)).await;
    let yaml = queue_yaml(
        backend,
        &aq_yaml(2, 10000, false).replace("{cap}", "1"),
        None,
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/x")).await.unwrap()
        }));
    }
    let mut sheds = 0;
    for t in tasks {
        let (status, _) = body_of(t.await.unwrap()).await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            sheds += 1;
        }
    }
    let elapsed = started.elapsed();
    // At least 7 shed (10 - cap - queue = 7). The queue-full sheds are
    // immediate, and the 3 admitted/queued complete in ~300ms, so the
    // total wall time is well under the 10s timeout.
    assert!(
        sheds >= 7,
        "at least 7 must be shed (queue full), got {sheds}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "queue-full sheds must be immediate, not wait the timeout; \
         elapsed {elapsed:?}"
    );
}

// --- 4. priority preservation -------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_priority_preserves_high_priority_admission() {
    // cap=1, queue_size=10, per_priority=true. Send 5 low-priority then
    // 5 high-priority concurrent requests. With per_priority splitting,
    // half the queue (5) is reserved for high-priority. Low-priority can
    // only queue up to 5 (half of 10); high-priority can queue up to the
    // full 10. So high-priority requests are more likely to be admitted
    // (not starved by the low-priority queue fill).
    let backend = spawn_slow_backend(Duration::from_millis(200)).await;
    let yaml = queue_yaml(
        backend,
        &aq_yaml(10, 100, true).replace("{cap}", "1"),
        Some(9),
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    // Send 5 low-priority first.
    let mut low_tasks = Vec::new();
    for _ in 0..5 {
        let c = h1_client();
        low_tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/x")).await.unwrap()
        }));
    }
    // Brief pause so the low-priority requests arrive first and start
    // filling the queue.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Send 5 high-priority.
    let mut hi_tasks = Vec::new();
    for _ in 0..5 {
        let c = h1_client();
        hi_tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/hi/x")).await.unwrap()
        }));
    }

    let mut hi_oks = 0;
    for t in hi_tasks {
        let (status, _) = body_of(t.await.unwrap()).await;
        match status {
            StatusCode::OK => hi_oks += 1,
            StatusCode::SERVICE_UNAVAILABLE => {}
            s => panic!("unexpected hi status {s}"),
        }
    }
    let mut low_oks = 0;
    for t in low_tasks {
        let (status, _) = body_of(t.await.unwrap()).await;
        match status {
            StatusCode::OK => low_oks += 1,
            StatusCode::SERVICE_UNAVAILABLE => {}
            s => panic!("unexpected low status {s}"),
        }
    }
    // High-priority should be admitted at least as often as low-priority
    // (the reserve prevents starvation). At least one high-priority must
    // be admitted.
    assert!(
        hi_oks >= 1,
        "high-priority must not be starved: hi_oks={hi_oks}"
    );
    assert!(
        hi_oks >= low_oks,
        "high-priority should be admitted at least as often as \
         low-priority: hi_oks={hi_oks}, low_oks={low_oks}"
    );
}

// --- 5. disabled = current behavior (immediate shed) --------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_queue_sheds_immediately_like_dw016() {
    // admission_queue not set: immediate shed, same as DW-016. The shed
    // is instant (no queue wait) and carries no Retry-After.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = queue_yaml(backend, "max_concurrent_requests: 1\n", None);
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let c = h1_client();
    let busy = tokio::spawn(async move { c.get(uri(gw, "/api/slow")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let c = h1_client();
    let started = Instant::now();
    let resp = c.get(uri(gw, "/api/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !resp.headers().contains_key("retry-after"),
        "immediate shed (DW-016) carries no Retry-After"
    );
    let (status, body) = body_of(resp).await;
    assert_eq!(envelope_code(&body), "gateway_saturated");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "shed must be immediate, took {:?}",
        started.elapsed()
    );
    let _ = body_of(busy.await.unwrap()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_false_sheds_immediately_like_dw016() {
    // admission_queue.enabled=false: same as not setting the block.
    let backend = spawn_slow_backend(Duration::from_millis(400)).await;
    let yaml = queue_yaml(
        backend,
        "max_concurrent_requests: 1\n\
         admission_queue:\n  enabled: false\n  max_queue_size: 10\n  \
         queue_timeout_ms: 100\n",
        None,
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let c = h1_client();
    let busy = tokio::spawn(async move { c.get(uri(gw, "/api/slow")).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let c = h1_client();
    let started = Instant::now();
    let resp = c.get(uri(gw, "/api/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !resp.headers().contains_key("retry-after"),
        "disabled queue carries no Retry-After"
    );
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "shed must be immediate, took {:?}",
        started.elapsed()
    );
    let _ = body_of(busy.await.unwrap()).await;
}

// --- 6. dry-run interaction ----------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dry_run_with_queue_admits_over_cap() {
    // load_shed_dry_run=true + admission_queue.enabled=true. The queue
    // timeout still counts as dry-run: when a request would be shed
    // (timeout or queue full), it is admitted over the cap instead.
    // So NO request gets a 503 — all are admitted (over the cap when
    // the queue would have shed them).
    let backend = spawn_slow_backend(Duration::from_millis(200)).await;
    let yaml = queue_yaml(
        backend,
        "max_concurrent_requests: 1\n\
         load_shed_dry_run: true\n\
         admission_queue:\n  enabled: true\n  max_queue_size: 2\n  \
         queue_timeout_ms: 50\n",
        None,
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let c = h1_client();
        tasks.push(tokio::spawn(async move {
            c.get(uri(gw, "/api/x")).await.unwrap()
        }));
    }
    let mut oks = 0;
    let mut sheds = 0;
    for t in tasks {
        let (status, _) = body_of(t.await.unwrap()).await;
        match status {
            StatusCode::OK => oks += 1,
            StatusCode::SERVICE_UNAVAILABLE => sheds += 1,
            s => panic!("unexpected status {s}"),
        }
    }
    // Dry-run: NO sheds. All 10 are admitted (some over the cap).
    assert_eq!(sheds, 0, "dry-run must not shed any request");
    assert_eq!(oks, 10, "dry-run must admit all 10 requests");
}
