//! Streaming analytics + ML insights tests (DW-092): live in-process
//! sketches (sub-second-freshness per-route rolling window with
//! counts, errors, and latency percentiles) and the ML traffic
//! insights engine (EWMA forecasting + seasonal-baseline anomaly
//! detection).
//!
//! The live-sketch tests drive the real dataplane (the same path
//! dwara-bin serves) and assert against the in-process snapshot. The
//! insights tests exercise the engine directly (deterministic, no
//! wall-clock dependency). The validation tests drive the snapshot
//! validator directly.

mod support;

use std::sync::Arc;

use bytes::Bytes;
use dwara_core::analytics::{
    insights::{AnomalyResult, BaselineWindow, ForecastResult, InsightsEngine},
    EmbeddedAnalytics, LiveSketches, DEFAULT_RETENTION_MS,
};
use dwara_core::config::{parse_gateway, AnalyticsInsights};
use dwara_core::observability::AccessRecord;
use dwara_core::proxy::DataPlane;
use http_body_util::Full;
use support::{gateway_yaml, h1_client, spawn_backend, spawn_gateway, uri};
use tokio::sync::watch;

// --- helpers ---------------------------------------------------------------

fn ok() -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(200)
        .body(Full::new(Bytes::from("ok")))
        .unwrap()
}

fn err_500() -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(500)
        .body(Full::new(Bytes::from("err")))
        .unwrap()
}

/// Open an analytics store in a temp dir, attach live sketches (with a
/// small window for rotation tests), and attach it to the dataplane.
struct AnalyticsHandle {
    store: Arc<EmbeddedAnalytics>,
    _dir: tempfile::TempDir,
    _shutdown_tx: watch::Sender<()>,
}

fn attach_analytics_with_live(dp: &Arc<DataPlane>, window_ms: u64) -> AnalyticsHandle {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        DEFAULT_RETENTION_MS,
        100,
        0,
    )
    .unwrap();
    let sketches = LiveSketches::new(window_ms);
    store.set_live_sketches(sketches);
    dp.set_analytics(Arc::clone(&store));
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);
    AnalyticsHandle {
        store,
        _dir: dir,
        _shutdown_tx: shutdown_tx,
    }
}

/// Attach an analytics store with live sketches AND the insights engine.
struct InsightsHandle {
    store: Arc<EmbeddedAnalytics>,
    _dir: tempfile::TempDir,
    _shutdown_tx: watch::Sender<()>,
}

fn attach_analytics_with_insights(
    dp: &Arc<DataPlane>,
    window_ms: u64,
    config: &AnalyticsInsights,
) -> InsightsHandle {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        DEFAULT_RETENTION_MS,
        100,
        0,
    )
    .unwrap();
    let sketches = LiveSketches::new(window_ms);
    store.set_live_sketches(sketches);
    let engine = InsightsEngine::new(config);
    store.set_insights(engine);
    dp.set_analytics(Arc::clone(&store));
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);
    InsightsHandle {
        store,
        _dir: dir,
        _shutdown_tx: shutdown_tx,
    }
}

/// Send N GET requests through the gateway to /api and return.
async fn send_requests(port: u16, n: usize, path: &str) {
    let client = h1_client();
    for _ in 0..n {
        let _ = client.get(uri(port, path)).await;
    }
}

fn parse_ok(yaml: &str) -> dwara_core::config::Gateway {
    parse_gateway(yaml).expect("test config parses")
}

fn validation_base() -> &'static str {
    "listeners: []\nroutes:\n  - name: r\n    service: s\n    match:\n      path: { type: regex, value: /.* }\n    action: { type: respond, status: 200 }\nservices:\n  - name: s\n    upstream: u\nupstreams:\n  - name: u\n    endpoints:\n      - address: 127.0.0.1\n        port: 1\n"
}

// --- live sketch tests -----------------------------------------------------

#[tokio::test]
async fn live_sketch_records_requests() {
    let (backend_port, _hits) =
        spawn_backend(|_n, _m, _p, _b| ok(), std::time::Duration::from_millis(0)).await;
    let yaml = gateway_yaml("", backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics_with_live(&dp, 60_000);
    let port = spawn_gateway(dp).await;
    send_requests(port, 5, "/api").await;
    // The live snapshot is synchronous (no writer drain needed).
    let snap = ah.store.live_snapshot().expect("live sketches attached");
    let route = snap
        .routes
        .iter()
        .find(|r| r.route == "all")
        .expect("route 'all' in snapshot");
    assert!(route.requests >= 5, "requests >= 5, got {}", route.requests);
    assert_eq!(route.errors, 0);
}

#[tokio::test]
async fn live_sketch_records_errors() {
    // Backend returns 500 for every request.
    let (backend_port, _hits) = spawn_backend(
        |_n, _m, _p, _b| err_500(),
        std::time::Duration::from_millis(0),
    )
    .await;
    let yaml = gateway_yaml("", backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics_with_live(&dp, 60_000);
    let port = spawn_gateway(dp).await;
    send_requests(port, 3, "/api").await;
    let snap = ah.store.live_snapshot().expect("live sketches attached");
    let route = snap
        .routes
        .iter()
        .find(|r| r.route == "all")
        .expect("route 'all' in snapshot");
    assert!(route.requests >= 3, "requests >= 3, got {}", route.requests);
    assert!(route.errors >= 3, "errors >= 3, got {}", route.errors);
    assert!(
        route.error_rate > 0.99,
        "error_rate ~1.0, got {}",
        route.error_rate
    );
}

#[tokio::test]
async fn live_sketch_latency_percentiles() {
    // Backend with a fixed 20ms delay so latency samples are
    // non-trivial; natural system jitter produces a spread.
    let (backend_port, _hits) =
        spawn_backend(|_n, _m, _p, _b| ok(), std::time::Duration::from_millis(20)).await;
    let yaml = gateway_yaml("", backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics_with_live(&dp, 60_000);
    let port = spawn_gateway(dp).await;
    send_requests(port, 10, "/api").await;
    let snap = ah.store.live_snapshot().expect("live sketches attached");
    let route = snap
        .routes
        .iter()
        .find(|r| r.route == "all")
        .expect("route 'all' in snapshot");
    assert!(
        route.requests >= 10,
        "requests >= 10, got {}",
        route.requests
    );
    // Percentiles should be non-decreasing: p50 <= p95 <= p99.
    assert!(
        route.p50_ms <= route.p95_ms + 0.01,
        "p50 {} <= p95 {}",
        route.p50_ms,
        route.p95_ms
    );
    assert!(
        route.p95_ms <= route.p99_ms + 0.01,
        "p95 {} <= p99 {}",
        route.p95_ms,
        route.p99_ms
    );
    // The average should be positive (requests took some time).
    assert!(route.avg_ms > 0.0, "avg > 0, got {}", route.avg_ms);
}

#[tokio::test]
async fn live_sketch_window_rotation() {
    let (backend_port, _hits) =
        spawn_backend(|_n, _m, _p, _b| ok(), std::time::Duration::from_millis(0)).await;
    let yaml = gateway_yaml("", backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    // 100 ms window for fast rotation.
    let ah = attach_analytics_with_live(&dp, 100);
    let port = spawn_gateway(dp).await;
    send_requests(port, 3, "/api").await;
    // Snapshot the first window.
    let snap1 = ah.store.live_snapshot().expect("live sketches attached");
    let reqs1 = snap1
        .routes
        .iter()
        .find(|r| r.route == "all")
        .map(|r| r.requests)
        .unwrap_or(0);
    assert!(reqs1 >= 3, "first window has >= 3 requests, got {reqs1}");
    // Wait for the window to expire and rotate.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    // Send one more request to trigger rotation + new window.
    send_requests(port, 1, "/api").await;
    let snap2 = ah.store.live_snapshot().expect("live sketches attached");
    let reqs2 = snap2
        .routes
        .iter()
        .find(|r| r.route == "all")
        .map(|r| r.requests)
        .unwrap_or(0);
    // The new window starts fresh: only the 1 new request.
    assert!(
        reqs2 <= 1,
        "new window starts fresh (<= 1 request), got {reqs2}"
    );
    // The window start should have advanced.
    assert!(
        snap2.window_start_ms > snap1.window_start_ms,
        "window advanced: {} > {}",
        snap2.window_start_ms,
        snap1.window_start_ms
    );
}

#[tokio::test]
async fn live_sketch_per_route() {
    // Two routes to two backends.
    let (backend_port, _hits) =
        spawn_backend(|_n, _m, _p, _b| ok(), std::time::Duration::from_millis(0)).await;
    let yaml = format!(
        "routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         - name: web\n\
         \x20 service: svc2\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /web\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         - name: svc2\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n"
    );
    let dp = support::dataplane_from(&yaml);
    let ah = attach_analytics_with_live(&dp, 60_000);
    let port = spawn_gateway(dp).await;
    send_requests(port, 3, "/api").await;
    send_requests(port, 2, "/web").await;
    let snap = ah.store.live_snapshot().expect("live sketches attached");
    let api = snap.routes.iter().find(|r| r.route == "api");
    let web = snap.routes.iter().find(|r| r.route == "web");
    assert!(api.is_some(), "route 'api' in snapshot");
    assert!(web.is_some(), "route 'web' in snapshot");
    let api = api.unwrap();
    let web = web.unwrap();
    assert!(api.requests >= 3, "api >= 3, got {}", api.requests);
    assert!(web.requests >= 2, "web >= 2, got {}", web.requests);
}

// --- insights engine tests (direct, deterministic) -------------------------

#[test]
fn forecast_predicts_next_window() {
    let engine = InsightsEngine::new(&AnalyticsInsights {
        forecast: true,
        anomaly_baseline: false,
        baseline_windows: 100,
    });
    // Feed historical data at minute 0 across several "days".
    for day in 0..10 {
        engine.observe(BaselineWindow {
            ts_ms: day * 86_400_000,
            requests: 100,
            errors: 5,
            avg_latency_ms: 50.0,
        });
    }
    // Forecast for a time whose NEXT minute is minute 0.
    let r: ForecastResult = engine.forecast(-60_000);
    assert!(r.predicted_requests > 0.0, "predicted requests > 0");
    assert!(r.confidence > 0.0, "confidence > 0");
    assert!(r.predicted_error_rate >= 0.0, "error rate >= 0");
    assert!(r.predicted_avg_latency_ms > 0.0, "latency > 0");
}

#[test]
fn anomaly_detection_flags_spike() {
    let engine = InsightsEngine::new(&AnalyticsInsights {
        forecast: false,
        anomaly_baseline: true,
        baseline_windows: 100,
    });
    // Build a baseline at minute 0: 100 requests, 0 errors.
    engine.observe(BaselineWindow {
        ts_ms: 0,
        requests: 100,
        errors: 0,
        avg_latency_ms: 50.0,
    });
    // Current window: 300 requests (3x baseline).
    let r: AnomalyResult = engine.detect_anomaly(&BaselineWindow {
        ts_ms: 0,
        requests: 300,
        errors: 0,
        avg_latency_ms: 50.0,
    });
    assert!(r.is_anomalous, "spike is anomalous");
    assert!(r.score > 0.0, "score > 0");
    assert!(r.reason.is_some(), "reason present");
}

#[test]
fn anomaly_detection_ignores_normal() {
    let engine = InsightsEngine::new(&AnalyticsInsights {
        forecast: false,
        anomaly_baseline: true,
        baseline_windows: 100,
    });
    engine.observe(BaselineWindow {
        ts_ms: 0,
        requests: 100,
        errors: 0,
        avg_latency_ms: 50.0,
    });
    let r: AnomalyResult = engine.detect_anomaly(&BaselineWindow {
        ts_ms: 0,
        requests: 120,
        errors: 0,
        avg_latency_ms: 55.0,
    });
    assert!(!r.is_anomalous, "normal traffic is not anomalous");
    assert!(r.reason.is_none(), "no reason when not anomalous");
}

#[test]
fn seasonal_baseline_builds() {
    let engine = InsightsEngine::new(&AnalyticsInsights {
        forecast: true,
        anomaly_baseline: true,
        baseline_windows: 200,
    });
    // Feed data over time at minute 0.
    for day in 0..20 {
        engine.observe(BaselineWindow {
            ts_ms: day * 86_400_000,
            requests: 100,
            errors: 5,
            avg_latency_ms: 50.0,
        });
    }
    // The seasonal entry for minute 0 should have accumulated count.
    let r = engine.forecast(-60_000);
    // After 20 observations confidence = 20/1440.
    assert!(
        (r.confidence - 20.0 / 1440.0).abs() < 1e-9,
        "confidence ~20/1440, got {}",
        r.confidence
    );
    assert!(r.predicted_requests > 0.0, "predicted requests > 0");
}

// --- validation tests ------------------------------------------------------

#[test]
fn validation_rejects_invalid_freshness() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  live_sketches:\n    enabled: true\n    freshness_target_ms: 50\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "analytics.live_sketches.freshness_target_ms"
                && i.message.contains("out of range")),
        "freshness 50 rejected: {issues:?}"
    );
    // Upper bound: 5001 is out of range.
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  live_sketches:\n    enabled: true\n    freshness_target_ms: 5001\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "analytics.live_sketches.freshness_target_ms"
                && i.message.contains("out of range")),
        "freshness 5001 rejected: {issues:?}"
    );
    // In-range values are accepted.
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  live_sketches:\n    enabled: true\n    freshness_target_ms: 500\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        !issues
            .iter()
            .any(|i| i.field == "analytics.live_sketches.freshness_target_ms"),
        "freshness 500 accepted: {issues:?}"
    );
}

#[test]
fn validation_rejects_zero_baseline_windows() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  insights:\n    forecast: true\n    anomaly_baseline: false\n    baseline_windows: 0\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "analytics.insights.baseline_windows"
                && i.message.contains("must be > 0")),
        "baseline_windows 0 rejected: {issues:?}"
    );
}

#[test]
fn validation_accepts_disabled_live_sketches_bounds() {
    // When live_sketches is disabled, the freshness bounds do not
    // apply (the sketches are not used).
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  live_sketches:\n    enabled: false\n    freshness_target_ms: 50\n",
        base = validation_base()
    ));
    let issues = dwara_core::snapshot::validate(&gw);
    assert!(
        !issues
            .iter()
            .any(|i| i.field == "analytics.live_sketches.freshness_target_ms"),
        "disabled live_sketches skip freshness validation: {issues:?}"
    );
}

// --- config round-trip test ------------------------------------------------

#[test]
fn config_parses_live_sketches_and_insights() {
    let gw = parse_ok(&format!(
        "{base}analytics:\n  path: /tmp/a.db\n  live_sketches:\n    enabled: true\n    freshness_target_ms: 250\n  insights:\n    forecast: true\n    anomaly_baseline: true\n    baseline_windows: 720\n",
        base = validation_base()
    ));
    let a = gw.analytics.as_ref().expect("analytics block");
    let ls = a.live_sketches.as_ref().expect("live_sketches block");
    assert!(ls.enabled);
    assert_eq!(ls.freshness_target_ms, 250);
    let ins = a.insights.as_ref().expect("insights block");
    assert!(ins.forecast);
    assert!(ins.anomaly_baseline);
    assert_eq!(ins.baseline_windows, 720);
}

// --- live sketch + insights integration (dataplane) ------------------------

#[tokio::test]
async fn live_sketch_feeds_insights_on_rotation() {
    let (backend_port, _hits) =
        spawn_backend(|_n, _m, _p, _b| ok(), std::time::Duration::from_millis(0)).await;
    let yaml = gateway_yaml("", backend_port, None, "");
    let dp = support::dataplane_from(&yaml);
    // 100 ms window + insights with anomaly baseline.
    let ah = attach_analytics_with_insights(
        &dp,
        100,
        &AnalyticsInsights {
            forecast: true,
            anomaly_baseline: true,
            baseline_windows: 100,
        },
    );
    let port = spawn_gateway(dp).await;
    // Send a burst to build the first window.
    send_requests(port, 10, "/api").await;
    // Wait for rotation so the window is observed by the engine.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    // Send another request to trigger rotation + observation.
    send_requests(port, 1, "/api").await;
    // The forecast endpoint should now return a prediction (the
    // engine has observed at least one window).
    let forecast = ah
        .store
        .insights_forecast()
        .expect("insights engine attached");
    // After one observation, the forecast for the minute that was
    // observed may or may not have data (depends on the minute-of-day
    // of the rotation). We assert the call succeeds and returns a
    // well-formed result.
    assert!(forecast.predicted_requests >= 0.0);
    assert!(forecast.confidence >= 0.0);
    // The anomaly endpoint should return a result (not anomalous yet
    // — the baseline is just building).
    let anomaly = ah
        .store
        .insights_detect_anomaly()
        .expect("insights engine attached");
    assert!(anomaly.score >= 0.0);
}

// --- direct record() test (no dataplane needed) ----------------------------

#[tokio::test]
async fn live_sketch_direct_record_and_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = EmbeddedAnalytics::open(
        &dir.path().join("a.db").display().to_string(),
        DEFAULT_RETENTION_MS,
        100,
        0,
    )
    .unwrap();
    let sketches = LiveSketches::new(60_000);
    store.set_live_sketches(sketches);
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let _workers = store.spawn_workers(shutdown_rx);
    // Record directly via AccessRecord (the same path the dataplane
    // uses).
    for i in 0..10u16 {
        let mut rec = AccessRecord::new(
            format!("req-{i}"),
            "GET".to_string(),
            "/api".to_string(),
            "edge".to_string(),
        );
        rec.route = "all".to_string();
        rec.status = if i >= 8 { 500 } else { 200 };
        rec.duration_ms = (i as f64) * 10.0;
        store.record(&rec);
    }
    let snap = store.live_snapshot().expect("live sketches attached");
    let route = snap
        .routes
        .iter()
        .find(|r| r.route == "all")
        .expect("route 'all' in snapshot");
    assert_eq!(route.requests, 10, "10 requests recorded");
    assert_eq!(route.errors, 2, "2 errors (status 500)");
    assert_eq!(route.error_rate, 0.2, "error rate 0.2");
    // p50 should be around the 5th sample (50ms), p99 the 10th (90ms).
    assert!(route.p50_ms > 0.0, "p50 > 0");
    assert!(route.p99_ms >= route.p50_ms, "p99 >= p50");
    drop(shutdown_tx);
}
