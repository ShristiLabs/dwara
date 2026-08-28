//! Response caching (DW-037): end-to-end behavior through the real
//! dataplane — hit/miss/stale/bypass headers, per-consumer keying with
//! masking, TTL and stale-while-revalidate windows, ETag
//! revalidation, the storage vetoes, the size cap, and reload/purge
//! invalidation. Unit-level pieces (envelope codec, key derivation,
//! validator matching) live in `tests/unit/response_cache.rs`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dwara_core::proxy::{self, DataPlane};
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use support::{dataplane_from, spawn_backend, spawn_backend_async, spawn_gateway, uri};

fn ip() -> std::net::IpAddr {
    "127.0.0.1".parse().unwrap()
}

/// Drive the dataplane directly (the masking-suite pattern): no
/// listener, full assertion access to status/headers/body.
async fn get(dp: &Arc<DataPlane>, path: &str) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let resp = proxy::handle(
        dp,
        ip(),
        Request::builder()
            .uri(path)
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, bytes)
}

async fn get_with(
    dp: &Arc<DataPlane>,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let mut builder = Request::builder().uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let resp = proxy::handle(dp, ip(), builder.body(Full::new(Bytes::new())).unwrap()).await;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, bytes)
}

fn x_cache(headers: &hyper::HeaderMap) -> &str {
    headers
        .get("x-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<absent>")
}

/// Gateway YAML: one `/api` prefix route with a `cache` block, the
/// rest of the route/gateway shape via `extra` (masking, transforms,
/// more routes, consumers, ...).
fn cache_yaml(backend_port: u16, cache_block: &str, extra: &str) -> String {
    format!(
        r#"
routes:
  - name: api
    service: svc
    match:
      path: {{ type: prefix, value: /api }}
    action: {{ type: proxy }}
    cache:
{cache_block}
{extra}services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {backend_port} }}]
"#
    )
}

const PLAIN_CACHE: &str = "      ttl_secs: 30";

/// Static-body backend counting requests, answering per-request.
async fn counting_backend(body: &'static str) -> (u16, Arc<std::sync::atomic::AtomicU64>) {
    spawn_backend(
        move |n, _m, p, _b| {
            let _ = p;
            Response::builder()
                .header("content-type", "application/json")
                .header("etag", format!("\"v{n}\""))
                .body(Full::new(Bytes::from(body.replace("{n}", &n.to_string()))))
                .unwrap()
        },
        Duration::ZERO,
    )
    .await
}

// --- the done-when: hit/miss headers, one upstream call ----------------------

#[tokio::test]
async fn miss_then_hit_with_headers_and_single_upstream_call() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));

    let (status, headers, body) = get(&dp, "/api/x").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(x_cache(&headers), "miss");
    assert_eq!(&body, r#"{"n":1}"#);

    let (status, headers, body) = get(&dp, "/api/x").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(x_cache(&headers), "hit");
    assert_eq!(&body, r#"{"n":1}"#, "the stored body replays verbatim");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Age is present and whole-seconds on a hit; the stored ETag and
    // content-type round-trip.
    assert!(headers.get("age").is_some());
    assert_eq!(
        headers.get("etag").and_then(|v| v.to_str().ok()),
        Some("\"v1\"")
    );
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json")
    );

    // The query string keys: a different query is a different entry.
    let (_, headers, _) = get(&dp, "/api/x?q=2").await;
    assert_eq!(x_cache(&headers), "miss");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn non_get_methods_bypass() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));
    for _ in 0..2 {
        let resp = proxy::handle(
            &dp,
            ip(),
            Request::builder()
                .method(hyper::Method::POST)
                .uri("/api/x")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-cache").and_then(|v| v.to_str().ok()),
            Some("bypass")
        );
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn credentialed_requests_bypass() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));
    for h in [("authorization", "Bearer t"), ("cookie", "s=1")] {
        let (_, headers, _) = get_with(&dp, "/api/x", &[h]).await;
        assert_eq!(x_cache(&headers), "bypass", "the {h:?} header must bypass");
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// --- per-consumer keying with masking (the DW-029 interaction) ---------------

#[tokio::test]
async fn masked_variants_never_cross_consumers() {
    let (port, count) = counting_backend(r#"{"n":{n},"secret":"s","floor":"f"}"#).await;
    let dp = dataplane_from(&cache_yaml(
        port,
        PLAIN_CACHE,
        r#"    masking:
      max_bytes: 4096
      fields:
        - /secret
      groups:
        partners:
          - /floor
consumers:
  - name: partner-co
    groups: [partners]
    credentials:
      - { type: api_key, key: partner-key }
  - name: plain-co
    groups: [basic]
    credentials:
      - { type: api_key, key: plain-key }
"#,
    ));

    // Cold: one upstream call per consumer (anonymous, partner, plain).
    // (The masked body re-serializes sorted: floor, n, secret.)
    let (_, h, b) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "miss");
    assert!(b.ends_with(&br#""secret":"***"}"#[..]));
    assert!(
        std::str::from_utf8(&b).unwrap().contains(r#""floor":"f""#),
        "anonymous keeps the floor"
    );

    let (_, h, b) = get_with(&dp, "/api/x", &[("x-api-key", "partner-key")]).await;
    assert_eq!(x_cache(&h), "miss");
    assert!(
        std::str::from_utf8(&b)
            .unwrap()
            .contains(r#""floor":"***""#),
        "partner group masks floor"
    );
    assert!(b.ends_with(&br#""secret":"***"}"#[..]));
    let (_, h, b2) = get_with(&dp, "/api/x", &[("x-api-key", "plain-key")]).await;
    assert_eq!(x_cache(&h), "miss");
    assert!(
        std::str::from_utf8(&b2).unwrap().contains(r#""floor":"f""#),
        "plain consumer keeps floor"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);

    // Warm: every identity replays its OWN stored bytes — the partner
    // a fully-masked variant, the plain one a lighter one — with zero
    // new upstream calls. Stored bytes are post-mask, keyed per
    // consumer: no variant can leak across.
    let (_, h, b) = get_with(&dp, "/api/x", &[("x-api-key", "partner-key")]).await;
    assert_eq!(x_cache(&h), "hit");
    assert!(
        std::str::from_utf8(&b)
            .unwrap()
            .contains(r#""floor":"***""#),
        "the partner variant replays"
    );
    let (_, h, b2) = get_with(&dp, "/api/x", &[("x-api-key", "plain-key")]).await;
    assert_eq!(x_cache(&h), "hit");
    assert!(
        std::str::from_utf8(&b2).unwrap().contains(r#""floor":"f""#),
        "the plain variant replays"
    );
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "hit");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
}

// --- TTL, stale-while-revalidate, ETag revalidation --------------------------

#[tokio::test]
async fn expired_entry_refetches() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(port, "      ttl_secs: 1", ""));
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "miss");
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "hit");
    // 1.5 s: 50% margin over the 1 s TTL, the freshness clock (not a
    // synchronization primitive — the sleep IS the thing under test).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (_, h, body) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "miss");
    assert_eq!(&body, r#"{"n":2}"#);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn stale_while_revalidate_serves_stale_and_refreshes_in_background() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(
        port,
        "      ttl_secs: 1\n      stale_while_revalidate_secs: 10",
        "",
    ));
    let _ = get(&dp, "/api/x").await; // miss, stores n=1
    let _ = get(&dp, "/api/x").await; // hit
    tokio::time::sleep(Duration::from_millis(1500)).await; // now stale
    let (_, h, body) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "stale");
    assert_eq!(&body, r#"{"n":1}"#, "the STALE body serves immediately");

    // The background revalidation lands within a bounded poll (the
    // backend answers instantly; the bound is scheduling slack).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while count.load(std::sync::atomic::Ordering::SeqCst) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "revalidation never ran"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Fresh again afterwards: a HIT with the refreshed body.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (_, h, body) = get(&dp, "/api/x").await;
        if x_cache(&h) == "hit" {
            assert_eq!(&body, r#"{"n":2}"#);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "entry never refreshed after background revalidation"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn etag_revalidation_304_refreshes_without_resending_body() {
    // Backend honors If-None-Match: the same validator answers 304
    // with an empty body.
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = Arc::clone(&count);
    let port = spawn_backend_async(move |req: Request<hyper::body::Incoming>| {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let inm = req
                .headers()
                .get("if-none-match")
                .and_then(|v| v.to_str().ok());
            let current = "\"always\"";
            if inm == Some(current) {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("etag", current)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            Ok(Response::builder()
                .header("content-type", "application/json")
                .header("etag", current)
                .body(Full::new(Bytes::from_static(b"{\"v\":1}")))
                .unwrap())
        }
    })
    .await;
    let dp = dataplane_from(&cache_yaml(port, "      ttl_secs: 1", ""));
    let _ = get(&dp, "/api/x").await; // miss + store
    tokio::time::sleep(Duration::from_millis(1500)).await; // expired
                                                           // The gateway injected the stored validator: the upstream answers
                                                           // 304, the cache refreshes and serves the STORED body as 200 —
                                                           // never a bare 304 to a client that sent no conditional.
    let (status, h, body) = get(&dp, "/api/x").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(x_cache(&h), "revalidated");
    assert_eq!(&body, "{\"v\":1}");
    // Client-sent validator against the FRESH entry: 304 from cache,
    // no upstream call at all.
    let (status, h, _) = get_with(&dp, "/api/x", &[("if-none-match", "\"always\"")]).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(x_cache(&h), "hit");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// --- the storage vetoes ------------------------------------------------------

#[tokio::test]
async fn no_store_and_set_cookie_and_encoded_are_not_stored() {
    for (header, value) in [
        ("cache-control", "no-store"),
        ("cache-control", "max-age=60, private"),
        ("set-cookie", "s=1"),
        ("content-encoding", "gzip"),
        ("vary", "*"),
    ] {
        let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = Arc::clone(&count);
        let port = spawn_backend_async(move |_req: Request<hyper::body::Incoming>| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .header("content-type", "application/json")
                        .header(header, value)
                        .body(Full::new(Bytes::from_static(b"{}")))
                        .unwrap(),
                )
            }
        })
        .await;
        let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));
        let _ = get(&dp, "/api/x").await;
        let (_, h, _) = get(&dp, "/api/x").await;
        assert_eq!(x_cache(&h), "miss", "'{header}: {value}' must veto storage");
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}

// --- the size cap: over-cap streams through, never stored --------------------

#[tokio::test]
async fn over_cap_body_passes_through_unstored_and_intact() {
    let big: &'static str = "0123456789abcdef".repeat(128).leak();
    let (port, count) = spawn_backend(
        move |_n, _m, _p, _b| {
            Response::builder()
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from_static(big.as_bytes())))
                .unwrap()
        },
        Duration::ZERO,
    )
    .await;
    let dp = dataplane_from(&cache_yaml(
        port,
        "      ttl_secs: 30\n      max_body_bytes: 64",
        "",
    ));
    for expected in ["miss", "miss"] {
        let (status, h, body) = get(&dp, "/api/big").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(x_cache(&h), expected);
        assert_eq!(body.len(), big.len());
        assert_eq!(&body[..16], b"0123456789abcdef");
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// --- vary keying -------------------------------------------------------------

#[tokio::test]
async fn vary_dimensions_key_independently() {
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = Arc::clone(&count);
    let port = spawn_backend_async(move |req: Request<hyper::body::Incoming>| {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let tenant = req
                .headers()
                .get("x-tenant")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("none")
                .to_string();
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .header("content-type", "text/plain")
                    .body(Full::new(Bytes::from(tenant)))
                    .unwrap(),
            )
        }
    })
    .await;
    let dp = dataplane_from(&cache_yaml(
        port,
        "      ttl_secs: 30\n      vary: [x-tenant]",
        "",
    ));
    let (_, h, b) = get_with(&dp, "/api/t", &[("x-tenant", "a")]).await;
    assert_eq!(x_cache(&h), "miss");
    assert_eq!(&b, "a");
    let (_, h, b) = get_with(&dp, "/api/t", &[("x-tenant", "b")]).await;
    assert_eq!(x_cache(&h), "miss", "a different vary value is a new entry");
    assert_eq!(&b, "b");
    let (_, h, b) = get_with(&dp, "/api/t", &[("x-tenant", "a")]).await;
    assert_eq!(x_cache(&h), "hit");
    assert_eq!(&b, "a");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn uncovered_upstream_vary_vetoes_storage() {
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = Arc::clone(&count);
    let port = spawn_backend_async(move |_req: Request<hyper::body::Incoming>| {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .header("content-type", "text/plain")
                    .header("vary", "x-other")
                    .body(Full::new(Bytes::from_static(b"v")))
                    .unwrap(),
            )
        }
    })
    .await;
    let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));
    let _ = get(&dp, "/api/x").await;
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(
        x_cache(&h),
        "miss",
        "an uncovered vary dimension forbids storage"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// --- invalidation: purge, config change, reload survival ---------------------

fn republish(dp: &Arc<DataPlane>, state: &Arc<ConfigState>, yaml: &str) {
    let gateway = dwara_core::config::parse_gateway(yaml).expect("reload config parses");
    state
        .compile_and_publish(&gateway)
        .expect("reload config publishes");
    dp.refresh();
}

#[tokio::test]
async fn purge_epoch_invalidates_and_cache_survives_unrelated_reload() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let yaml = cache_yaml(port, PLAIN_CACHE, "");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&dwara_core::config::parse_gateway(&yaml).unwrap())
        .unwrap();
    let dp = DataPlane::new(state.clone());
    let _ = get(&dp, "/api/x").await; // miss + store
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "hit");

    // Purge (the admin endpoint calls this same epoch advance): the
    // next request re-fetches.
    let epoch = dp.response_cache().bump_route("api");
    assert_eq!(epoch, 1);
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "miss");

    // Warm again, then reload with an UNCHANGED route: the store (and
    // its entries) survive — runtime state, not config.
    let _ = get(&dp, "/api/x").await;
    let yaml2 = format!(
        "allow_empty_routes: false\n{}",
        cache_yaml(port, PLAIN_CACHE, "")
    );
    republish(&dp, &state, &yaml2);
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(
        x_cache(&h),
        "hit",
        "an unrelated reload leaves entries warm"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn route_change_invalidates_only_that_route() {
    let (port, _count) = counting_backend(r#"{"n":{n}}"#).await;
    let two_routes = format!(
        r#"
routes:
  - name: api
    service: svc
    match: {{ path: {{ type: prefix, value: /api }} }}
    action: {{ type: proxy }}
    cache:
      ttl_secs: 30
  - name: other
    service: svc
    match: {{ path: {{ type: prefix, value: /other }} }}
    action: {{ type: proxy }}
    cache:
      ttl_secs: 30
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    );
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&dwara_core::config::parse_gateway(&two_routes).unwrap())
        .unwrap();
    let dp = DataPlane::new(state.clone());
    let _ = get(&dp, "/api/x").await;
    let _ = get(&dp, "/other/y").await;
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "hit");
    let (_, h, _) = get(&dp, "/other/y").await;
    assert_eq!(x_cache(&h), "hit");

    // Change ONLY the `api` route (a response transform is added): its
    // stored bytes were shaped by the old definition and MUST die;
    // `other` stays warm.
    let changed = two_routes.replacen(
        "  - name: api\n",
        "  - name: api\n    transforms:\n      response:\n        headers:\n          set:\n            x-changed: \"1\"\n",
        1,
    );
    republish(&dp, &state, &changed);
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(
        x_cache(&h),
        "miss",
        "a changed route definition invalidates its entries"
    );
    assert!(
        dp.response_cache().epoch("api") > dp.response_cache().epoch("other"),
        "only the changed route bumped"
    );
    let (_, h, _) = get(&dp, "/other/y").await;
    assert_eq!(x_cache(&h), "hit", "the untouched route stays warm");
}

/// The replay-consistency pin (the review's demanded test): a route
/// whose TRANSFORMS change must never replay the old stored bytes.
#[tokio::test]
async fn transform_change_never_replays_stale_shaped_bytes() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let base = cache_yaml(port, PLAIN_CACHE, "");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&dwara_core::config::parse_gateway(&base).unwrap())
        .unwrap();
    let dp = DataPlane::new(state.clone());
    let (_, _, body) = get(&dp, "/api/x").await;
    assert_eq!(&body, r#"{"n":1}"#);

    // New transform policy: wrap the JSON body.
    let transformed = cache_yaml(
        port,
        PLAIN_CACHE,
        "    transforms:\n      response:\n        body:\n          json:\n            max_bytes: 4096\n            ops:\n              - op: set\n                path: /wrapped\n                value: true\n",
    );
    republish(&dp, &state, &transformed);
    let (_, h, body) = get(&dp, "/api/x").await;
    assert_eq!(
        x_cache(&h),
        "miss",
        "the entry stored under the old shape is dead"
    );
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        doc["wrapped"], true,
        "the NEW shape applies, not the stored one"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// --- over the wire (listener path) + metrics --------------------------------

#[tokio::test]
async fn wire_path_and_metrics_families() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));
    let gw = spawn_gateway(dp.clone()).await;
    let client = support::h1_client();
    let resp = client.get(uri(gw, "/api/wire")).await.unwrap();
    assert_eq!(
        resp.headers().get("x-cache").and_then(|v| v.to_str().ok()),
        Some("miss")
    );
    let resp = client.get(uri(gw, "/api/wire")).await.unwrap();
    assert_eq!(
        resp.headers().get("x-cache").and_then(|v| v.to_str().ok()),
        Some("hit")
    );
    drop(resp);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

    let text = dp.observability().render();
    assert!(
        text.contains("dwara_cache_lookups_total"),
        "lookup family renders"
    );
    assert!(text.contains("outcome=\"hit\""));
    assert!(text.contains("outcome=\"miss\""));
    assert!(text.contains("dwara_cache_stores_total"));
    assert!(text.contains("dwara_cache_entries"));
}

// --- tester stage: the remaining closed rules and the replay-tail pin --------

#[tokio::test]
async fn head_upgrade_and_body_bearing_requests_bypass() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));
    // HEAD: cacheable in spirit, bypassed in v1 (no-body replay framing).
    let resp = proxy::handle(
        &dp,
        ip(),
        Request::builder()
            .method(hyper::Method::HEAD)
            .uri("/api/x")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-cache").and_then(|v| v.to_str().ok()),
        Some("bypass"),
        "HEAD is bypassed in v1"
    );
    // A GET with a declared body never caches (the body could select the
    // response; the deterministic rule refuses to guess).
    let resp = proxy::handle(
        &dp,
        ip(),
        Request::builder()
            .method(hyper::Method::GET)
            .uri("/api/x")
            .body(Full::new(Bytes::from_static(b"body")))
            .unwrap(),
    )
    .await;
    assert_eq!(
        resp.headers().get("x-cache").and_then(|v| v.to_str().ok()),
        Some("bypass"),
        "a body-bearing GET bypasses"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// THE replay-tail pin: a cached hit must still run the decoration
/// tail — compression re-negotiates per request (the stored body is
/// identity), the route's security headers stamp the replayed
/// response, and a `match.accept` route's `Vary: Accept` fold is
/// advertised on the replay.
#[tokio::test]
async fn replayed_hits_still_run_the_decoration_tail() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&format!(
        r#"
routes:
  - name: api
    service: svc
    match:
      path: {{ type: prefix, value: /api }}
      accept: application/json
    action: {{ type: proxy }}
    cache:
      ttl_secs: 30
    compression:
      algorithms: [gzip]
      min_size: 0
    security_headers:
      hsts_max_age_secs: 31536000
      nosniff: true
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    ));
    // First fetch (accepts gzip, JSON): compressed by the tail, stored
    // identity before compression.
    let (_, h, _) = get_with(
        &dp,
        "/api/x",
        &[("accept", "application/json"), ("accept-encoding", "gzip")],
    )
    .await;
    assert_eq!(x_cache(&h), "miss");
    assert_eq!(
        h.get("content-encoding").and_then(|v| v.to_str().ok()),
        Some("gzip")
    );

    // Replay: still hit, still gzip (re-negotiated per request from the
    // identity bytes), still HSTS + nosniff, still Vary: Accept.
    let (_, h, body) = get_with(
        &dp,
        "/api/x",
        &[("accept", "application/json"), ("accept-encoding", "gzip")],
    )
    .await;
    assert_eq!(x_cache(&h), "hit");
    assert_eq!(
        h.get("content-encoding").and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert!(
        body.len() > 8,
        "the replayed body is compressed again: {} bytes",
        body.len()
    );
    assert_eq!(
        h.get("strict-transport-security")
            .and_then(|v| v.to_str().ok()),
        Some("max-age=31536000"),
        "security headers stamp the replay"
    );
    assert_eq!(
        h.get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    let vary = h
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        vary.to_ascii_lowercase().contains("accept"),
        "the fold is advertised: {vary}"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A client conditional on a cache with NO stored entry passes through
/// untouched; and when the upstream 304 names a DIFFERENT validator
/// than the stored one, the stored entry is dropped (validator drift —
/// it is no longer the current representation).
#[tokio::test]
async fn validator_drift_drops_the_stored_entry() {
    let which = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let w = Arc::clone(&which);
    let port = support::spawn_backend_async(move |req: Request<hyper::body::Incoming>| {
        let w = Arc::clone(&w);
        async move {
            let n = w.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let etag = format!("\"v{n}\"");
            if req
                .headers()
                .get("if-none-match")
                .and_then(|v| v.to_str().ok())
                == Some(&*etag)
            {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("etag", etag)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            Ok(Response::builder()
                .header("content-type", "text/plain")
                .header("etag", etag)
                .body(Full::new(Bytes::from(format!("body{n}"))))
                .unwrap())
        }
    })
    .await;
    let dp = dataplane_from(&cache_yaml(port, "      ttl_secs: 1", ""));
    // Cold miss stores v1.
    let _ = get(&dp, "/api/x").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // The client sends its OWN conditional naming a validator only the
    // upstream knows: the gateway forwards it (client conditionals win),
    // the upstream answers 304 naming v2, the stored v1 entry is stale
    // drift and must be dropped; the client still gets its 304.
    let (status, h, _) = get_with(&dp, "/api/x", &[("if-none-match", "\"v2\"")]).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(x_cache(&h), "miss");
    assert_eq!(which.load(std::sync::atomic::Ordering::SeqCst), 2);
    // Next plain request is a cold miss (nothing stored).
    let (_, h, body) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "miss");
    assert_eq!(&body, "body3");
}

/// Stale-while-revalidate is single-flight under concurrency: several
/// concurrent requests for the same expired-within-window key all serve
/// stale immediately and together trigger exactly ONE background
/// revalidation (the in-flight guard; DW-038 generalizes this).
#[tokio::test]
async fn swr_is_single_flight_under_concurrency() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let released = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let g0 = Arc::clone(&gate);
    let r0 = Arc::clone(&released);
    let c0 = Arc::clone(&count);
    let port = support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| {
        let g = Arc::clone(&g0);
        let r = Arc::clone(&r0);
        let c = Arc::clone(&c0);
        async move {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Slow revalidation: it stays in flight long enough for
            // the concurrent stale reads to pile up behind the guard.
            let n = r.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if n >= 2 {
                g.notified().await;
            }
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .header("content-type", "text/plain")
                    .body(Full::new(Bytes::from(format!("b{n}"))))
                    .unwrap(),
            )
        }
    })
    .await;
    let dp = dataplane_from(&cache_yaml(
        port,
        "      ttl_secs: 1\n      stale_while_revalidate_secs: 30",
        "",
    ));
    let _ = get(&dp, "/api/x").await; // miss, stores b1
    let _ = get(&dp, "/api/x").await; // hit
    tokio::time::sleep(Duration::from_millis(1500)).await; // stale now
                                                           // Five concurrent stale reads: all serve stale; ONE revalidation.
    let mut joins = Vec::new();
    for _ in 0..5 {
        let dp = Arc::clone(&dp);
        joins.push(tokio::spawn(async move { get(&dp, "/api/x").await }));
    }
    for j in joins {
        let (_, h, body) = j.await.unwrap();
        assert_eq!(x_cache(&h), "stale");
        assert_eq!(&body, "b1");
    }
    // Exactly one revalidation ran (the slow one), then release it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "concurrent stale serves triggered exactly one revalidation"
    );
    gate.notify_one();
}

// --- validation grammar (snapshot::validate_route_cache) ---------------------

fn publishes(yaml: &str) -> Result<(), String> {
    let gateway = dwara_core::config::parse_gateway(yaml).map_err(|e| e.to_string())?;
    dwara_core::snapshot::compile(&gateway)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn cache_validation_bounds_and_grammar() {
    let ok = |cache: &str| publishes(&cache_yaml(1, cache, "")).is_ok();
    let err = |cache: &str| {
        let e = publishes(&cache_yaml(1, cache, "")).unwrap_err();
        assert!(!e.is_empty());
        e
    };
    // The bounds.
    assert!(ok("      ttl_secs: 1"));
    assert!(ok("      ttl_secs: 86400"));
    assert!(err("      ttl_secs: 0").contains("ttl_secs"));
    assert!(err("      ttl_secs: 86401").contains("ttl_secs"));
    assert!(ok(
        "      ttl_secs: 30\n      stale_while_revalidate_secs: 86400"
    ));
    assert!(
        err("      ttl_secs: 30\n      stale_while_revalidate_secs: 86401")
            .contains("stale_while_revalidate_secs")
    );
    assert!(ok("      ttl_secs: 30\n      max_body_bytes: 1"));
    assert!(ok("      ttl_secs: 30\n      max_body_bytes: 16777216"));
    assert!(err("      ttl_secs: 30\n      max_body_bytes: 0").contains("max_body_bytes"));
    assert!(err("      ttl_secs: 30\n      max_body_bytes: 16777217").contains("max_body_bytes"));
    // The vary grammar: forbidden names name their reason.
    for (name, needle) in [
        ("authorization", "never cacheable"),
        ("cookie", "never cacheable"),
        ("host", "host match"),
        ("transfer-encoding", "hop-by-hop"),
        ("upgrade", "hop-by-hop"),
        ("content-length", "framing"),
        ("cache-control", "cache directives"),
        ("x-consumer-name", "already a cache key"),
    ] {
        let e = err(&format!("      ttl_secs: 30\n      vary: [{name}]"));
        assert!(e.contains(needle), "vary [{name}] must explain: {e}");
    }
    // Duplicates and non-names.
    assert!(err("      ttl_secs: 30\n      vary: [x-a, x-a]").contains("duplicate"));
    assert!(err("      ttl_secs: 30\n      vary: [X-A]").contains("not a header name"));
    assert!(err("      ttl_secs: 30\n      vary: [x_a]").contains("not a header name"));
    // Too many dimensions.
    let many = (0..9)
        .map(|i| format!("x-d{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(err(&format!("      ttl_secs: 30\n      vary: [{many}]")).contains("at most 8"));
    // Unknown fields in the block are rejected (strict schema).
    assert!(err("      ttl_secs: 30\n      enabled: true").contains("enabled"));
}
