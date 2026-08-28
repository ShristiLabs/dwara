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
    // DW-038: the coalescing wait bound.
    assert!(ok("      ttl_secs: 30\n      coalescing: {}"));
    assert!(ok(
        "      ttl_secs: 30\n      coalescing: { wait_ms: 60000 }"
    ));
    assert!(err("      ttl_secs: 30\n      coalescing: { wait_ms: 0 }").contains("wait_ms"));
    assert!(err("      ttl_secs: 30\n      coalescing: { wait_ms: 60001 }").contains("wait_ms"));
    assert!(err("      ttl_secs: 30\n      coalescing: { wait: 5 }")
        .to_ascii_lowercase()
        .contains("unknown field"));
}

// --- request coalescing (DW-038): N concurrent misses -> 1 upstream call ----

/// Route cache block with coalescing enabled and a generous wait (the
/// default 5 s would race the test rendezvous on a loaded CI runner).
const COALESCING: &str = "      ttl_secs: 30\n      coalescing: { wait_ms: 60000 }";

/// One gauge/unlabeled-counter value off the observability text render
/// (0 when the family has not rendered a sample yet).
fn metric(dp: &Arc<DataPlane>, name: &str) -> i64 {
    let prefix = format!("{name} ");
    for line in dp.observability().render().lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            if let Ok(v) = rest.trim().parse::<i64>() {
                return v;
            }
        }
    }
    0
}

/// One labeled-counter child value off the render (0 when absent).
fn outcome(dp: &Arc<DataPlane>, family: &str, label: &str) -> i64 {
    metric(dp, &format!("{family}{{outcome=\"{label}\"}}"))
}

/// Bounded poll until `cond` holds (the suite's rendezvous pattern:
/// observable state, never bare sleeps).
async fn await_state(cond: impl Fn() -> bool, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A one-way gate: arrivals park until [`Gate::release`], and once
/// released, LATER arrivals pass straight through (fail-open fetches
/// that reach the upstream after the test opened the gate must not
/// park on a notification that already fired — Notify stores no
/// permits). The subscribe-before-check in `wait` closes the
/// release-races-wait registration window.
struct Gate {
    open: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Gate {
            open: std::sync::atomic::AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        })
    }

    fn release(&self) {
        self.open.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let mut notified = Box::pin(self.notify.notified());
            notified.as_mut().enable();
            if self.open.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// A gated counting backend: every arrival records itself, then parks
/// until the returned gate is released. Bodies carry the arrival
/// number so leader/follower answers are distinguishable.
async fn gated_backend() -> (
    u16,
    Arc<std::sync::atomic::AtomicU64>,
    Arc<std::sync::atomic::AtomicU64>,
    Arc<Gate>,
) {
    let gate = Gate::new();
    let arrived = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let g0 = Arc::clone(&gate);
    let a0 = Arc::clone(&arrived);
    let c0 = Arc::clone(&count);
    let port = spawn_backend_async(move |_req: Request<hyper::body::Incoming>| {
        let g = Arc::clone(&g0);
        let a = Arc::clone(&a0);
        let c = Arc::clone(&c0);
        async move {
            let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            g.wait().await;
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .header("content-type", "text/plain")
                    .body(Full::new(Bytes::from(format!("b{n}"))))
                    .unwrap(),
            )
        }
    })
    .await;
    (port, arrived, count, gate)
}

/// Fire N concurrent GETs at the dataplane (same path).
fn fire(
    dp: &Arc<DataPlane>,
    path: &str,
    n: usize,
    headers: &[(&'static str, &'static str)],
) -> Vec<tokio::task::JoinHandle<(StatusCode, hyper::HeaderMap, Bytes)>> {
    let mut joins = Vec::new();
    for _ in 0..n {
        let dp = Arc::clone(dp);
        let path = path.to_string();
        let headers: Vec<(&'static str, String)> =
            headers.iter().map(|(k, v)| (*k, v.to_string())).collect();
        joins.push(tokio::spawn(async move {
            let hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
            get_with(&dp, &path, &hs).await
        }));
    }
    joins
}

/// THE done-when pin: eight concurrent misses on one coalescing-enabled
/// route collapse into ONE upstream call; every follower receives the
/// leader's exact stored outcome (x-cache hit), and the coalescing
/// metrics tell the whole story.
#[tokio::test]
async fn concurrent_misses_collapse_to_one_upstream_call() {
    let (port, arrived, count, gate) = gated_backend().await;
    let dp = dataplane_from(&cache_yaml(port, COALESCING, ""));

    let joins = fire(&dp, "/api/x", 8, &[]);
    // Rendezvous: the leader is parked at the backend AND all seven
    // followers are parked on its slot (the waiters gauge) before the
    // gate opens — the collapse is observed, not assumed.
    await_state(
        || {
            arrived.load(std::sync::atomic::Ordering::SeqCst) == 1
                && metric(&dp, "dwara_coalescing_waiters") == 7
        },
        "1 backend arrival + 7 parked followers",
    )
    .await;
    gate.release();

    let (mut misses, mut hits) = (0, 0);
    for j in joins {
        let (status, h, body) = j.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body, "b1", "every client gets the leader's answer");
        match x_cache(&h) {
            "miss" => misses += 1,
            "hit" => hits += 1,
            other => panic!("unexpected x-cache {other:?}"),
        }
    }
    assert_eq!((misses, hits), (1, 7));
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "8 concurrent misses -> 1 upstream call"
    );
    assert_eq!(metric(&dp, "dwara_coalescing_leaders_total"), 1);
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "served"),
        7
    );
    assert_eq!(
        metric(&dp, "dwara_coalescing_saved_upstream_calls_total"),
        7
    );
    assert_eq!(metric(&dp, "dwara_coalescing_waiters"), 0);
    // The entry the leader stored is a normal cache entry: a LATER
    // request hits it without coalescing at all.
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "hit");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Without the coalescing block nothing changes: every miss fetches.
#[tokio::test]
async fn without_the_coalescing_block_every_miss_fetches() {
    let (port, count) = counting_backend(r#"{"n":{n}}"#).await;
    let dp = dataplane_from(&cache_yaml(port, PLAIN_CACHE, ""));
    let joins = fire(&dp, "/api/x", 3, &[]);
    for j in joins {
        let (status, h, _) = j.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(x_cache(&h), "miss");
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(metric(&dp, "dwara_coalescing_leaders_total"), 0);
    assert_eq!(metric(&dp, "dwara_coalescing_waiters"), 0);
}

/// The wait bound fails open: a follower that out-waits its bound does
/// its own upstream call (a 1 ms bound against a 300 ms upstream), and
/// the client is never errored.
#[tokio::test]
async fn follower_timeout_fails_open_to_its_own_fetch() {
    let big: &'static str = "{}";
    let (port, count) = spawn_backend(
        move |_n, _m, _p, _b| {
            Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(big.as_bytes())))
                .unwrap()
        },
        Duration::from_millis(300),
    )
    .await;
    let dp = dataplane_from(&cache_yaml(
        port,
        "      ttl_secs: 30\n      coalescing: { wait_ms: 1 }",
        "",
    ));
    let joins = fire(&dp, "/api/x", 2, &[]);
    for j in joins {
        let (status, h, _) = j.await.unwrap();
        assert_eq!(status, StatusCode::OK, "fail open, never a client error");
        assert_eq!(x_cache(&h), "miss");
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(outcome(&dp, "dwara_coalescing_followers_total", "fell_back_timeout") >= 1);
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "served"),
        0
    );
}

/// A purge (epoch bump) mid-flight strands the follower open: it must
/// NOT inherit the dead generation's answer — it fetches its own, and
/// the leader's store is dropped by the epoch guard.
#[tokio::test]
async fn epoch_flip_midflight_strands_followers_open() {
    let (port, arrived, count, gate) = gated_backend().await;
    let dp = dataplane_from(&cache_yaml(port, COALESCING, ""));
    let joins = fire(&dp, "/api/x", 2, &[]);
    await_state(
        || {
            arrived.load(std::sync::atomic::Ordering::SeqCst) == 1
                && metric(&dp, "dwara_coalescing_waiters") == 1
        },
        "leader parked + 1 follower waiting",
    )
    .await;
    // The admin purge path (same epoch advance).
    dp.response_cache().bump_route("api");
    gate.release();
    let mut bodies = Vec::new();
    for j in joins {
        let (status, _h, body) = j.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        bodies.push(String::from_utf8_lossy(&body).into_owned());
    }
    bodies.sort();
    assert_eq!(bodies, vec!["b1".to_string(), "b2".to_string()]);
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the stranded follower fetched its own answer"
    );
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "fell_back_epoch"),
        1
    );
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "served"),
        0
    );
    // The leader's store was dropped (epoch guard): cold miss next.
    let (_, h, _) = get(&dp, "/api/x").await;
    assert_eq!(x_cache(&h), "miss");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
}

/// Deterministic failure propagation, pinned: a leader whose outcome is
/// NOT storable (no-store veto) publishes nothing — its followers each
/// run their own fetch (full retry policy included), never an inherited
/// failure and never a shared unstored body.
#[tokio::test]
async fn unstoreable_leader_outcome_never_reaches_followers() {
    let gate = Gate::new();
    let arrived = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let g0 = Arc::clone(&gate);
    let a0 = Arc::clone(&arrived);
    let c0 = Arc::clone(&count);
    let port = spawn_backend_async(move |_req: Request<hyper::body::Incoming>| {
        let g = Arc::clone(&g0);
        let a = Arc::clone(&a0);
        let c = Arc::clone(&c0);
        async move {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            g.wait().await;
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .header("content-type", "text/plain")
                    .header("cache-control", "no-store")
                    .body(Full::new(Bytes::from_static(b"fresh")))
                    .unwrap(),
            )
        }
    })
    .await;
    let dp = dataplane_from(&cache_yaml(port, COALESCING, ""));
    let joins = fire(&dp, "/api/x", 3, &[]);
    await_state(
        || {
            arrived.load(std::sync::atomic::Ordering::SeqCst) == 1
                && metric(&dp, "dwara_coalescing_waiters") == 2
        },
        "unstoreable leader parked + 2 followers waiting",
    )
    .await;
    gate.release();
    for j in joins {
        let (status, _h, body) = j.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body, "fresh");
    }
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "coalescing claims nothing for non-cacheable content"
    );
    assert_eq!(
        outcome(
            &dp,
            "dwara_coalescing_followers_total",
            "fell_back_unshared"
        ),
        2
    );
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "served"),
        0
    );
    assert_eq!(
        metric(&dp, "dwara_coalescing_saved_upstream_calls_total"),
        0
    );
}

/// The coalescing key is the whole cache key: concurrent requests that
/// differ in a vary dimension never coalesce (both reach the upstream,
/// neither parks behind the other).
#[tokio::test]
async fn distinct_vary_values_never_coalesce() {
    let (port, arrived, count, gate) = gated_backend().await;
    let dp = dataplane_from(&cache_yaml(
        port,
        "      ttl_secs: 30\n      vary: [x-tenant]\n      coalescing: { wait_ms: 60000 }",
        "",
    ));
    let a = fire(&dp, "/api/t", 1, &[("x-tenant", "a")]);
    let b = fire(&dp, "/api/t", 1, &[("x-tenant", "b")]);
    await_state(
        || {
            arrived.load(std::sync::atomic::Ordering::SeqCst) == 2
                && metric(&dp, "dwara_coalescing_waiters") == 0
        },
        "both vary variants fetched independently",
    )
    .await;
    gate.release();
    let mut bodies = Vec::new();
    for mut j in [a, b] {
        let (status, _h, body) = j.pop().unwrap().await.unwrap();
        assert_eq!(status, StatusCode::OK);
        bodies.push(String::from_utf8_lossy(&body).into_owned());
    }
    bodies.sort();
    // Both variants answered (arrival order is racy; the SET is not).
    assert_eq!(bodies, vec!["b1".to_string(), "b2".to_string()]);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(metric(&dp, "dwara_coalescing_leaders_total"), 2);
    assert_eq!(metric(&dp, "dwara_coalescing_waiters"), 0);
}

/// Backpressure: the leader map saturates at MAX_COALESCING_KEYS
/// distinct in-flight keys and everything past it fails open to an
/// independent fetch (uncounted by coalescing metrics — it was neither
/// leader nor follower). The upstream's connection_cap is raised so
/// all 300 fetches are genuinely in flight at once (the default 64
/// would queue them behind parked connections and never reach the
/// map).
#[tokio::test]
async fn leader_map_saturation_fails_open() {
    let (port, arrived, count, gate) = gated_backend().await;
    let yaml = format!(
        r#"
routes:
  - name: api
    service: svc
    match: {{ path: {{ type: prefix, value: /api }} }}
    action: {{ type: proxy }}
    cache:
      ttl_secs: 30
      coalescing: {{ wait_ms: 60000 }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    connection_cap: 512
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    );
    let dp = dataplane_from(&yaml);
    const N: usize = 300; // 256 leaders + 44 uncounted independent fetches
    let mut joins = Vec::new();
    for i in 0..N {
        let dp = Arc::clone(&dp);
        joins.push(tokio::spawn(async move {
            get(&dp, &format!("/api/sat?k={i}")).await
        }));
    }
    await_state(
        || arrived.load(std::sync::atomic::Ordering::SeqCst) == N as u64,
        "all 300 independent fetches reached the upstream",
    )
    .await;
    assert_eq!(
        metric(&dp, "dwara_coalescing_leaders_total"),
        256,
        "the map capped at MAX_COALESCING_KEYS leaders"
    );
    assert_eq!(metric(&dp, "dwara_coalescing_waiters"), 0);
    gate.release();
    for j in joins {
        let (status, _h, _) = j.await.unwrap();
        assert_eq!(status, StatusCode::OK, "saturation never sheds or errors");
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), N as u64);
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "served"),
        0
    );
}

/// No deadlock or double-subscribe with the DW-037 single-flight
/// revalidation: a background revalidation parked mid-fetch on one key
/// while coalescing collapses a cold miss on ANOTHER key — disjoint
/// state, no shared locks, both behaviors intact.
#[tokio::test]
async fn swr_revalidation_and_coalescing_do_not_deadlock() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let g0 = Arc::clone(&gate);
    let c0 = Arc::clone(&count);
    let port = spawn_backend_async(move |_req: Request<hyper::body::Incoming>| {
        let g = Arc::clone(&g0);
        let c = Arc::clone(&c0);
        async move {
            let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            // ONLY the revalidation (arrival 2) parks; every other
            // arrival answers instantly.
            if n == 2 {
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
        "      ttl_secs: 1\n      stale_while_revalidate_secs: 30\n      coalescing: { wait_ms: 60000 }",
        "",
    ));
    let _ = get(&dp, "/api/x").await; // miss, stores b1
    let _ = get(&dp, "/api/x").await; // hit
    tokio::time::sleep(Duration::from_millis(1500)).await; // stale now
                                                           // Stale serving triggers the gated background revalidation (arrival 2).
    let stale = fire(&dp, "/api/x", 3, &[]);
    for j in stale {
        let (_, h, body) = j.await.unwrap();
        assert_eq!(x_cache(&h), "stale");
        assert_eq!(&body, "b1");
    }
    await_state(
        || count.load(std::sync::atomic::Ordering::SeqCst) == 2,
        "revalidation parked at the upstream",
    )
    .await;
    // With the revalidation still parked, a cold burst on another path
    // MUST still collapse and complete — no shared lock, no waiting on
    // the revalidation's in-flight set.
    let joins = fire(&dp, "/api/other", 3, &[]);
    let (mut misses, mut hits) = (0, 0);
    for j in joins {
        let (status, h, body) = j.await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "coalescing completes while a revalidation is parked"
        );
        assert_eq!(&body, "b3");
        match x_cache(&h) {
            "miss" => misses += 1,
            "hit" => hits += 1,
            other => panic!("unexpected x-cache {other:?}"),
        }
    }
    assert_eq!((misses, hits), (1, 2));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
    gate.notify_waiters(); // let the revalidation finish and drain
}

/// GET-only scope (DW-038): the shapes the cache lookup bypasses
/// (POST, body-bearing GET, upgrade-header GET) never coalesce — with
/// a leader parked on the key's slot, none of them joins it (the
/// waiters gauge stays at zero and the leader count stays at one);
/// each fetches independently exactly as before the feature existed.
#[tokio::test]
async fn bypassed_shapes_never_join_a_coalescing_leader() {
    let (port, arrived, count, gate) = gated_backend().await;
    let dp = dataplane_from(&cache_yaml(port, COALESCING, ""));

    // The GET leader: parked at the backend holding the key's slot.
    let mut leader = fire(&dp, "/api/x", 1, &[]);
    await_state(
        || arrived.load(std::sync::atomic::Ordering::SeqCst) == 1,
        "GET leader parked at the backend",
    )
    .await;
    assert_eq!(metric(&dp, "dwara_coalescing_leaders_total"), 1);

    // Three bypassed shapes at the SAME path while the leader holds
    // the slot. A shape that (wrongly) joined would park as a waiter;
    // instead all three arrive at the upstream on their own.
    let bypassed: Vec<tokio::task::JoinHandle<(StatusCode, hyper::HeaderMap, Bytes)>> = [
        (
            hyper::Method::POST,
            vec![],
            Some(Bytes::from_static(b"payload")),
        ),
        (
            hyper::Method::GET,
            vec![],
            Some(Bytes::from_static(b"body")),
        ),
        (hyper::Method::GET, vec![("upgrade", "websocket")], None),
    ]
    .into_iter()
    .map(|(method, headers, body)| {
        let dp = Arc::clone(&dp);
        tokio::spawn(async move {
            let mut builder = Request::builder().method(method).uri("/api/x");
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
            let payload = body.unwrap_or_default();
            let resp = proxy::handle(&dp, ip(), builder.body(Full::new(payload)).unwrap()).await;
            let (parts, bod) = resp.into_parts();
            let bytes = bod.collect().await.unwrap().to_bytes();
            (parts.status, parts.headers, bytes)
        })
    })
    .collect();
    await_state(
        || {
            arrived.load(std::sync::atomic::Ordering::SeqCst) == 4
                && metric(&dp, "dwara_coalescing_waiters") == 0
        },
        "all three bypassed shapes reached the upstream, none parked",
    )
    .await;
    assert_eq!(
        metric(&dp, "dwara_coalescing_leaders_total"),
        1,
        "bypassed shapes never lead either"
    );
    gate.release();

    for j in bypassed {
        let (status, h, _) = j.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(x_cache(&h), "bypass");
    }
    let (status, _, _) = leader.pop().unwrap().await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        4,
        "one leader + three independent bypass fetches"
    );
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "served"),
        0
    );
    assert_eq!(metric(&dp, "dwara_coalescing_waiters"), 0);
}

/// Consumer isolation (DW-038): the coalescing key embeds the
/// consumer identity, so two consumers' concurrent identical GETs on
/// the same path collapse WITHIN each identity (one leader each) but
/// never ACROSS — no follower is ever handed an outcome computed for
/// another consumer.
#[tokio::test]
async fn consumers_never_coalesce_across_identities() {
    let (port, arrived, count, gate) = gated_backend().await;
    let dp = dataplane_from(&cache_yaml(
        port,
        COALESCING,
        r#"consumers:
  - name: partner-co
    credentials:
      - { type: api_key, key: partner-key }
  - name: plain-co
    credentials:
      - { type: api_key, key: plain-key }
"#,
    ));

    // Two concurrent GETs per consumer on the SAME path: per identity
    // one leader fetches while its follower parks; the identities
    // never merge (that would need identical cache keys, and the
    // consumer name is a key component).
    let partner = fire(&dp, "/api/x", 2, &[("x-api-key", "partner-key")]);
    let plain = fire(&dp, "/api/x", 2, &[("x-api-key", "plain-key")]);
    await_state(
        || {
            arrived.load(std::sync::atomic::Ordering::SeqCst) == 2
                && metric(&dp, "dwara_coalescing_waiters") == 2
        },
        "one leader per identity parked, one follower each",
    )
    .await;
    gate.release();

    let collect = |joins: Vec<tokio::task::JoinHandle<(StatusCode, hyper::HeaderMap, Bytes)>>| async {
        let mut bodies = Vec::new();
        for j in joins {
            let (status, h, body) = j.await.unwrap();
            assert_eq!(status, StatusCode::OK);
            match x_cache(&h) {
                "miss" | "hit" => {}
                other => panic!("unexpected x-cache {other:?}"),
            }
            bodies.push(String::from_utf8_lossy(&body).into_owned());
        }
        bodies
    };
    let partner_bodies = collect(partner).await;
    let plain_bodies = collect(plain).await;

    // Within an identity the follower replayed the leader's exact
    // stored outcome; across identities the answers differ.
    assert_eq!(partner_bodies[0], partner_bodies[1]);
    assert_eq!(plain_bodies[0], plain_bodies[1]);
    assert_ne!(
        partner_bodies[0], plain_bodies[0],
        "each consumer received its own leader's outcome"
    );
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one upstream call per consumer identity, never one shared"
    );
    assert_eq!(metric(&dp, "dwara_coalescing_leaders_total"), 2);
    assert_eq!(
        outcome(&dp, "dwara_coalescing_followers_total", "served"),
        2
    );
    assert_eq!(
        metric(&dp, "dwara_coalescing_saved_upstream_calls_total"),
        2
    );
    assert_eq!(metric(&dp, "dwara_coalescing_waiters"), 0);
}
