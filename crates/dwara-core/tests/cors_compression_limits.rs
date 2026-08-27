//! Route-scoped edge policies (DW-027): CORS preflight short-circuiting,
//! actual-response CORS decoration, response compression negotiation and
//! policy enforcement, and per-route request body/header limits.

mod support;

use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Frame;
use hyper::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_METHOD, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_TYPE, ORIGIN, VARY,
};
use hyper::{Method, Request, StatusCode};
use support::{
    body_of, dataplane_from, envelope_code, spawn_backend_async, spawn_backend_full, spawn_gateway,
    uri,
};

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A backend that counts every request it serves and answers 200 with
/// the request method echoed in a JSON body.
async fn counter_backend() -> (u16, Arc<AtomicU64>) {
    let count = Arc::new(AtomicU64::new(0));
    let port = {
        let c = Arc::clone(&count);
        spawn_backend_full(Arc::new(
            move |req: hyper::Request<hyper::body::Incoming>| {
                c.fetch_add(1, Ordering::SeqCst);
                let body = format!("{{\"method\":\"{}\"}}", req.method());
                hyper::Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap()
            },
        ))
        .await
    };
    (port, count)
}

/// Backend serving sized payloads for the compression tests, dispatched
/// on the path SUFFIX (the gateway forwards the full path; routes use
/// distinct prefixes): `*/big` a 4 KiB compressible text/plain body,
/// `*/small` 4 bytes, `*/sse` an event-stream-typed body, anything else
/// a body that already claims gzip encoding.
async fn payload_backend() -> u16 {
    spawn_backend_full(Arc::new(
        move |req: hyper::Request<hyper::body::Incoming>| {
            let path = req.uri().path();
            let (ctype, body, pre_encoded): (&str, Bytes, bool) = if path.ends_with("/big") {
                (
                    "text/plain",
                    Bytes::from("dwara compression payload line\n".repeat(160)),
                    false,
                )
            } else if path.ends_with("/small") {
                ("text/plain", Bytes::from_static(b"tiny"), false)
            } else if path.ends_with("/sse") {
                (
                    "text/event-stream",
                    Bytes::from("data: one\n\ndata: two\n\n".repeat(8)),
                    false,
                )
            } else {
                (
                    "application/octet-stream",
                    Bytes::from_static(b"pre-encoded bytes pre-encoded bytes pre-encoded"),
                    true,
                )
            };
            let mut builder = hyper::Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, ctype)
                .header(CONTENT_LENGTH, body.len().to_string());
            if pre_encoded {
                builder = builder.header(CONTENT_ENCODING, "gzip");
            }
            builder.body(Full::new(body)).unwrap()
        },
    ))
    .await
}

fn edge_yaml(backend_port: u16, payload_backend_port: u16) -> String {
    format!(
        r#"
routes:
  - name: api
    service: svc
    match: {{ path: {{ type: prefix, value: /api }} }}
    action: {{ type: proxy }}
    cors:
      allowed_origins: ["https://app.example.com"]
      allowed_headers: ["Authorization", "Content-Type"]
      expose_headers: ["X-Request-Id"]
      max_age_secs: 600
  - name: authcors
    service: svc
    match: {{ path: {{ type: prefix, value: /authcors }} }}
    action: {{ type: proxy }}
    auth_required: true
    cors:
      allowed_origins: ["https://app.example.com"]
  - name: wildcard
    service: svc
    match: {{ path: {{ type: prefix, value: /wild }} }}
    action: {{ type: proxy }}
    cors:
      allowed_origins: ["*"]
  - name: methodlimited
    service: svc
    match:
      path: {{ type: prefix, value: /methods }}
      methods: [GET, POST]
    action: {{ type: proxy }}
    cors:
      allowed_origins: ["*"]
  - name: nocors
    service: svc
    match: {{ path: {{ type: prefix, value: /plain }} }}
    action: {{ type: proxy }}
  - name: limited
    service: svc
    match: {{ path: {{ type: prefix, value: /limited }} }}
    action: {{ type: proxy }}
    limits:
      max_body_bytes: 16
      max_header_count: 8
      max_header_bytes: 4096
  - name: compress
    service: payloads
    match: {{ path: {{ type: prefix, value: /compress }} }}
    action: {{ type: proxy }}
    compression:
      algorithms: [gzip, zstd]
      min_size: 8
  - name: compress_small_ok
    service: payloads
    match: {{ path: {{ type: prefix, value: /compress-small }} }}
    action: {{ type: proxy }}
    compression:
      min_size: 0
      algorithms: [gzip]
  - name: compress_excl
    service: payloads
    match: {{ path: {{ type: prefix, value: /compress-excl }} }}
    action: {{ type: proxy }}
    compression:
      min_size: 0
      algorithms: [gzip]
      excluded_content_types: ["text/event-stream"]
services:
  - name: svc
    upstream: up
  - name: payloads
    upstream: payloads_up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {backend_port} }}]
  - name: payloads_up
    endpoints: [{{ address: 127.0.0.1, port: {payload_backend_port} }}]
"#
    )
}

fn preflight(path: &str, origin: &str, method: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri(path)
        .header(ORIGIN, origin)
        .header(ACCESS_CONTROL_REQUEST_METHOD, method)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn send(
    dp: &Arc<dwara_core::proxy::DataPlane>,
    req: Request<Full<Bytes>>,
) -> hyper::Response<dwara_core::proxy::ProxyBody> {
    dwara_core::proxy::handle(dp, ip(), req).await
}

fn h(v: Option<&hyper::header::HeaderValue>) -> String {
    v.and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn gunzip(data: &[u8]) -> String {
    let mut out = String::new();
    flate2::read::GzDecoder::new(data)
        .read_to_string(&mut out)
        .expect("valid gzip stream");
    out
}

// ---------------------------------------------------------------------------
// CORS: preflight short-circuit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preflight_is_answered_by_gateway_never_upstream_even_with_auth() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // The auth-requiring CORS route: a preflight must not be subject to
    // authn (browsers send preflights without credentials).
    let resp = send(
        &dp,
        preflight("/authcors/x", "https://app.example.com", "GET"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "preflight reached upstream"
    );

    // The plain CORS route: an allowed preflight answers with the policy.
    let resp = send(&dp, preflight("/api/x", "https://app.example.com", "POST")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com"
    );
    let methods = h(resp.headers().get(ACCESS_CONTROL_ALLOW_METHODS));
    assert!(methods.contains("POST"), "methods list: {methods}");
    assert!(methods.contains("GET"));
    assert!(methods.contains("OPTIONS"));
    assert_eq!(h(resp.headers().get(ACCESS_CONTROL_MAX_AGE)), "600");
    let vary = h(resp.headers().get(VARY));
    assert!(vary.to_lowercase().contains("origin"), "vary: {vary}");
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "preflight reached upstream"
    );
}

#[tokio::test]
async fn preflight_with_disallowed_request_header_fails_closed() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // Authorization is in allowed_headers, X-Custom is not: the whole
    // preflight fails (one disallowed header fails it) and the response
    // carries no CORS headers.
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/x")
            .header(ORIGIN, "https://app.example.com")
            .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .header("access-control-request-headers", "Authorization, X-Custom")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        "preflight with a disallowed header must not be answered as allowed"
    );
    let allow = h(resp.headers().get(ACCESS_CONTROL_ALLOW_HEADERS));
    assert!(
        allow.is_empty(),
        "no allow-headers on a failed preflight: {allow}"
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn preflight_disallowed_origin_or_method_short_circuits_without_cors_headers() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    let bad_origin = send(&dp, preflight("/api/x", "https://evil.example.net", "GET")).await;
    assert_eq!(bad_origin.status(), StatusCode::NO_CONTENT);
    assert!(bad_origin
        .headers()
        .get(ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
    assert_eq!(count.load(Ordering::SeqCst), 0);

    // TRACE is not in the default method set.
    let bad_method = send(&dp, preflight("/api/x", "https://app.example.com", "TRACE")).await;
    assert_eq!(bad_method.status(), StatusCode::NO_CONTENT);
    assert!(bad_method
        .headers()
        .get(ACCESS_CONTROL_ALLOW_METHODS)
        .is_none());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn plain_options_without_preflight_markers_proxies_normally() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // OPTIONS with Origin but NO Access-Control-Request-Method: a real
    // API request, proxied.
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/x")
            .header(ORIGIN, "https://app.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // OPTIONS with neither marker on a CORS-less route: proxied too.
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/plain/x")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn preflight_on_route_whose_methods_exclude_options_is_unrouted() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // Documented behavior: the method criterion applies before any CORS
    // handling; a preflight OPTIONS on a methods-restricted route that
    // does not list OPTIONS is a 404. Include OPTIONS in match.methods
    // on CORS routes.
    let resp = send(
        &dp,
        preflight("/methods/x", "https://app.example.com", "GET"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// CORS: actual responses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn allow_credentials_is_echoed_on_preflight_and_actual_responses() {
    let (port, count) = counter_backend().await;
    let yaml = format!(
        r#"
routes:
  - name: cred
    service: svc
    match: {{ path: {{ type: prefix, value: /cred }} }}
    action: {{ type: proxy }}
    cors:
      allowed_origins: ["https://app.example.com"]
      allow_credentials: true
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    );
    let dp = dataplane_from(&yaml);

    // Preflight: origin echoed specifically (never `*`) + credentials flag.
    let resp = send(&dp, preflight("/cred/x", "https://app.example.com", "GET")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com",
        "credentialed policy must echo the origin, never wildcard"
    );
    assert_eq!(
        h(resp.headers().get("access-control-allow-credentials")),
        "true"
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);

    // Actual response: same two guarantees.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/cred/x")
            .header(ORIGIN, "https://app.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com"
    );
    assert_eq!(
        h(resp.headers().get("access-control-allow-credentials")),
        "true"
    );
}

#[tokio::test]
async fn preflight_markers_on_a_route_without_cors_proxy_upstream() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // A full preflight shape on a route with no cors block: the gateway
    // has no policy to answer with, so the request is a normal proxy
    // (the upstream decides what to do with OPTIONS).
    let resp = send(&dp, preflight("/plain/x", "https://app.example.com", "GET")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        "no cors policy: no gateway-injected CORS headers"
    );
}

#[tokio::test]
async fn actual_responses_carry_policy_headers_only_for_allowed_origins() {
    let (port, _) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    let resp = send(
        &dp,
        Request::builder()
            .uri("/api/x")
            .header(ORIGIN, "https://app.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com"
    );
    assert!(resp
        .headers()
        .get("access-control-expose-headers")
        .is_some());
    let vary = h(resp.headers().get(VARY));
    assert!(vary.to_lowercase().contains("origin"), "vary: {vary}");

    // Disallowed origin: response passes through with no CORS headers.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api/x")
            .header(ORIGIN, "https://evil.example.net")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    // No Origin at all: not a CORS request, no CORS headers.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api/x")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    // Wildcard policy answers `*` for any origin.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/wild/x")
            .header(ORIGIN, "https://anywhere.example.org")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)), "*");
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gzip_compression_round_trip_with_headers() {
    let (port, _) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress/big")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    assert!(
        resp.headers().get(CONTENT_LENGTH).is_none(),
        "length must not survive compression"
    );
    let vary = h(resp.headers().get(VARY));
    assert!(
        vary.to_lowercase().contains("accept-encoding"),
        "vary: {vary}"
    );
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        gunzip(&body),
        "dwara compression payload line\n".repeat(160),
        "decompressed body must round-trip"
    );
}

#[tokio::test]
async fn compression_negotiates_policy_algorithm_preference_and_q_values() {
    let (port, _) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    let get = |accept: Option<&str>| {
        let mut b = Request::builder().uri("/compress/big");
        if let Some(ae) = accept {
            b = b.header("accept-encoding", ae);
        }
        send(&dp, b.body(Full::new(Bytes::new())).unwrap())
    };

    // Policy order [gzip, zstd]: both acceptable -> gzip.
    let resp = get(Some("gzip, zstd")).await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    let _ = body_of(resp).await;

    // Only zstd acceptable -> zstd.
    let resp = get(Some("zstd")).await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "zstd");
    let (_, body) = body_of(resp).await;
    assert_eq!(
        zstd::decode_all(&body[..]).expect("valid zstd stream"),
        Bytes::from("dwara compression payload line\n".repeat(160))
    );

    // brotli is NOT in this route's policy: no compression.
    let resp = get(Some("br")).await;
    assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    let vary = h(resp.headers().get(VARY));
    assert!(vary.to_lowercase().contains("accept-encoding"));
    let _ = body_of(resp).await;

    // q=0 excludes a coding even when listed.
    let resp = get(Some("gzip;q=0, zstd")).await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "zstd");
    let _ = body_of(resp).await;

    // No Accept-Encoding at all: identity.
    let resp = get(None).await;
    assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    let _ = body_of(resp).await;
}

#[tokio::test]
async fn accept_encoding_wildcard_selects_first_policy_algorithm() {
    let (port, _) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // `*` accepts any policy algorithm: the policy's own order wins
    // (gzip first on the /compress route).
    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress/big")
            .header("accept-encoding", "*")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        gunzip(&body),
        "dwara compression payload line\n".repeat(160)
    );

    // A wildcard does not rescue an algorithm the policy omits: `br`
    // stays out and gzip still serves.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress/big")
            .header("accept-encoding", "br, *")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    let _ = body_of(resp).await;
}

#[tokio::test]
async fn bodyless_status_responses_are_never_compressed() {
    // 204/304 (and 1xx/101) have no body to encode: they pass through
    // regardless of min_size, keeping validators (ETag) intact.
    let backend_port = spawn_backend_full(Arc::new(
        move |req: hyper::Request<hyper::body::Incoming>| {
            let status = if req.uri().path().ends_with("/notmod") {
                StatusCode::NOT_MODIFIED
            } else {
                StatusCode::NO_CONTENT
            };
            hyper::Response::builder()
                .status(status)
                .header("etag", "\"v1\"")
                .body(Full::new(Bytes::new()))
                .unwrap()
        },
    ))
    .await;
    let yaml = format!(
        r#"
routes:
  - name: compress
    service: payloads
    match: {{ path: {{ type: prefix, value: /compress }} }}
    action: {{ type: proxy }}
    compression:
      min_size: 0
      algorithms: [gzip]
services:
  - name: payloads
    upstream: payloads_up
upstreams:
  - name: payloads_up
    endpoints: [{{ address: 127.0.0.1, port: {backend_port} }}]
"#
    );
    let dp = dataplane_from(&yaml);

    for path in ["/compress/notmod", "/compress/nocontent"] {
        let resp = send(
            &dp,
            Request::builder()
                .uri(path)
                .header("accept-encoding", "gzip")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        let expected = if path.ends_with("/notmod") {
            StatusCode::NOT_MODIFIED
        } else {
            StatusCode::NO_CONTENT
        };
        assert_eq!(resp.status(), expected, "path: {path}");
        assert!(
            resp.headers().get(CONTENT_ENCODING).is_none(),
            "bodyless status must not be compressed: {path}"
        );
        assert_eq!(h(resp.headers().get("etag")), "\"v1\"", "path: {path}");
        let vary = h(resp.headers().get(VARY));
        assert!(
            vary.to_lowercase().contains("accept-encoding"),
            "identity passthrough still varies: {path}, vary: {vary}"
        );
        let _ = body_of(resp).await;
    }
}

#[tokio::test]
async fn compression_brotli_round_trip() {
    let payloads = payload_backend().await;
    let yaml = r#"
routes:
  - name: br
    service: payloads
    match: { path: { type: prefix, value: /compress } }
    action: { type: proxy }
    compression:
      min_size: 0
      algorithms: [brotli]
services:
  - name: payloads
    upstream: payloads_up
upstreams:
  - name: payloads_up
    endpoints: [{ address: 127.0.0.1, port: PORT }]
"#
    .replace("PORT", &payloads.to_string());
    let dp = dataplane_from(&yaml);

    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress/big")
            .header("accept-encoding", "br")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "br");
    let (_, body) = body_of(resp).await;
    let mut decompressed = Vec::new();
    let mut cursor = std::io::Cursor::new(&body[..]);
    brotli::BrotliDecompress(&mut cursor, &mut decompressed).expect("valid brotli stream");
    assert_eq!(
        Bytes::from(decompressed),
        Bytes::from("dwara compression payload line\n".repeat(160))
    );
}

#[tokio::test]
async fn compression_respects_min_size_and_content_type_policy() {
    let (port, _) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // 4-byte body below the route's min_size of 8: uncompressed, Vary
    // still present (cache correctness).
    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress/small")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    assert!(!h(resp.headers().get(CONTENT_LENGTH)).is_empty());
    let vary = h(resp.headers().get(VARY));
    assert!(vary.to_lowercase().contains("accept-encoding"));
    let _ = body_of(resp).await;

    // Same body under a min_size:0 route: compressed.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress-small/small")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    let _ = body_of(resp).await;

    // Excluded content type: SSE passes through.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress-excl/sse")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    let _ = body_of(resp).await;

    // Already-encoded upstream responses are never re-compressed.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/compress/pre-encoded")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        h(resp.headers().get(CONTENT_ENCODING)),
        "gzip",
        "upstream encoding passes through"
    );
    let (_, body) = body_of(resp).await;
    assert_eq!(body.len(), 47, "passthrough body is untouched");
}

#[tokio::test]
async fn compression_and_cors_compose_on_one_route() {
    let payloads = payload_backend().await;
    let yaml = r#"
routes:
  - name: both
    service: payloads
    match: { path: { type: prefix, value: /both } }
    action: { type: proxy }
    cors:
      allowed_origins: ["https://app.example.com"]
    compression:
      min_size: 0
      algorithms: [gzip]
services:
  - name: payloads
    upstream: payloads_up
upstreams:
  - name: payloads_up
    endpoints: [{ address: 127.0.0.1, port: PORT }]
"#
    .replace("PORT", &payloads.to_string());
    let dp = dataplane_from(&yaml);

    let resp = send(
        &dp,
        Request::builder()
            .uri("/both/big")
            .header(ORIGIN, "https://app.example.com")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com"
    );
    let vary = h(resp.headers().get(VARY));
    assert!(vary.to_lowercase().contains("origin"));
    assert!(
        vary.to_lowercase().contains("accept-encoding"),
        "merged Vary: {vary}"
    );
    let (_, body) = body_of(resp).await;
    assert_eq!(
        gunzip(&body),
        "dwara compression payload line\n".repeat(160)
    );
}

#[tokio::test]
async fn gateway_respond_and_redirect_bodies_respect_min_size() {
    // Respond/redirect bodies carry no Content-Length header; their
    // exact size hint must drive `min_size` so an empty 302 or a tiny
    // static body is never wrapped in a ~23-byte gzip container. (The
    // configured body is newline-free on purpose: YAML double-quoted
    // scalars line-fold literal newlines into spaces.)
    let (port, _) = counter_backend().await;
    let big_body = "respond payload line for compression ".repeat(40);
    let yaml = format!(
        r#"
routes:
  - name: small
    service: svc
    match: {{ path: {{ type: prefix, value: /small }} }}
    action: {{ type: respond, status: 200, body: "tiny body" }}
    compression: {{ min_size: 1024, algorithms: [gzip] }}
  - name: big
    service: svc
    match: {{ path: {{ type: prefix, value: /big }} }}
    action: {{ type: respond, status: 200, body: "{big_body}" }}
    compression: {{ min_size: 1024, algorithms: [gzip] }}
  - name: jump
    service: svc
    match: {{ path: {{ type: prefix, value: /jump }} }}
    action: {{ type: redirect, status: 302, path: /landed }}
    compression: {{ min_size: 1024, algorithms: [gzip] }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    );
    let dp = dataplane_from(&yaml);

    // Below min_size: uncompressed, verbatim, still varying.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/small/x")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    let vary = h(resp.headers().get(VARY));
    assert!(
        vary.to_lowercase().contains("accept-encoding"),
        "skipped candidate still varies: {vary}"
    );
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"tiny body", "small body passes through");

    // Above min_size: compressed, decompresses to the configured body.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/big/x")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    let (_, body) = body_of(resp).await;
    assert_eq!(gunzip(&body), big_body, "respond body round-trips");

    // Redirect's EMPTY body is below any min_size: never compressed.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/jump/x")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(
        resp.headers().get(CONTENT_ENCODING).is_none(),
        "empty redirect body must not be compressed"
    );
    let _ = body_of(resp).await;
}

#[tokio::test]
async fn upstream_vary_lines_fold_into_the_merged_vary() {
    // Two legal `Vary` field lines from the upstream must BOTH survive
    // the gateway's token merge, as one folded line — not be replaced
    // by a merge that only read the first.
    let backend = spawn_backend_full(Arc::new(move |_req| {
        let body = Bytes::from("vary fold payload line\n".repeat(128));
        hyper::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, body.len().to_string())
            .header(VARY, "Accept-Language")
            .header(VARY, "Cookie")
            .body(Full::new(body))
            .unwrap()
    }))
    .await;
    let yaml = format!(
        r#"
routes:
  - name: fold
    service: svc
    match: {{ path: {{ type: prefix, value: /fold }} }}
    action: {{ type: proxy }}
    compression: {{ min_size: 8, algorithms: [gzip] }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {backend} }}]
"#
    );
    let dp = dataplane_from(&yaml);

    // Compressed path: the merge runs inside wrap_response.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/fold/x")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    let lines: Vec<String> = resp
        .headers()
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 1, "folded into one line: {lines:?}");
    let lower = lines[0].to_lowercase();
    for token in ["accept-language", "cookie", "accept-encoding"] {
        assert!(lower.contains(token), "folded vary: {}", lines[0]);
    }
    let _ = body_of(resp).await;

    // Identity path (no Accept-Encoding): the skip branch merges too.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/fold/x")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let lines: Vec<String> = resp
        .headers()
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    assert_eq!(lines.len(), 1, "identity fold: {lines:?}");
    assert!(lines[0].to_lowercase().contains("cookie"));
    let _ = body_of(resp).await;
}

#[tokio::test]
async fn mixed_case_config_origin_matches_normalized_request_origin() {
    // Config entries are normalized at snapshot-compile time; the
    // compiled set must still match a differently-cased request origin
    // (and echo the request's spelling, not the config's).
    let (port, _) = counter_backend().await;
    let yaml = format!(
        r#"
routes:
  - name: case
    service: svc
    match: {{ path: {{ type: prefix, value: /case }} }}
    action: {{ type: proxy }}
    cors:
      allowed_origins: ["https://APP.Example.COM:443"]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    );
    let dp = dataplane_from(&yaml);

    let resp = send(
        &dp,
        Request::builder()
            .uri("/case/x")
            .header(ORIGIN, "https://app.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com",
        "the request origin is echoed"
    );
    let _ = body_of(resp).await;
}

// ---------------------------------------------------------------------------
// Trailers on compressed streams
// ---------------------------------------------------------------------------

/// Response body that streams two data frames and then a trailers
/// frame: the h2 upstream shape whose compressed ordering the test
/// below pins. Trailers only reach the gateway over h2 (hyper's h1
/// client discards them), so this is the one end-to-end shape that
/// exercises `CompressedBody`'s trailers ordering.
struct TraileredBody {
    step: u8,
}

impl hyper::body::Body for TraileredBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        this.step += 1;
        match this.step {
            1 => Poll::Ready(Some(Ok(Frame::data(Bytes::from(
                "trailered payload line one\n".repeat(40),
            ))))),
            2 => Poll::Ready(Some(Ok(Frame::data(Bytes::from(
                "trailered payload line two\n".repeat(40),
            ))))),
            3 => {
                let mut trailers = hyper::HeaderMap::new();
                trailers.insert(
                    "x-checksum",
                    hyper::header::HeaderValue::from_static("c0ffee"),
                );
                Poll::Ready(Some(Ok(Frame::trailers(trailers))))
            }
            _ => Poll::Ready(None),
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        // Unknown length: the response is a streaming compression
        // candidate with no Content-Length to gate on.
        hyper::body::SizeHint::default()
    }
}

/// An h2-over-TLS upstream (rcgen self-signed CA, ALPN h2) whose every
/// response is a [`TraileredBody`]. Returns (port, CA PEM path for the
/// upstream's `trusted_ca_file`). The tempdir holding the CA bundle is
/// deliberately leaked: the spawned listener outlives the helper frame
/// and the file must remain readable for the gateway's whole lifetime.
async fn spawn_trailers_h2_upstream() -> (u16, String) {
    dwara_core::tls::install_aws_lc_rs_provider();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "dwara-test-trailers-ca");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    let ca_path = ca_path.display().to_string();
    std::mem::forget(dir);

    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), ca.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            )),
        )
        .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    |_req: hyper::Request<hyper::body::Incoming>| async {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain")
                                .body(TraileredBody { step: 0 })
                                .unwrap(),
                        )
                    },
                );
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                .await;
            });
        }
    });
    (port, ca_path)
}

#[tokio::test]
async fn compressed_stream_emits_codec_tail_before_trailers() {
    // h2 upstream (trailers) -> gateway compression -> h2c client: the
    // gzip tail bytes must be emitted as DATA frames BEFORE the
    // trailers frame. Data after trailers is an h2 framing violation;
    // on the old ordering the client's stream tears (or the gzip
    // container truncates) and this test fails on either symptom.
    let (upstream_port, ca_path) = spawn_trailers_h2_upstream().await;
    let yaml = format!(
        r#"
routes:
  - name: trailers
    service: svc
    match: {{ path: {{ type: prefix, value: /tl }} }}
    action: {{ type: proxy }}
    compression: {{ min_size: 1, algorithms: [gzip] }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    protocol: http2
    trusted_ca_file: "{ca_path}"
    endpoints: [{{ address: localhost, port: {upstream_port} }}]
"#
    );
    let dp = dataplane_from(&yaml);
    let gateway_port = spawn_gateway(dp).await;

    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .build_http::<Full<Bytes>>();
    let resp = client
        .request(
            Request::builder()
                .uri(uri(gateway_port, "/tl/x"))
                .header("accept-encoding", "gzip")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .expect("h2c request through the gateway");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    let collected = resp.into_body().collect().await.expect("stream completes");
    assert_eq!(
        collected
            .trailers()
            .and_then(|t| t.get("x-checksum"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        "c0ffee",
        "upstream trailers survive compression and arrive after the body"
    );
    let body = collected.to_bytes();
    assert_eq!(
        gunzip(&body),
        format!(
            "{}{}",
            "trailered payload line one\n".repeat(40),
            "trailered payload line two\n".repeat(40),
        ),
        "gzip container is complete: the codec tail preceded the trailers"
    );
}

// ---------------------------------------------------------------------------
// Request limits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn declared_body_over_limit_is_413_before_upstream_contact() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    let resp = send(
        &dp,
        Request::builder()
            .method(Method::POST)
            .uri("/limited/upload")
            .header(CONTENT_LENGTH, "32")
            .body(Full::new(Bytes::from(vec![b'x'; 32])))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let (_, body) = body_of(resp).await;
    assert_eq!(envelope_code(&body), "request_body_too_large");
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "over-limit request reached upstream"
    );

    // At the cap exactly: passes.
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::POST)
            .uri("/limited/upload")
            .header(CONTENT_LENGTH, "16")
            .body(Full::new(Bytes::from(vec![b'x'; 16])))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn header_limits_reject_with_431() {
    let (port, count) = counter_backend().await;
    let payloads = payload_backend().await;
    let dp = dataplane_from(&edge_yaml(port, payloads));

    // Count limit: 8 allowed; send 9 headers beyond the standard set.
    let mut builder = Request::builder().uri("/limited/x");
    for i in 0..9 {
        builder = builder.header(format!("x-extra-{i}"), "v");
    }
    let resp = send(&dp, builder.body(Full::new(Bytes::new())).unwrap()).await;
    assert_eq!(resp.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    let (_, body) = body_of(resp).await;
    assert_eq!(envelope_code(&body), "request_headers_too_large");
    assert_eq!(count.load(Ordering::SeqCst), 0);

    // Byte-size limit (route allows 4096 total): one giant header value.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/limited/x")
            .header("x-big", "y".repeat(8192))
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    let (_, body) = body_of(resp).await;
    assert_eq!(envelope_code(&body), "request_headers_too_large");
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

/// A body of unknown length (no size hint) yielding fixed-size frames —
/// chunked framing on the wire, the shape the streaming limit guards.
struct ChunkedBody {
    remaining: usize,
}

impl hyper::body::Body for ChunkedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.remaining > 0 {
            this.remaining -= 1;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'z'; 8])))))
        } else {
            Poll::Ready(None)
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::default()
    }
}

#[tokio::test]
async fn streaming_body_over_limit_aborts_with_413() {
    // A backend that reads the whole body before answering.
    let reader_port =
        spawn_backend_async(|req: hyper::Request<hyper::body::Incoming>| async move {
            use http_body_util::BodyExt as _;
            let _ = req.into_body().collect().await;
            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::new())))
        })
        .await;
    let yaml = format!(
        r#"
routes:
  - name: limited
    service: svc
    match: {{ path: {{ type: prefix, value: /limited }} }}
    action: {{ type: proxy }}
    limits:
      max_body_bytes: 16
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {reader_port} }}]
"#
    );
    let dp = dataplane_from(&yaml);
    let gateway_port = spawn_gateway(dp).await;

    // A chunked (no Content-Length) body of 5 frames x 8 bytes over a
    // 16-byte cap: the counting wrapper trips on frame 3 and the client
    // sees 413 (or, per the documented abort semantics, a transport
    // error if its side already gave up on the connection).
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<ChunkedBody>();
    let outcome = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gateway_port, "/limited/upload"))
                .body(ChunkedBody { remaining: 5 })
                .unwrap(),
        )
        .await;
    match outcome {
        Ok(resp) => {
            assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(_) => {
            // Documented: the gateway tore the stream mid-upload; the
            // client may see a transport error instead of the 413.
        }
    }
}
