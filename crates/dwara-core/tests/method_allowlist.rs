//! Per-route method allowlist integration tests (DW-030).
//!
//! Pins the 405 + Allow contract and its placement in the request path:
//! enforced after route resolution and the maintenance 503, before the
//! route limits and CORS preflight short-circuit and authentication;
//! CORS preflights are exempt (the DW-041 maintenance carve-out's twin);
//! HEAD is never implicitly granted by GET; the 405 carries the security
//! headers (and, on CORS routes, the policy's actual-response CORS
//! headers, the maintenance-503 precedent).

mod support;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode};
use support::*;

/// Gateway YAML: one `/api` route to one upstream with an extra route
/// block spliced in (`route_extra`) and gateway-level extras prepended.
fn allowlist_yaml(route_extra: &str, backend_port: u16) -> String {
    format!(
        "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n{route_extra}\
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

#[tokio::test]
async fn method_outside_the_allowlist_is_405_with_allow() {
    let (port, _count) = spawn_backend(
        |_n, method, _path, _body| panic!("upstream must not see a refused method: {method}"),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dp = dataplane_from(&allowlist_yaml("  methods:\n    - GET\n    - POST\n", port));
    let gw = spawn_gateway(dp).await;

    let resp = h1_client()
        .request(
            Request::delete(uri(gw, "/api/thing"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(envelope_code(&body), "method_not_allowed");
    let _ = _count;

    // A second shape on the same route: PUT.
    let resp = h1_client()
        .request(
            Request::put(uri(gw, "/api/thing"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body) = body_of(resp).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn allow_header_lists_the_configured_methods_verbatim() {
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new("ok".into())),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dp = dataplane_from(&allowlist_yaml("  methods:\n    - GET\n    - POST\n", port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::delete(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let allow = resp
        .headers()
        .get(hyper::header::ALLOW)
        .and_then(|v| v.to_str().ok())
        .expect("Allow header present")
        .to_string();
    assert_eq!(allow, "GET, POST");
    let _ = body_of(resp).await;
}

#[tokio::test]
async fn methods_inside_the_allowlist_proxy_normally() {
    let (port, count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new("ok".into())),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dp = dataplane_from(&allowlist_yaml("  methods:\n    - GET\n", port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::get(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn absent_allowlist_leaves_every_method_untouched() {
    // The additive default: no methods list, a DELETE proxies exactly as
    // pre-DW-030.
    let (port, count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new("ok".into())),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dp = dataplane_from(&allowlist_yaml("", port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::delete(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn head_is_not_implicitly_granted_by_get() {
    let (port, count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new("ok".into())),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dp = dataplane_from(&allowlist_yaml("  methods:\n    - GET\n", port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::head(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the refused HEAD never reached the upstream"
    );
    // Listing HEAD alongside GET admits it.
    let dp = dataplane_from(&allowlist_yaml("  methods:\n    - GET\n    - HEAD\n", port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::head(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn method_matching_is_case_insensitive() {
    // Configured lowercase "get" matches a canonical GET request (the
    // match.methods comparison semantics).
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new("ok".into())),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dp = dataplane_from(&allowlist_yaml("  methods:\n    - get\n", port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::get(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn cors_preflight_is_exempt_from_the_allowlist() {
    // The guardrail case: a preflight OPTIONS on a CORS route whose
    // allowlist names only GET must answer the CORS 204, never 405 —
    // the preflight asks about the GATEWAY's cross-origin policy, not
    // the resource (the DW-041 maintenance carve-out's twin).
    let (port, _count) = spawn_backend(
        |_n, method, _p, _b| panic!("preflight must be answered by the gateway: {method}"),
        std::time::Duration::from_millis(0),
    )
    .await;
    let route_extra =
        "  methods:\n    - GET\n  cors:\n    allowed_origins:\n      - https://example.com\n";
    let dp = dataplane_from(&allowlist_yaml(route_extra, port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(uri(gw, "/api/x"))
                .header("Origin", "https://example.com")
                .header("Access-Control-Request-Method", "GET")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn non_preflight_options_without_cors_markers_still_405s() {
    // An OPTIONS WITHOUT the preflight markers is a resource request:
    // the allowlist governs it (no cors block on this route at all).
    let (port, _count) = spawn_backend(
        |_n, method, _p, _b| panic!("upstream must not see bare OPTIONS: {method}"),
        std::time::Duration::from_millis(0),
    )
    .await;
    let dp = dataplane_from(&allowlist_yaml("  methods:\n    - GET\n", port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::options(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn cors_actual_headers_decorate_the_405_for_browser_readability() {
    // The maintenance-503 precedent: a cross-origin ACTUAL request must
    // be able to read the 405 envelope, so the policy's actual-response
    // CORS headers ride on it.
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new("ok".into())),
        std::time::Duration::from_millis(0),
    )
    .await;
    let route_extra =
        "  methods:\n    - GET\n  cors:\n    allowed_origins:\n      - https://example.com\n";
    let dp = dataplane_from(&allowlist_yaml(route_extra, port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::DELETE)
                .uri(uri(gw, "/api/x"))
                .header("Origin", "https://example.com")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(acao.as_deref(), Some("https://example.com"));
}

#[tokio::test]
async fn the_405_carries_the_routes_security_headers() {
    // DW-028: every route-matched response including short-circuits.
    let (port, _count) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new("ok".into())),
        std::time::Duration::from_millis(0),
    )
    .await;
    let route_extra = "  methods:\n    - GET\n  security_headers:\n    nosniff: true\n";
    let dp = dataplane_from(&allowlist_yaml(route_extra, port));
    let gw = spawn_gateway(dp).await;
    let resp = h1_client()
        .request(
            Request::delete(uri(gw, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let nosniff = resp
        .headers()
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (status, _) = body_of(resp).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(nosniff.as_deref(), Some("nosniff"));
}
