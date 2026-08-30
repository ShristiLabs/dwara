//! WAF-lite heuristic filtering (DW-051), end to end.
//!
//! Every test spawns a real gateway and a real backend: the gateway
//! inspects the request for SQLi/XSS/path-traversal signatures and
//! either blocks (403) or allows (200 from the backend). Dry-run mode
//! logs and allows. Filter selection, body inspection, body size
//! limits, per-route isolation, and a false-positive battery are all
//! covered.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode};

mod support;

use support::{body_of, h1_client, spawn_backend, spawn_gateway, uri};

/// Backend that echoes "ok" for every request (the WAF should block
/// before the backend is reached when a match is found).
async fn ok_backend() -> u16 {
    spawn_backend(
        |_n, _method, path, _body| {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from(format!("ok:{path}"))))
                .unwrap()
        },
        std::time::Duration::ZERO,
    )
    .await
    .0
}

/// Gateway YAML with WAF enabled on the `/api` route.
fn waf_yaml(backend_port: u16, waf_block: &str) -> String {
    format!(
        "routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         {waf_block}\n\
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

const WAF_ENABLED: &str = "  waf:\n    enabled: true";
const WAF_DRY_RUN: &str = "  waf:\n    enabled: true\n    dry_run: true";
const WAF_SQLI_ONLY: &str = "  waf:\n    enabled: true\n    filters: [sqli]";
const WAF_NO_BODY: &str = "  waf:\n    enabled: true\n    max_body_inspect_bytes: 0";
const WAF_SMALL_BODY: &str = "  waf:\n    enabled: true\n    max_body_inspect_bytes: 10";

/// Second route without WAF (per-route isolation test).
fn waf_yaml_two_routes(backend_port: u16) -> String {
    format!(
        "routes:\n\
         - name: protected\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 waf:\n\
         \x20   enabled: true\n\
         - name: open\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /public\n\
         \x20 action:\n\
         \x20   type: proxy\n\
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

async fn get(port: u16, path: &str) -> (StatusCode, String) {
    let client = h1_client();
    let resp = client.get(uri(port, path)).await.unwrap();
    let (status, bytes) = body_of(resp).await;
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn post_json(port: u16, path: &str, body: &str) -> (StatusCode, String) {
    let client = h1_client();
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri(port, path))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let (status, bytes) = body_of(resp).await;
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn post_json_with_header(
    port: u16,
    path: &str,
    body: &str,
    header_name: &str,
    header_val: &str,
) -> (StatusCode, String) {
    let client = h1_client();
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri(port, path))
        .header("content-type", "application/json")
        .header(header_name, header_val)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let (status, bytes) = body_of(resp).await;
    (status, String::from_utf8_lossy(&bytes).to_string())
}

// ---------------------------------------------------------------------------
// 1. SQLi detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sqli_in_query_is_blocked() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let (status, body) = get(port, "/api/users?id=1'%20OR%201=1--").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("waf_blocked"));
}

// ---------------------------------------------------------------------------
// 2. XSS detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn xss_in_query_is_blocked() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let (status, body) = get(port, "/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("waf_blocked"));
}

// ---------------------------------------------------------------------------
// 3. Path traversal detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn path_traversal_in_query_is_blocked() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let (status, body) = get(port, "/api?file=../../etc/passwd").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("waf_blocked"));
}

// ---------------------------------------------------------------------------
// 4. Dry-run mode (request passes through, match is logged)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dry_run_allows_request() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_DRY_RUN));
    let port = spawn_gateway(dp).await;
    let (status, body) = get(port, "/api/users?id=1'%20OR%201=1--").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("ok:"));
}

// ---------------------------------------------------------------------------
// 5. Filter selection (only sqli, XSS payload passes)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn filter_selection_sqli_only_xss_passes() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_SQLI_ONLY));
    let port = spawn_gateway(dp).await;
    let (status, body) = get(port, "/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("ok:"));
}

// ---------------------------------------------------------------------------
// 6. Body inspection (JSON body with SQLi pattern)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_inspection_sqli_blocked() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let (status, body) = post_json(port, "/api/users", r#"{"id":"1' OR 1=1--"}"#).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("waf_blocked"));
}

// ---------------------------------------------------------------------------
// 7. Body size limit (body larger than max_body_inspect_bytes)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_size_limit_skips_inspection() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_SMALL_BODY));
    let port = spawn_gateway(dp).await;
    // Build a body where the SQLi pattern is beyond the 10-byte cap.
    // The first 10 bytes are "AAAAAAAAAA" (clean), then the SQLi payload.
    let clean_prefix = "A".repeat(20);
    let body = format!(r#"{{"data":"{}' OR 1=1--"}}"#, clean_prefix);
    let (status, _body) = post_json(port, "/api/data", &body).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// 8. Disabled WAF (no waf block)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabled_waf_no_inspection() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, ""));
    let port = spawn_gateway(dp).await;
    let (status, body) = get(port, "/api/users?id=1'%20OR%201=1--").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("ok:"));
}

// ---------------------------------------------------------------------------
// 9. False positive battery (20+ legitimate request patterns)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_false_positives_on_legitimate_requests() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let legit_paths: &[&str] = &[
        "/api/users?page=1&limit=20",
        "/api/users/123?fields=name,email",
        "/api/search?q=hello+world&sort=relevance",
        "/api/products?category=electronics&min_price=10&max_price=500",
        "/api/orders?status=pending&from=2024-01-01&to=2024-12-31",
        "/api/profile?user=john_doe",
        "/api/blog/posts?tag=rust&tag=programming",
        "/api/geo?lat=37.7749&lng=-122.4194",
        "/api/translate?text=Hello&from=en&to=es",
        "/api/upload?filename=report.pdf&size=1024",
        "/api/calc?expr=2%2B2*3-1",
        "/api/lookup?key=abc123def456",
        "/api/config?env=production&debug=false",
        "/api/health?check=all",
        "/api/metrics?interval=60s&format=prometheus",
        "/api/v2/users?expand=profile,settings",
        "/api/v1/items?cursor=eyJpZCI6MTIzfQ&limit=50",
        "/api/reports?type=summary&year=2024",
        "/api/notifications?unread=true&limit=10",
        "/api/cart?item_id=42&quantity=3",
        "/api/checkout?payment_method=card&currency=usd",
        "/api/feedback?rating=5&comment=Great+service",
    ];
    for path in legit_paths {
        let (status, body) = get(port, path).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "false positive on {path}: body={body}"
        );
    }
}

// ---------------------------------------------------------------------------
// 10. Header inspection (SQLi in User-Agent)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn header_inspection_sqli_in_user_agent_blocked() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let (status, body) = post_json_with_header(
        port,
        "/api/data",
        r#"{"x":1}"#,
        "user-agent",
        "Bot' OR 1=1--",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("waf_blocked"));
}

// ---------------------------------------------------------------------------
// 11. Per-route isolation (route A has WAF, route B doesn't)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn per_route_isolation() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml_two_routes(backend));
    let port = spawn_gateway(dp).await;
    // Malicious request to protected route -> blocked.
    let (status_protected, body_protected) = get(port, "/api?file=../../etc/passwd").await;
    assert_eq!(status_protected, StatusCode::FORBIDDEN);
    assert!(body_protected.contains("waf_blocked"));
    // Same malicious request to open route -> passes.
    let (status_open, body_open) = get(port, "/public?file=../../etc/passwd").await;
    assert_eq!(status_open, StatusCode::OK);
    assert!(body_open.starts_with("ok:"));
}

// ---------------------------------------------------------------------------
// Body inspection disabled (max_body_inspect_bytes: 0)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_inspection_disabled_when_cap_zero() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_NO_BODY));
    let port = spawn_gateway(dp).await;
    let (status, body) = post_json(port, "/api/users", r#"{"id":"1' OR 1=1--"}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("ok:"));
}

// ---------------------------------------------------------------------------
// Path traversal in the path itself (not query)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn path_traversal_in_path_blocked() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let (status, body) = get(port, "/api/../../etc/passwd").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("waf_blocked"));
}

// ---------------------------------------------------------------------------
// Legitimate POST body (no false positive)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn legitimate_post_body_passes() {
    let backend = ok_backend().await;
    let dp = support::dataplane_from(&waf_yaml(backend, WAF_ENABLED));
    let port = spawn_gateway(dp).await;
    let (status, _body) = post_json(
        port,
        "/api/users",
        r#"{"name":"John","email":"john@example.com"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
