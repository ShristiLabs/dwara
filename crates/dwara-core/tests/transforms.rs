//! Request/response transforms and security headers (DW-028), end to
//! end through the real dataplane. The grammar-level behavior (pointer
//! parsing, op ordering, encoding) is pinned in `tests/unit/transforms.rs`;
//! this suite pins the PIPELINE: what the upstream receives, what the
//! client receives, the fail-closed statuses, and the streaming
//! guarantee (a route whose transforms touch no body forwards streams
//! byte-exactly; only a JSON body transform buffers).

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Request, Response, StatusCode};

use support::{body_of, dataplane_from, envelope_code};

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// A backend that echoes what it received as a JSON document:
/// method, path+query, headers, and the raw body text — the upstream's
/// exact view of the transformed request.
async fn echo_backend_async() -> u16 {
    support::spawn_backend_async(move |req: Request<hyper::body::Incoming>| async move {
        use http_body_util::BodyExt;
        let (parts, body) = req.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let mut headers = serde_json::Map::new();
        for (k, v) in parts.headers.iter() {
            let value = v.to_str().unwrap_or("<binary>");
            headers
                .entry(k.as_str().to_string())
                .and_modify(|existing: &mut serde_json::Value| {
                    let joined = format!("{}, {value}", existing.as_str().unwrap_or("<binary>"));
                    *existing = serde_json::Value::String(joined);
                })
                .or_insert_with(|| serde_json::Value::String(value.to_string()));
        }
        let doc = serde_json::json!({
            "method": parts.method.as_str(),
            "uri": parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(""),
            "headers": headers,
            "body": String::from_utf8_lossy(&bytes),
            "declared_len": parts.headers.get("content-length")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string()),
        });
        Ok(Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(doc.to_string())))
            .unwrap())
    })
    .await
}

/// Gateway YAML with one prefix route carrying `route_extra` (indented
/// two spaces per YAML level).
fn yaml(backend_port: u16, route_extra: &str) -> String {
    format!(
        r#"
routes:
  - name: t
    service: svc
    match:
      path: {{ type: prefix, value: /api }}
    action: {{ type: proxy }}
{route_extra}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {backend_port} }}]
"#
    )
}

async fn send(
    dp: &Arc<dwara_core::proxy::DataPlane>,
    req: Request<Full<Bytes>>,
) -> hyper::Response<dwara_core::proxy::ProxyBody> {
    dwara_core::proxy::handle(dp, ip(), req).await
}

#[tokio::test]
async fn request_header_transforms_shape_the_forwarded_request() {
    let port = echo_backend_async().await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      request:
        headers:
          set:
            x-gateway: dwara
          add:
            x-tags: edge
          remove:
            - x-client-secret
          rename:
            x-legacy-id: x-request-ref"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .header("x-client-secret", "s3cret")
            .header("x-legacy-id", "abc")
            .header("x-tags", "orig")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, body) = body_of(resp).await;
    let view: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let headers = &view["headers"];
    assert_eq!(headers["x-gateway"], "dwara");
    assert_eq!(headers["x-request-ref"], "abc");
    // add appended after the client's own value
    assert_eq!(headers["x-tags"], "orig, edge");
    // removed upstream-side; the client did send it
    assert!(headers.get("x-client-secret").is_none());
    assert!(headers.get("x-legacy-id").is_none());
}

#[tokio::test]
async fn request_query_transforms_reach_the_upstream_after_route_matching() {
    let port = echo_backend_async().await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      request:
        query:
          set:
            region: us-east
          add:
            source: gw
          remove:
            - debug
          rename:
            uid: user_id"#,
    ));
    // Route matching saw the ORIGINAL query: ?debug=1 still routes (the
    // match is path-prefix here, but rate limits and query criteria
    // likewise evaluated the original). The upstream sees the result.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api?uid=7&keep=%2Fraw&debug=1")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (_, body) = body_of(resp).await;
    let view: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        view["uri"].as_str().unwrap(),
        "/api?user_id=7&keep=%2Fraw&region=us-east&source=gw",
        "rename keeps position and the raw %2F spelling survives untouched pairs"
    );
}

#[tokio::test]
async fn request_body_transform_rewrites_json_and_declares_the_new_length() {
    let port = echo_backend_async().await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      request:
        body:
          json:
            max_bytes: 4096
            ops:
              - { op: set, path: /meta/via, value: dwara }
              - { op: remove, path: /internal/secret }"#,
    ));
    let body = r#"{"meta":{},"internal":{"secret":"hunter2"},"n":1}"#;
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::POST)
            .uri("/api")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, out) = body_of(resp).await;
    let view: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let received: serde_json::Value = serde_json::from_str(view["body"].as_str().unwrap()).unwrap();
    assert_eq!(received["meta"]["via"], "dwara");
    assert!(
        received
            .get("internal")
            .and_then(|i| i.get("secret"))
            .is_none(),
        "the secret leaf is gone (the parent object stays: the pointer addressed the leaf)"
    );
    assert_eq!(received["n"], 1);
    // The declared Content-Length matches the TRANSFORMED body, not the
    // client's original (framing correctness).
    let transformed = serde_json::to_string(&received).unwrap();
    assert_eq!(
        view["declared_len"].as_str().unwrap(),
        transformed.len().to_string()
    );
}

#[tokio::test]
async fn request_body_transform_leaves_non_json_bodies_untouched() {
    let port = echo_backend_async().await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      request:
        body:
          json:
            max_bytes: 8
            ops:
              - { op: remove, path: /x }"#,
    ));
    // A text body LARGER than the cap: the transform never applies (it
    // is gated on the content type), so the tiny cap cannot reject it.
    let body = "not json at all, quite a bit longer than eight bytes";
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::POST)
            .uri("/api")
            .header(CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(body)))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, out) = body_of(resp).await;
    let view: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(view["body"].as_str().unwrap(), body);
}

#[tokio::test]
async fn request_body_transform_fails_closed_over_cap_invalid_json_and_pointer_misses() {
    let port = echo_backend_async().await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      request:
        body:
          json:
            max_bytes: 16
            ops:
              - { op: remove, path: /x }"#,
    ));
    async fn post(dp: &Arc<dwara_core::proxy::DataPlane>, body: &str) -> (StatusCode, Bytes) {
        let resp = send(
            dp,
            Request::builder()
                .method(Method::POST)
                .uri("/api")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await;
        body_of(resp).await
    }

    // Declared over cap: 413 without reading.
    let (status, body) = post(&dp, "{\"padding\":\"0123456789\"}").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(envelope_code(&body), "request_body_too_large");

    // JSON-typed but unparseable: 400 (the route pinned a JSON
    // contract; garbage claiming application/json is a client error).
    let (status, body) = post(&dp, "not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(envelope_code(&body), "request_body_invalid_json");

    // Pointer miss: 400 with a generic client message (the pointer
    // itself is server-side only).
    let (status, body) = post(&dp, "{\"other\":1}").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(envelope_code(&body), "request_transform_failed");

    // An empty declared body: nothing to transform, forwards fine.
    let (status, _) = post(&dp, "").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn response_header_transforms_shape_the_client_response() {
    let port = echo_backend_async().await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      response:
        headers:
          set:
            x-filtered: yes
          remove:
            - server
          rename:
            x-upstream-note: x-note"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(headers.get("x-filtered").unwrap(), "yes");
    assert!(headers.get("server").is_none());
    assert!(headers.get("x-upstream-note").is_none());
}

#[tokio::test]
async fn response_body_transform_rewrites_json_responses() {
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(
                    "{\"client\":{\"seen\":true},\"debug\":{\"internal\":\"trace\"}}",
                )))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      response:
        body:
          json:
            max_bytes: 4096
            ops:
              - { op: set, path: /client/via, value: dwara }
              - { op: remove, path: /debug/internal }"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let parts = {
        let (status, bytes) = body_of(resp).await;
        assert_eq!(status, StatusCode::OK);
        // Content-Length was rewritten to the transformed length.
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };
    // The echo backend's own document carried headers/debug etc.; the
    // transform stamped /client/via and removed /debug.
    assert_eq!(parts["client"]["via"], "dwara");
    assert!(
        parts.get("debug").and_then(|d| d.get("internal")).is_none(),
        "the internal leaf is gone (the parent object stays)"
    );
    assert_eq!(parts["client"]["seen"], true);
    let declared = serde_json::to_string(&parts).unwrap();
    // The response's Content-Length header matches the body received.
    // (Checked via a second request to read the header.)
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        resp.headers().get("content-length").unwrap().as_bytes(),
        declared.len().to_string().as_bytes()
    );
}

#[tokio::test]
async fn response_body_transform_preserves_streaming_for_other_content() {
    // The done-when of the issue: streaming is preserved unless a
    // transform explicitly buffers. A text/event-stream response on a
    // body-TRANSFORMED route must arrive byte-exact and unstamped.
    // (No Content-Length declared: the gateway sees a body of unknown
    // length, exactly the streaming shape.)
    let sse = Arc::new(Bytes::from("data: one\n\ndata: two\n\ndata: three\n\n"));
    let port = support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| {
        let sse = Arc::clone(&sse);
        async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "text/event-stream")
                .body(Full::new(sse.as_ref().clone()))
                .unwrap())
        }
    })
    .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      response:
        body:
          json:
            max_bytes: 16
            ops:
              - { op: remove, path: /x }"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );
    let (_, body) = body_of(resp).await;
    assert_eq!(
        body,
        Bytes::from("data: one\n\ndata: two\n\ndata: three\n\n"),
        "non-JSON streamed content passes through the transformed route untouched"
    );
}

#[tokio::test]
async fn response_body_transform_fails_closed_502() {
    let port = echo_backend_async().await;
    // The echo document is bigger than 16 bytes with a pointer that
    // does not resolve (/absent-key): both failure modes answer 502.
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      response:
        body:
          json:
            max_bytes: 16
            ops:
              - { op: remove, path: /absent-key }"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_transform_failed");
}

#[tokio::test]
async fn response_body_transform_skips_already_encoded_bodies() {
    // An upstream that already encoded its body: the transform does
    // not decode, so the response passes through untouched (the
    // documented pass-through, mirroring the compression policy).
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .header("content-encoding", "gzip")
                .body(Full::new(Bytes::from_static(b"\x1f\x8b-not-really-gzip")))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      response:
        body:
          json:
            max_bytes: 4
            ops:
              - { op: remove, path: /x }"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"\x1f\x8b-not-really-gzip"));
}

#[tokio::test]
async fn security_headers_replace_upstream_values_on_action_responses() {
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            let mut b = Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .header("strict-transport-security", "max-age=1")
                .header("x-content-type-options", "bogus")
                .header("content-security-policy", "stale-policy");
            b = b.header("x-frame-options", "ALLOW-FROM https://x");
            Ok(b.body(Full::new(Bytes::from_static(b"ok"))).unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    security_headers:
      hsts_max_age_secs: 31536000
      hsts_include_subdomains: true
      nosniff: true
      content_security_policy: "default-src 'self'"
      frame_options: deny"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(
        h.get("strict-transport-security").unwrap(),
        "max-age=31536000; includeSubDomains"
    );
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(
        h.get("content-security-policy").unwrap(),
        "default-src 'self'"
    );
    assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
}

#[tokio::test]
async fn security_headers_stamp_gateway_short_circuits_but_not_unrouted_404s() {
    let port = echo_backend_async().await;
    let dp = dataplane_from(&format!(
        r#"
routes:
  - name: guarded
    service: svc
    match:
      path: {{ type: prefix, value: /api }}
    action: {{ type: proxy }}
    auth_required: true
    security_headers:
      nosniff: true
      hsts_max_age_secs: 60
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    ));
    // 401 (no credential): a browser parsing this error page gets the
    // same edge hardening as a 200.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        resp.headers().get("strict-transport-security").unwrap(),
        "max-age=60"
    );

    // Unrouted 404: no route, no policy.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/nope")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(resp.headers().get("x-content-type-options").is_none());
}

#[tokio::test]
async fn header_only_transforms_preserve_streaming_bodies_byte_exactly() {
    // The other half of the streaming guarantee: a route whose request
    // transforms touch only headers forwards a large body byte-exact.
    let payload = "x".repeat(256 * 1024);
    let port = echo_backend_async().await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      request:
        headers:
          set:
            x-gateway: dwara"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::POST)
            .uri("/api")
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::from(payload.clone())))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, body) = body_of(resp).await;
    let view: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(view["body"].as_str().unwrap().len(), payload.len());
    assert_eq!(view["headers"]["x-gateway"], "dwara");
}

#[tokio::test]
async fn transforms_route_matching_and_limits_saw_the_original_request() {
    // Route criteria (query match) evaluate the ORIGINAL query even
    // when a transform renames that very parameter — pinned so the
    // "transforms run on the forward path" contract cannot drift into
    // matching.
    let port = echo_backend_async().await;
    let dp = dataplane_from(&format!(
        r#"
routes:
  - name: versioned
    service: svc
    match:
      path: {{ type: prefix, value: /v }}
      query:
        - {{ name: version, value: "2" }}
    action: {{ type: proxy }}
    transforms:
      request:
        query:
          rename:
            version: v
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/v/items?version=2")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK, "matched on the original query");
    let view: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(view["uri"].as_str().unwrap(), "/v/items?v=2");
}

#[tokio::test]
async fn response_transform_order_runs_before_compression_eligibility() {
    // A header transform rewriting Content-Type feeds the compression
    // policy's eligibility check (tail order: transforms, then
    // compression). text/plain out of policy -> uncompressed even with
    // a compression block that would compress application/json.
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(
                    "{\"pad\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
                )))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    transforms:
      response:
        headers:
          set:
            content-type: text/plain
    compression:
      min_size: 8
      content_types: ["application/json"]"#,
    ));
    let resp = send(
        &dp,
        Request::builder()
            .uri("/api")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    // The final Content-Type is text/plain (out of compression
    // policy), so the body passes uncompressed despite the gzip offer.
    assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "text/plain");
    assert!(resp.headers().get("content-encoding").is_none());
    let (_, body) = body_of(resp).await;
    assert_eq!(
        body,
        Bytes::from("{\"pad\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}")
    );
}

#[tokio::test]
async fn retries_replay_the_transformed_bytes_not_the_original_stream() {
    // The body transform runs BEFORE retry buffering, so a retried
    // attempt re-sends the TRANSFORMED body. The upstream's
    // buffer_max_bytes is deliberately tiny (4): the DW-014 buffer
    // could never hold this body, proving the replay source is the
    // transform's bytes, not the generic buffer path.
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_backend = Arc::clone(&hits);
    let port = support::spawn_backend_async(move |req: Request<hyper::body::Incoming>| {
        let hits = Arc::clone(&hits_for_backend);
        async move {
            use http_body_util::BodyExt;
            let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
            let body = req.into_body().collect().await.unwrap().to_bytes();
            // EVERY attempt — first send and retry alike — must observe
            // the TRANSFORMED document, never the client's original.
            assert_eq!(
                body,
                Bytes::from("{\"meta\":{\"via\":\"dwara\"}}"),
                "attempt {n} saw untransformed bytes"
            );
            if n == 1 {
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            Ok(Response::builder()
                .header(CONTENT_TYPE, "text/plain")
                .body(Full::new(body))
                .unwrap())
        }
    })
    .await;
    let dp = dataplane_from(&format!(
        r#"
routes:
  - name: t
    service: svc
    match:
      path: {{ type: prefix, value: /api }}
    action: {{ type: proxy }}
    transforms:
      request:
        body:
          json:
            max_bytes: 4096
            ops:
              - {{ op: set, path: /meta/via, value: dwara }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
    retries:
      attempts: 2
      retry_post: true
      backoff_base_ms: 1
      backoff_cap_ms: 2
      budget_percent: 100
      buffer_max_bytes: 4
"#
    ));
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::POST)
            .uri("/api")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from("{\"meta\":{}}")))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, body) = body_of(resp).await;
    assert_eq!(
        body,
        Bytes::from("{\"meta\":{\"via\":\"dwara\"}}"),
        "the retry echoed the transformed body back"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2, "one retry after the 503");
}
