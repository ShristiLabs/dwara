//! Mock mode and request validation integration tests (DW-047).
//!
//! Drives `proxy::handle` directly against in-process configs (no real
//! upstream) and pins:
//!
//! - MOCK ACTION: a route with `action: { type: mock, ... }` answers
//!   the canned status/headers/body without contacting any upstream;
//!   `body` and `body_file` both work; `delay_ms` introduces a
//!   measurable pause; the default content-type is inferred
//!   (application/json for JSON bodies, text/plain otherwise) unless
//!   the operator sets one.
//! - REQUEST VALIDATION: a route with `request_validation.body_schema`
//!   validates the request body before the action runs; a mismatch
//!   answers 400 `validation_failed`; a match proceeds to the action;
//!   the schema subset (type, required, properties, items, enum,
//!   minimum, maximum, minLength, maxLength, additionalProperties) is
//!   exercised.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::StatusCode;
use serde_json::json;

mod support;

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn dp_from(yaml: &str) -> Arc<DataPlane> {
    let gateway = parse_gateway(yaml).expect("test config parses");
    let state = Arc::new(ConfigState::new());
    state
        .compile_and_publish(&gateway)
        .expect("test config publishes");
    DataPlane::new(state)
}

async fn handle(
    dp: &Arc<DataPlane>,
    request: Request<Full<Bytes>>,
) -> (StatusCode, String, hyper::HeaderMap) {
    let resp = dwara_core::proxy::handle(dp, peer(), request).await;
    let (parts, body) = resp.into_parts();
    let text =
        String::from_utf8(body.collect().await.expect("body").to_bytes().to_vec()).expect("utf8");
    (parts.status, text, parts.headers)
}

fn req(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn req_with_method_body(method: &str, path: &str, body: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// The common service+upstream block appended to every mock test config.
/// The mock action never contacts the upstream, but the frozen
/// vocabulary requires a service to reference one.
const SVC_UPSTREAM: &str = r#"
services:
  - name: mock-service
    upstream: mock-backend
upstreams:
  - name: mock-backend
    endpoints:
      - { address: 127.0.0.1, port: 1 }
allow_empty_routes: false
"#;

/// Build a mock-route config with the given action YAML block.
fn mock_config(action_yaml: &str) -> String {
    format!(
        r#"routes:
  - name: mock-route
    service: mock-service
    match:
      path:
        type: exact
        value: /mock
      methods: [GET]
    action:
{action_yaml}
"#
    ) + SVC_UPSTREAM
}

// --- mock action -----------------------------------------------------------

#[tokio::test]
async fn mock_inline_body_and_headers() {
    let yaml = mock_config(
        "      type: mock\n      status: 200\n      body: '{\"message\":\"hello\"}'\n      headers:\n        X-Custom: test-value",
    );
    let dp = dp_from(&yaml);
    let (status, body, headers) = handle(&dp, req("/mock")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "{\"message\":\"hello\"}");
    assert_eq!(
        headers.get("x-custom").unwrap(),
        &hyper::header::HeaderValue::from_str("test-value").unwrap()
    );
    // Default content-type: body parses as JSON -> application/json.
    assert_eq!(
        headers.get(hyper::header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn mock_custom_status() {
    let yaml = mock_config("      type: mock\n      status: 418\n      body: \"I'm a teapot\"");
    let dp = dp_from(&yaml);
    let (status, body, headers) = handle(&dp, req("/mock")).await;
    assert_eq!(status, StatusCode::from_u16(418).unwrap());
    assert_eq!(body, "I'm a teapot");
    // Non-JSON body -> text/plain default.
    assert_eq!(
        headers.get(hyper::header::CONTENT_TYPE).unwrap(),
        "text/plain"
    );
}

#[tokio::test]
async fn mock_empty_body() {
    let yaml = mock_config("      type: mock\n      status: 204");
    let dp = dp_from(&yaml);
    let (status, body, _) = handle(&dp, req("/mock")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(body, "");
}

#[tokio::test]
async fn mock_explicit_content_type_header() {
    let yaml = mock_config(
        "      type: mock\n      status: 200\n      body: '<xml>hello</xml>'\n      headers:\n        Content-Type: application/xml",
    );
    let dp = dp_from(&yaml);
    let (status, _, headers) = handle(&dp, req("/mock")).await;
    assert_eq!(status, StatusCode::OK);
    // Explicit content-type wins over the inferred default.
    assert_eq!(
        headers.get(hyper::header::CONTENT_TYPE).unwrap(),
        "application/xml"
    );
}

#[tokio::test]
async fn mock_delay_ms() {
    let yaml = mock_config(
        "      type: mock\n      status: 200\n      body: delayed\n      delay_ms: 100",
    );
    let dp = dp_from(&yaml);
    let start = std::time::Instant::now();
    let (status, _, _) = handle(&dp, req("/mock")).await;
    let elapsed = start.elapsed();
    assert_eq!(status, StatusCode::OK);
    // The delay is at least 100ms (allow generous margin for scheduler).
    assert!(
        elapsed >= std::time::Duration::from_millis(90),
        "expected >=90ms delay, got {elapsed:?}"
    );
}

#[tokio::test]
async fn mock_body_file() {
    // Write a temp file for the mock body.
    let dir = std::env::temp_dir();
    let body_path = dir.join("dwara_mock_test_body.json");
    std::fs::write(&body_path, r#"{"from":"file"}"#).unwrap();
    let body_path_str = body_path.to_str().unwrap();
    let yaml = mock_config(&format!(
        "      type: mock\n      status: 200\n      body_file: {body_path_str}"
    ));
    let dp = dp_from(&yaml);
    let (status, body, headers) = handle(&dp, req("/mock")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"from":"file"}"#);
    assert_eq!(
        headers.get(hyper::header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let _ = std::fs::remove_file(&body_path);
}

// --- request validation ----------------------------------------------------

fn validation_config(schema_yaml: &str) -> String {
    format!(
        r#"routes:
  - name: validated-post
    service: mock-service
    match:
      path:
        type: exact
        value: /submit
      methods: [POST]
    action:
      type: mock
      status: 201
      body: '{{"ok":true}}'
    request_validation:
      body_schema:
{schema_yaml}
"#
    ) + SVC_UPSTREAM
}

const OBJECT_SCHEMA_YAML: &str = "        type: object\n        required: [name, age]\n        properties:\n          name:\n            type: string\n            minLength: 1\n          age:\n            type: integer\n            minimum: 0\n            maximum: 150";

#[tokio::test]
async fn validation_pass_valid_body() {
    let yaml = validation_config(OBJECT_SCHEMA_YAML);
    let dp = dp_from(&yaml);
    let body = json!({"name":"Alice","age":30}).to_string();
    let (status, resp_body, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(resp_body, "{\"ok\":true}");
}

#[tokio::test]
async fn validation_fails_missing_required() {
    let yaml = validation_config(OBJECT_SCHEMA_YAML);
    let dp = dp_from(&yaml);
    let body = json!({"name":"Alice"}).to_string();
    let (status, resp_body, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
    assert!(resp_body.contains("age"));
}

#[tokio::test]
async fn validation_fails_wrong_type() {
    let yaml = validation_config(OBJECT_SCHEMA_YAML);
    let dp = dp_from(&yaml);
    let body = json!({"name":"Alice","age":"thirty"}).to_string();
    let (status, resp_body, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
}

#[tokio::test]
async fn validation_fails_minimum() {
    let yaml = validation_config(OBJECT_SCHEMA_YAML);
    let dp = dp_from(&yaml);
    let body = json!({"name":"Alice","age":-1}).to_string();
    let (status, resp_body, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
}

#[tokio::test]
async fn validation_fails_not_json() {
    let yaml = validation_config(OBJECT_SCHEMA_YAML);
    let dp = dp_from(&yaml);
    let (status, resp_body, _) =
        handle(&dp, req_with_method_body("POST", "/submit", "not json")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
    assert!(resp_body.contains("JSON"));
}

#[tokio::test]
async fn validation_fails_empty_body_with_required() {
    let yaml = validation_config(OBJECT_SCHEMA_YAML);
    let dp = dp_from(&yaml);
    let (status, resp_body, _) = handle(&dp, req_with_method_body("POST", "/submit", "")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
    assert!(resp_body.contains("required"));
}

#[tokio::test]
async fn validation_additional_properties_false() {
    let schema = "        type: object\n        properties:\n          a:\n            type: string\n        additionalProperties: false";
    let yaml = validation_config(schema);
    let dp = dp_from(&yaml);
    // Extra property -> rejected.
    let body = json!({"a":"ok","b":"extra"}).to_string();
    let (status, resp_body, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
    assert!(resp_body.contains("additional"));

    // Only known properties -> passes.
    let body = json!({"a":"ok"}).to_string();
    let (status, _, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn validation_array_items() {
    let schema = "        type: array\n        items:\n          type: string";
    let yaml = validation_config(schema);
    let dp = dp_from(&yaml);
    // Valid: array of strings.
    let body = json!(["a", "b", "c"]).to_string();
    let (status, _, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::CREATED);

    // Invalid: array with a non-string element.
    let body = json!(["a", 42, "c"]).to_string();
    let (status, resp_body, _) = handle(&dp, req_with_method_body("POST", "/submit", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
}

#[tokio::test]
async fn validation_enum() {
    let schema = "        type: string\n        enum: [red, green, blue]";
    let yaml = validation_config(schema);
    let dp = dp_from(&yaml);
    // Valid enum value.
    let (status, _, _) = handle(&dp, req_with_method_body("POST", "/submit", "\"red\"")).await;
    assert_eq!(status, StatusCode::CREATED);

    // Invalid enum value.
    let (status, resp_body, _) =
        handle(&dp, req_with_method_body("POST", "/submit", "\"purple\"")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("validation_failed"));
    assert!(resp_body.contains("enum"));
}

#[tokio::test]
async fn validation_string_length_bounds() {
    let schema = "        type: string\n        minLength: 3\n        maxLength: 5";
    let yaml = validation_config(schema);
    let dp = dp_from(&yaml);
    // Too short.
    let (status, resp_body, _) =
        handle(&dp, req_with_method_body("POST", "/submit", "\"ab\"")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("minLength"));

    // Too long.
    let (status, resp_body, _) =
        handle(&dp, req_with_method_body("POST", "/submit", "\"abcdef\"")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(resp_body.contains("maxLength"));

    // Just right.
    let (status, _, _) = handle(&dp, req_with_method_body("POST", "/submit", "\"abcd\"")).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn validation_no_schema_passes_anything() {
    // A route with no request_validation passes any body through.
    let yaml = r#"routes:
  - name: no-validation
    service: mock-service
    match:
      path:
        type: exact
        value: /open
      methods: [POST]
    action:
      type: mock
      status: 200
      body: '{}'
"#
    .to_string()
        + SVC_UPSTREAM;
    let dp = dp_from(&yaml);
    let (status, _, _) = handle(
        &dp,
        req_with_method_body("POST", "/open", "anything at all"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
