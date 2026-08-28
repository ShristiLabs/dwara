//! HMAC request-signing integration tests (DW-036, issue #37).
//!
//! Signs requests with an INDEPENDENT implementation of the canonical
//! string documented in `security::authn` (the suite re-derives the
//! grammar from the docs, not from the gateway's `canonical_string`
//! helper, so the documentation is pinned as the interop contract),
//! then drives them through the real dataplane over HTTP: round trips
//! (GET with the empty-body digest, POST with a payload digest), every
//! tamper family (method/path/query/body/header) rejected 401, the
//! clock-skew window boundaries, nonce replay, unknown keys, and the
//! interaction with policies (signed traffic is still rate-limited).

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use sha2::{Digest, Sha256};

mod support;

use support::{body_of, spawn_gateway, spawn_gateway_on};

const SECRET: &str = "test-hmac-secret-0123456789abcdef0123456789abcdef";
const KEY_ID: &str = "signer-key-1";

/// The signed request headers for one request, built from the module
/// docs' grammar ALONE (this suite is the independent conformance
/// signer; do not import the gateway's canonical builder here).
fn sign(
    secret: &str,
    key_id: &str,
    method: &str,
    target: &str,
    body: &[u8],
    nonce: &str,
    timestamp: u64,
) -> Vec<(String, String)> {
    // target = "/path?query"; the canonical string carries the path and
    // the query (no leading '?') as separate lines, the query line EMPTY
    // when absent.
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (target, String::new()),
    };
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let bytes = hasher.finalize();
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let timestamp = timestamp.to_string();
    let canonical = [
        "dwara-hmac-v1",
        key_id,
        method,
        path,
        &query,
        &timestamp,
        nonce,
        &digest,
    ]
    .join("\n");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(canonical.as_bytes());
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    vec![
        ("x-dwara-key-id".to_string(), key_id.to_string()),
        ("x-dwara-timestamp".to_string(), timestamp),
        ("x-dwara-nonce".to_string(), nonce.to_string()),
        ("x-dwara-body-sha256".to_string(), digest),
        ("x-dwara-signature".to_string(), signature),
    ]
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Gateway YAML with an HMAC consumer; `extra` splices gateway-level
/// keys (e.g. the `hmac_auth` block or rate-limit policies).
fn hmac_gateway_yaml(extra: &str, backend_port: u16) -> String {
    format!(
        "{extra}routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {backend_port}\n\
         consumers:\n\
         - name: signer\n\
         \x20 credentials:\n\
         \x20   - type: hmac\n\
         \x20     key_id: {KEY_ID}\n\
         \x20     secret: {SECRET}\n"
    )
}

/// Upstream echoing method + path + full body (needs the async handler
/// to collect a streaming body); the tamper tests assert the upstream
/// never answers for a mismatched request (the digest wrapper aborts
/// the send before the upstream can complete it).
async fn async_echo_backend() -> u16 {
    support::spawn_backend_async(|req: Request<hyper::body::Incoming>| async move {
        let (parts, body) = req.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let payload = format!(
            "{} {} consumer={} body={}",
            parts.method,
            parts.uri.path(),
            parts
                .headers
                .get("x-consumer-name")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<none>"),
            String::from_utf8_lossy(&bytes)
        );
        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(payload))))
    })
    .await
}

/// One signed HTTP request through a spawned gateway.
async fn send_signed(
    port: u16,
    method: &str,
    target: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> (StatusCode, HeaderMap, String) {
    let client = support::h1_client();
    let mut builder = Request::builder()
        .method(method)
        .uri(support::uri(port, target));
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let req = builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = resp.collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn signed_round_trip_get_and_post() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // GET with the empty-body digest.
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-roundtrip-get",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("GET /api/x consumer=signer body="),
        "identity rides the request: {body}"
    );

    // POST with a payload digest: the upstream sees the exact signed body.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/api/submit",
        b"hello hmac",
        "nonce-request-roundtrip-post",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "POST", "/api/submit", b"hello hmac", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("body=hello hmac"), "{body}");
}

#[tokio::test]
async fn tampered_method_path_and_query_each_rejected() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // Method: sign GET, send POST with the GET's headers.
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-tamper-method",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "POST", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Path: sign /api/a, send /api/b.
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/a",
        b"",
        "nonce-request-tamper-path",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/b", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Query: sign ?a=1, send ?a=2 (query order and VALUE are signed).
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x?a=1",
        b"",
        "nonce-request-tamper-query",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x?a=2", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Control: the correctly signed query request passes.
    let (status, _, _) = send_signed(port, "GET", "/api/x?a=1", b"", &headers).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn tampered_body_rejected_mid_stream() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // Sign the digest of `aaaa`, send `bbbb`: the header MAC verifies
    // (the digest header itself is signed), so the mismatch is caught
    // while STREAMING — the wrapper aborts the upstream send at the
    // final frame and the client sees the family's 401.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/api/submit",
        b"aaaa",
        "nonce-request-tamper-body",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "POST", "/api/submit", b"bbbb", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tampered_header_rejected() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // Swap the nonce after signing: the MAC covers the nonce line, so
    // the canonical string the gateway builds no longer matches.
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-original",
        now_secs(),
    );
    for (name, value) in &mut headers {
        if name == "x-dwara-nonce" {
            *value = "nonce-request-swapped-after-signing".to_string();
        }
    }
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn clock_skew_window_boundaries() {
    let backend = async_echo_backend().await;
    // Skew 2s makes the window edges reachable without flaky margins:
    // "in" is |drift| far below 2, "at" lands inside by the sign-to-
    // verify epsilon (milliseconds), "out" is far beyond.
    let yaml = hmac_gateway_yaml("hmac_auth:\n  max_clock_skew_secs: 2\n", backend);
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;

    let now = now_secs();
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-skew-in",
        now,
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "timestamp at now is inside the window"
    );

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-skew-at",
        now.saturating_add(2),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "timestamp exactly +skew is the inclusive boundary"
    );

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-skew-out-future",
        now.saturating_add(30),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "future timestamp outside");

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-skew-out-past",
        now.saturating_sub(30),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "past timestamp outside");
}

#[tokio::test]
async fn replayed_nonce_rejected_then_fresh_nonce_accepted() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-once-only",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK);

    // Byte-identical replay inside the window: the nonce is remembered.
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // A fresh nonce on the same key works again (replay, not revocation).
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-second-request",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_key_missing_headers_and_bad_material_rejected() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // Unknown key id: the same 401 shape as every other family, with
    // the HMAC challenge advertised.
    let headers = sign(
        SECRET,
        "ghost-key",
        "GET",
        "/api/x",
        b"",
        "nonce-request-unknown-key",
        now_secs(),
    );
    let (status, hdrs, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        hdrs.get("www-authenticate").unwrap(),
        "Dwara-HMAC-SHA256 realm=\"dwara\"",
        "the challenge names the HMAC family"
    );
    assert_eq!(
        support::envelope_code(body.as_bytes()),
        "unauthorized",
        "the family's failure envelope matches the other authn families"
    );

    // Missing timestamp header: presented-but-malformed is still 401.
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-missing-ts",
        now_secs(),
    );
    headers.retain(|(name, _)| name != "x-dwara-timestamp");
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Malformed signature hex.
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-bad-hex",
        now_secs(),
    );
    for (name, value) in &mut headers {
        if name == "x-dwara-signature" {
            value.truncate(10);
        }
    }
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A short nonce (under the 16-byte entropy floor) is malformed.
    let headers = sign(SECRET, KEY_ID, "GET", "/api/x", b"", "short", now_secs());
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong secret entirely.
    let headers = sign(
        "an-entirely-different-secret",
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-wrong-secret",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signed_requests_are_still_rate_limited() {
    let backend = async_echo_backend().await;
    let yaml = hmac_gateway_yaml(
        "policies:\n  - name: tight\n    rate_limit: { requests: 1, window_seconds: 60 }\n",
        backend,
    )
    .replace(
        "consumers:\n- name: signer\n",
        "consumers:\n- name: signer\n  policies: [tight]\n",
    );
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;

    let first = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-rl-1",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &first).await;
    assert_eq!(status, StatusCode::OK, "the consumer's policy allows one");

    let second = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-rl-2",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &second).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "signed requests are policy-evaluated: {body}"
    );
}

#[tokio::test]
async fn env_referenced_secret_verifies() {
    // DW-045 seam: the HMAC secret resolves through ${...} references
    // exactly like api keys. A unique variable name keeps this test
    // independent of its siblings under the same-process executor.
    const VAR: &str = "DWARA_TEST_HMAC_SECRET_9F3A1C";
    std::env::set_var(VAR, SECRET);
    let backend = async_echo_backend().await;
    let yaml = hmac_gateway_yaml("", backend)
        .replace(&format!("secret: {SECRET}"), &format!("secret: ${{{VAR}}}"));
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-env-ref",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    std::env::remove_var(VAR);
}

// ---- config validation ------------------------------------------------------

/// `compile_and_publish` must fail with an issue naming the offending
/// field; assert on the rendered issue text so the message contract is
/// pinned, not just the failure.
fn assert_invalid(yaml: &str, needle: &str) {
    let gateway = dwara_core::config::parse_gateway(yaml).expect("parses");
    let state = dwara_core::snapshot::ConfigState::new();
    let err = state
        .compile_and_publish(&gateway)
        .expect_err("validation must fail");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains(needle),
        "expected an issue mentioning '{needle}', got: {rendered}"
    );
}

fn valid_hmac_yaml(extra: &str) -> String {
    format!(
        "{extra}routes:\n\
         - name: r\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path: {{ type: prefix, value: /api }}\n\
         \x20 action: {{ type: proxy }}\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n\
         consumers:\n\
         - name: signer\n\
         \x20 credentials:\n\
         \x20   - type: hmac\n\
         \x20     key_id: {KEY_ID}\n\
         \x20     secret: {SECRET}\n"
    )
}

#[test]
fn hmac_validation_bounds() {
    assert_invalid(
        &valid_hmac_yaml("hmac_auth:\n  max_clock_skew_secs: 0\n"),
        "hmac_auth.max_clock_skew_secs",
    );
    assert_invalid(
        &valid_hmac_yaml("hmac_auth:\n  max_clock_skew_secs: 3601\n"),
        "hmac_auth.max_clock_skew_secs",
    );
    // In-range values publish (1 and 3600 are the inclusive edges).
    for skew in [1u64, 3600] {
        let gateway = dwara_core::config::parse_gateway(&valid_hmac_yaml(&format!(
            "hmac_auth:\n  max_clock_skew_secs: {skew}\n"
        )))
        .unwrap();
        dwara_core::snapshot::ConfigState::new()
            .compile_and_publish(&gateway)
            .expect("edges publish");
    }
}

#[test]
fn hmac_credential_validation_issues() {
    assert_invalid(
        &valid_hmac_yaml("").replace(&format!("key_id: {KEY_ID}"), "key_id: \"\""),
        "hmac key_id is empty",
    );
    assert_invalid(
        &valid_hmac_yaml("").replace(&format!("key_id: {KEY_ID}"), "key_id: has space"),
        "visible ASCII",
    );
    assert_invalid(
        &valid_hmac_yaml("").replace(&format!("secret: {SECRET}"), "secret: \"\""),
        "hmac secret is empty",
    );
    // Unresolvable reference (fail closed at compile, naming the ref).
    assert_invalid(
        &valid_hmac_yaml("").replace(
            &format!("secret: {SECRET}"),
            "secret: ${file:/nonexistent/dwara-test-hmac-secret}",
        ),
        "secret file",
    );
    // Duplicate key ids across consumers are ambiguous selectors.
    assert_invalid(
        &valid_hmac_yaml("").replace(
            "consumers:\n",
            "consumers:\n\
             - name: other\n\
             \x20 credentials:\n\
             \x20   - type: hmac\n\
             \x20     key_id: signer-key-1\n\
             \x20     secret: another-secret-entirely\n",
        ),
        "already declared by consumer 'other'",
    );
}

// ---- forwarding shape -------------------------------------------------------

#[tokio::test]
async fn signature_headers_forwarded_and_unsigned_traffic_untouched() {
    // The X-Dwara-* family forwards upstream untouched (the X-API-Key
    // precedent: only X-Consumer-* are stripped), and unsigned requests
    // on the same gateway stay anonymous-allowed.
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    let client = support::h1_client();
    let resp = client
        .request(
            Request::builder()
                .uri(support::uri(port, "/api/headers"))
                .header("x-echo-headers", "1")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK, "anonymous traffic still flows");
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        !body.contains("401"),
        "no auth challenge on unsigned traffic: {body}"
    );

    // A signed request to a peer-address gateway also works over IPv6
    // loopback (the family is transport-independent).
    let (host, v6port) = spawn_gateway_on(
        support::dataplane_from(&hmac_gateway_yaml("", backend)),
        "[::1]:0",
    )
    .await;
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-v6",
        now_secs(),
    );
    let client = support::h1_client();
    let uri: hyper::Uri = format!("http://{host}:{v6port}/api/x").parse().unwrap();
    let mut builder = Request::builder().uri(uri);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    let resp = client
        .request(builder.body(Full::new(Bytes::new())).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---- gap coverage: body-digest enforcement depth (DW-036) ------------------
//
// The existing tamper test exercises a single-frame Content-Length
// body, where the digest check fires at declared-size saturation. The
// unknown-length (chunked) shape can only be checked at the
// TERMINATING frame, and multi-frame accumulation is a distinct hash
// pipeline — both pinned here.

/// Request body yielding fixed data frames with an UNKNOWN size hint
/// (hyper therefore sends it with chunked framing): the body shape
/// whose digest can only be enforced at the terminating frame.
struct ChunkedBody {
    frames: std::vec::IntoIter<Bytes>,
}

impl Body for ChunkedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.get_mut().frames.next() {
            Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            None => Poll::Ready(None),
        }
    }

    fn size_hint(&self) -> SizeHint {
        // Unknown by construction: never lets the digest check fire at
        // declared-size saturation.
        SizeHint::default()
    }
}

/// One signed request with a multi-frame unknown-length body.
async fn send_signed_chunked(
    port: u16,
    target: &str,
    frames: &[&[u8]],
    headers: &[(String, String)],
) -> (StatusCode, String) {
    let client: Client<HttpConnector, ChunkedBody> =
        Client::builder(TokioExecutor::new()).build_http();
    let mut builder = Request::builder()
        .method("POST")
        .uri(support::uri(port, target));
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let body = ChunkedBody {
        frames: frames
            .iter()
            .map(|f| Bytes::copy_from_slice(f))
            .collect::<Vec<_>>()
            .into_iter(),
    };
    let resp = client.request(builder.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn chunked_body_digest_checked_at_terminating_frame() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // Correct digest over a body delivered as THREE frames: every frame
    // must fold into the same incremental hash a one-shot signer
    // computed, and the upstream must see the concatenated bytes.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/api/submit",
        b"chunked-body",
        "nonce-request-chunked-ok",
        now_secs(),
    );
    let frames: [&[u8]; 3] = [b"chun", b"ked-", b"body"];
    let (status, body) = send_signed_chunked(port, "/api/submit", &frames, &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("body=chunked-body"),
        "multi-frame body reassembles upstream: {body}"
    );

    // Mismatching digest on an unknown-length body: no declared size,
    // so the check can only fire at the terminating frame — the
    // tampered stream still never completes.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/api/submit",
        b"honest-body",
        "nonce-request-chunked-bad",
        now_secs(),
    );
    let bad_frames: [&[u8]; 2] = [b"chunked-", b"body"];
    let (status, _) = send_signed_chunked(port, "/api/submit", &bad_frames, &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "terminating-frame mismatch is a 401, not a completed forward"
    );
}

#[tokio::test]
async fn empty_body_with_mismatching_digest_rejected() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // Sign the digest of a payload, send NO body: the forwarding
    // encoder never polls a Content-Length: 0 stream (hyper writes
    // the header from the size hint and drops the body), so the
    // digest decision runs EAGERLY when the wrapper is built — only
    // the SHA-256 of the empty string may verify for an empty body,
    // and a mismatch answers the family's 401 before forwarding.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/api/submit",
        b"payload-that-was-omitted",
        "nonce-request-empty-mismatch",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "POST", "/api/submit", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Control: an empty body signed with the empty-string digest
    // forwards and 200s — the eager path must not reject honest
    // empties.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/api/submit",
        b"",
        "nonce-request-empty-honest",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "POST", "/api/submit", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn missing_key_id_nonce_or_digest_header_rejected() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // The suite already pins the missing-timestamp shape; the other
    // three required headers share it: a partial header set is a
    // malformed PRESENTED credential (401), never anonymous.
    for missing in ["x-dwara-key-id", "x-dwara-nonce", "x-dwara-body-sha256"] {
        let mut headers = sign(
            SECRET,
            KEY_ID,
            "GET",
            "/api/x",
            b"",
            &format!("nonce-request-missing-{missing}"),
            now_secs(),
        );
        headers.retain(|(name, _)| name != missing);
        let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{missing}: {body}");
    }
}

#[tokio::test]
async fn over_cap_signed_body_is_413_whether_or_not_the_digest_matches() {
    let backend = async_echo_backend().await;
    // A capped route alongside the default one; the digest wrapper sits
    // INSIDE the limit wrapper, so the 413 must win over any digest
    // verdict.
    let yaml = hmac_gateway_yaml("", backend).replace(
        "services:\n",
        "- name: limited\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path: { type: prefix, value: /limited }\n\
         \x20 action: { type: proxy }\n\
         \x20 limits:\n\
         \x20   max_body_bytes: 8\n\
         services:\n",
    );
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;

    let oversized: Vec<u8> = (0..100).collect();
    // Declared-length over cap, digest CORRECT: 413 (route limits run
    // before authn, and the streaming half would agree).
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/limited/submit",
        &oversized,
        "nonce-request-cap-exact",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "POST", "/limited/submit", &oversized, &headers).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Declared-length over cap, digest WRONG: still 413 — the limit
    // wrapper rejects before the digest decision can answer 401.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/limited/submit",
        b"eight-bytes-exact!!",
        "nonce-request-cap-wrong-digest",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "POST", "/limited/submit", &oversized, &headers).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the 413 wins over the digest verdict"
    );

    // Unknown-length over cap, digest wrong: the streaming cap fires
    // mid-stream, BEFORE the terminating-frame digest check.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/limited/submit",
        b"honest-eight-bytes",
        "nonce-request-cap-chunked",
        now_secs(),
    );
    let chunk_frames: [&[u8]; 2] = [&oversized, &oversized];
    let (status, _) = send_signed_chunked(port, "/limited/submit", &chunk_frames, &headers).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Control: a signed body within the cap still passes on the same
    // route (the cap did not break the digest pipeline).
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/limited/submit",
        b"12345678",
        "nonce-request-cap-within",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "POST", "/limited/submit", b"12345678", &headers).await;
    assert_eq!(status, StatusCode::OK);
}

// ---- gap coverage: canonicalization edges ------------------------------------

#[tokio::test]
async fn percent_encoded_path_signed_raw_without_normalization() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // %20 must reach the canonical string (and the upstream) as the
    // raw encoded bytes the client sent — the gateway signs what it
    // received, not a decoded interpretation.
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/a%20b",
        b"",
        "nonce-request-pct-ok",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/a%20b", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("GET /api/a%20b"),
        "the encoded path forwards verbatim: {body}"
    );

    // %2F and a literal / are DIFFERENT canonical strings: swapping one
    // for the other (what a normalizing middlebox would do) breaks the
    // signature.
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/a%2Fb",
        b"",
        "nonce-request-pct-slash",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/a/b", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a decoded variant of the signed path must not verify"
    );
}

#[tokio::test]
async fn absent_and_empty_query_share_the_empty_canonical_line() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // The grammar's query line is EMPTY both when the query is absent
    // and when it is present-but-empty ("/api/x?"): the two requests
    // have identical canonical strings, so a signature computed for the
    // bare path verifies for the trailing-? form. Pin the documented
    // equivalence (and that neither normalizes to "?").
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-empty-query-eq",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x?", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "absent and empty query are the same empty canonical line"
    );
}

#[tokio::test]
async fn lowercase_extension_method_verifies_under_uppercase_grammar() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // The grammar says "the HTTP method, uppercased" — the gateway
    // uppercases whatever arrived, so a case-mangled chain still
    // verifies against an upper-case-signed canonical string...
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-lower-wire",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "get", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // ...while a signer that put the lower-case form INTO its canonical
    // string is non-conformant and must not verify...
    let headers = sign(
        SECRET,
        KEY_ID,
        "get",
        "/api/x",
        b"",
        "nonce-request-lower-canonical",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "get", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a lower-case canonical method line is not the grammar"
    );

    // ...and the transform is a transform, not a wildcard: signing POST
    // and sending `get` stays a tamper.
    let headers = sign(
        SECRET,
        KEY_ID,
        "POST",
        "/api/x",
        b"",
        "nonce-request-method-swap",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "get", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- gap coverage: family precedence with a signature present -----------------

#[tokio::test]
async fn precedence_authorization_schemes_and_api_key_over_signature() {
    let backend = async_echo_backend().await;
    // A second consumer with an api-key credential makes both the
    // Authorization schemes and the api-key family dispatchable.
    let yaml = hmac_gateway_yaml("", backend).replace(
        "consumers:\n",
        "consumers:\n\
         - name: keyuser\n\
         \x20 credentials:\n\
         \x20   - type: api_key\n\
         \x20     key: sekrit-key\n",
    );
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;

    // Bearer with no JWT provider configured stays pass-through, so a
    // signed request carrying a stray Bearer token still authenticates
    // through the signature family.
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-prec-bearer",
        now_secs(),
    );
    headers.push((
        "authorization".to_string(),
        "Bearer some-oauth-token".to_string(),
    ));
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("consumer=signer"),
        "the bearer falls through to the verified signature: {body}"
    );

    // A PRESENTED Basic credential is interpreted once any credential
    // exists: it fails (no match) and must NOT fall through to the
    // otherwise-valid signature — header credentials express intent
    // and win in order.
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-prec-basic",
        now_secs(),
    );
    headers.push(("authorization".to_string(), "Basic dTpw".to_string()));
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a rejected Basic credential does not fall through to the signature"
    );

    // X-API-Key outranks Authorization AND the signature family: a
    // valid key with junk signature headers still authenticates.
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-prec-apikey",
        now_secs(),
    );
    headers.push(("x-api-key".to_string(), "sekrit-key".to_string()));
    headers[4].1.replace_range(0..1, "0");
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("consumer=keyuser"),
        "the api-key family wins over the junk signature: {body}"
    );

    // ...and a PRESENTED-but-unknown api key is a 401 even with a valid
    // signature attached (no fall-through, same rule as Basic).
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-prec-apikey-bad",
        now_secs(),
    );
    headers.push(("x-api-key".to_string(), "not-a-configured-key".to_string()));
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- gap coverage: the upstream forwarding pin --------------------------------

#[tokio::test]
async fn x_dwara_headers_forwarded_upstream_byte_for_byte() {
    // The X-API-Key precedent: signature headers ride to the upstream
    // untouched (only X-Consumer-* are stripped inbound). Pin the
    // VALUES, not just their presence.
    let headers_echo_backend =
        support::spawn_backend_async(|req: Request<hyper::body::Incoming>| async move {
            let mut lines = Vec::new();
            for name in [
                "x-dwara-key-id",
                "x-dwara-timestamp",
                "x-dwara-nonce",
                "x-dwara-body-sha256",
                "x-dwara-signature",
            ] {
                let value = req
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<absent>");
                lines.push(format!("{name}={value}"));
            }
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(lines.join("\n")))))
        })
        .await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", headers_echo_backend));
    let port = spawn_gateway(dp).await;

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-forwarded",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (name, value) in &headers {
        assert!(
            body.contains(&format!("{name}={value}")),
            "{name} must forward byte-for-byte: {body}"
        );
    }
}

// ---- gap coverage: the replay window across a reload --------------------------

#[tokio::test]
async fn nonce_still_burned_after_config_reload() {
    // The replay-nonce store is shared across authenticator rebuilds
    // (the jwks_caches precedent): a reload must not re-open the replay
    // window mid-flight. publish + refresh is exactly the binary's
    // reload path.
    let backend = async_echo_backend().await;
    let yaml = hmac_gateway_yaml("", backend);
    let state = support::state_from(&yaml);
    let dp = dwara_core::proxy::DataPlane::new(Arc::clone(&state));
    let port = spawn_gateway(Arc::clone(&dp)).await;

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-survives-reload",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK);

    state
        .compile_and_publish(&dwara_core::config::parse_gateway(&yaml).unwrap())
        .expect("republish of an unchanged config");
    dp.refresh();

    // Byte-identical replay after the rebuild: still rejected.
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the nonce survived the reload: {body}"
    );

    // A fresh nonce on the reloaded generation still passes.
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-post-reload-fresh",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK);
}

// ---- gap coverage: timestamp format robustness --------------------------------

#[tokio::test]
async fn malformed_timestamps_rejected() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    for (label, ts) in [
        ("non-digit", "not-a-timestamp"),
        ("negative", "-100"),
        ("21 digits", "100000000000000000000"),
    ] {
        let mut headers = sign(
            SECRET,
            KEY_ID,
            "GET",
            "/api/x",
            b"",
            &format!("nonce-request-bad-ts-{label}"),
            now_secs(),
        );
        for (name, value) in &mut headers {
            if name == "x-dwara-timestamp" {
                *value = ts.to_string();
            }
        }
        // Tampering the timestamp after signing also breaks the MAC;
        // either way the family must answer a clean 401 envelope — and
        // crucially must not 5xx or wedge on the hostile value.
        let (status, hdrs, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}: {body}");
        assert_eq!(
            support::envelope_code(body.as_bytes()),
            "unauthorized",
            "{label}: the failure is a normal 401 envelope"
        );
        assert_eq!(
            hdrs.get("www-authenticate").unwrap(),
            "Dwara-HMAC-SHA256 realm=\"dwara\"",
            "{label}: the challenge still names the family"
        );
    }
}

// ---- gap coverage: ${file:} secret reference ----------------------------------

#[tokio::test]
async fn file_referenced_secret_verifies() {
    // The env-reference round trip is pinned elsewhere; the file form
    // of the same DW-045 seam must resolve and verify identically (the
    // resolver trims one trailing newline, the mounted-secret shape).
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"file-backed-hmac-secret\n").unwrap();
    let backend = async_echo_backend().await;
    let yaml = hmac_gateway_yaml("", backend).replace(
        &format!("secret: {SECRET}"),
        &format!("secret: ${{file:{}}}", file.path().display()),
    );
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;

    let headers = sign(
        "file-backed-hmac-secret",
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-file-secret",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// ---- gap coverage: presented-material boundaries -------------------------------

#[tokio::test]
async fn nonce_and_key_id_boundary_lengths() {
    let backend = async_echo_backend().await;
    let dp = support::dataplane_from(&hmac_gateway_yaml("", backend));
    let port = spawn_gateway(dp).await;

    // Exactly 16 nonce bytes is the entropy floor: accepted.
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "0123456789abcdef",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a 16-byte nonce is the floor, not under it"
    );

    // One byte under the floor is malformed (the existing suite only
    // pinned a 5-byte nonce).
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "0123456789abcde",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a 15-byte nonce is malformed"
    );

    // One byte over the 256 ceiling: malformed.
    let long_nonce = "n".repeat(257);
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        &long_nonce,
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a 257-byte nonce is malformed"
    );

    // A 20-byte nonce CONTAINING a space: length is fine, the visible-
    // ASCII grammar is not (hyper permits interior spaces in values).
    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "abcd efghijklmnop",
        now_secs(),
    );
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a space inside the nonce violates the canonical grammar"
    );

    // A key id one byte over the 128-byte ceiling: malformed at the
    // format check (a 129-byte key id can never be configured, so this
    // pins the presented-side bound).
    let long_key_id = "k".repeat(129);
    let mut headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-long-key-id",
        now_secs(),
    );
    for (name, value) in &mut headers {
        if name == "x-dwara-key-id" {
            *value = long_key_id.clone();
        }
    }
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a 129-byte key id is malformed"
    );
}

#[tokio::test]
async fn same_nonce_under_two_key_ids_both_accepted_then_replay_rejected() {
    // The replay cache is keyed key_id + '\n' + nonce: identical nonce
    // VALUES under different keys are different cache entries. Pin the
    // scope end-to-end (the unit suite pins the cache primitive).
    let backend = async_echo_backend().await;
    let yaml = hmac_gateway_yaml("", backend).replace(
        &format!("      secret: {SECRET}\n"),
        &format!(
            "      secret: {SECRET}\n\
             - name: secondsigner\n\
             \x20 credentials:\n\
             \x20   - type: hmac\n\
             \x20     key_id: signer-key-2\n\
             \x20     secret: second-consumer-secret-0123456789abcdef\n"
        ),
    );
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;
    const NONCE: &str = "nonce-shared-across-keys";

    // Both keys present the SAME nonce value: both fresh.
    let first = sign(SECRET, KEY_ID, "GET", "/api/x", b"", NONCE, now_secs());
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &first).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("consumer=signer"), "{body}");

    let second = sign(
        "second-consumer-secret-0123456789abcdef",
        "signer-key-2",
        "GET",
        "/api/x",
        b"",
        NONCE,
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &second).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same nonce under another key is a different cache entry: {body}"
    );
    assert!(body.contains("consumer=secondsigner"), "{body}");

    // Replaying the FIRST key's request is still a replay under that
    // key (the second key's use did not un-burn it).
    let (status, _, _) = send_signed(port, "GET", "/api/x", b"", &first).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- gap coverage: hmac_auth without hmac credentials --------------------------

#[tokio::test]
async fn presented_signature_with_no_hmac_credentials_rejected_and_unsigned_flows() {
    // A gateway-wide hmac_auth block with ZERO hmac credentials is a
    // valid no-op policy; presenting a signature anyway is a credential
    // the gateway cannot verify — a 401 (the empty key map's documented
    // posture), while unsigned traffic flows anonymously.
    let backend = async_echo_backend().await;
    let yaml = hmac_gateway_yaml("hmac_auth:\n  max_clock_skew_secs: 60\n", backend)
        .replace(
            &format!("    - type: hmac\n      key_id: {KEY_ID}\n      secret: {SECRET}\n"),
            "    - type: api_key\n      key: sekrit-key\n",
        )
        .replace("- name: signer\n", "- name: keyuser\n");
    let dp = support::dataplane_from(&yaml);
    let port = spawn_gateway(dp).await;

    let client = support::h1_client();
    let resp = client
        .request(
            Request::builder()
                .uri(support::uri(port, "/api/x"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "unsigned traffic flows");

    let headers = sign(
        SECRET,
        KEY_ID,
        "GET",
        "/api/x",
        b"",
        "nonce-request-no-hmac-creds",
        now_secs(),
    );
    let (status, _, body) = send_signed(port, "GET", "/api/x", b"", &headers).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a presented signature with an empty key map is a 401: {body}"
    );
}
