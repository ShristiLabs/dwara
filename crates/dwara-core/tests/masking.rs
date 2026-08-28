//! Response field masking (DW-029), end to end through the real
//! dataplane. The pointer/union grammar is pinned in
//! `tests/unit/transforms.rs`; this suite pins the PIPELINE posture:
//! the sentinel never leaks a configured field, the union with the
//! consumer's groups, the fail-closed 502 for every response the
//! gateway cannot prove clean (encoded, non-JSON, over-cap,
//! unparseable, pointer miss), the pass-through of bodiless and
//! gateway-authored responses, the ordering against compression
//! (DW-027) and operator transforms (DW-028), and the `dwara::policy`
//! audit trail.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CONTENT_ENCODING, CONTENT_TYPE};
use hyper::{Request, Response, StatusCode};

use support::{body_of, dataplane_from, envelope_code};

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// A backend serving one fixed JSON document (the leaky upstream).
async fn json_backend(body: &'static str) -> u16 {
    support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
        Ok(Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap())
    })
    .await
}

/// Gateway YAML with one prefix route carrying `route_extra`.
fn yaml(backend_port: u16, route_extra: &str) -> String {
    format!(
        r#"
routes:
  - name: m
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

async fn get(dp: &Arc<dwara_core::proxy::DataPlane>, path: &str) -> (StatusCode, Bytes) {
    let resp = dwara_core::proxy::handle(
        dp,
        ip(),
        Request::builder()
            .uri(path)
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    body_of(resp).await
}

async fn get_json(
    dp: &Arc<dwara_core::proxy::DataPlane>,
    path: &str,
) -> (StatusCode, serde_json::Value) {
    let (status, body) = get(dp, path).await;
    (
        status,
        serde_json::from_slice(&body).expect("client body is JSON"),
    )
}

/// A response body of fixed frames with UNKNOWN total size: hyper
/// serves it CHUNKED (no Content-Length), which pins the streaming arm
/// of the masking cap — the declared-length shortcut
/// (`size_hint().exact()`) never fires, so the frame-by-frame check in
/// `collect_capped` is the only guard under test.
struct ChunkedBody {
    frames: std::collections::VecDeque<Bytes>,
}

impl ChunkedBody {
    fn new(frames: &[&'static str]) -> ChunkedBody {
        ChunkedBody {
            frames: frames
                .iter()
                .map(|f| Bytes::from_static(f.as_bytes()))
                .collect(),
        }
    }
}

impl hyper::body::Body for ChunkedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(
            self.get_mut()
                .frames
                .pop_front()
                .map(|d| Ok(hyper::body::Frame::data(d))),
        )
    }
    // size_hint stays the default (unknown) — that is the point.
}

// --- the floor: fields masked for every consumer ---------------------------

#[tokio::test]
async fn masking_replaces_configured_fields_with_the_fixed_sentinel() {
    let port = json_backend(
        r#"{"user":{"email":"a@b.c","name":"ada"},"cards":[{"cvv":"123"}],"ok":true}"#,
    )
    .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields:
        - /user/email
        - /cards/0/cvv"#,
    ));
    let (status, doc) = get_json(&dp, "/api").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["user"]["email"], "***", "the sentinel is fixed");
    assert_eq!(doc["cards"][0]["cvv"], "***");
    assert_eq!(doc["user"]["name"], "ada", "untouched fields survive");
    assert_eq!(doc["ok"], true);
    // Framing: the declared length matches the masked body.
    let masked = serde_json::to_vec(&doc).unwrap();
    let resp = dwara_core::proxy::handle(
        &dp,
        ip(),
        Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        resp.headers().get("content-length").unwrap().as_bytes(),
        masked.len().to_string().as_bytes()
    );
}

// --- per consumer group: the union rule ------------------------------------

#[tokio::test]
async fn group_masking_adds_pointers_for_members_only() {
    let port =
        json_backend(r#"{"floor":"v","internal":{"margin":0.2},"user":{"email":"a@b.c"}}"#).await;
    let dp = dataplane_from(&format!(
        r#"
routes:
  - name: m
    service: svc
    match:
      path: {{ type: prefix, value: /api }}
    action: {{ type: proxy }}
    masking:
      max_bytes: 4096
      fields:
        - /floor
        - /user/email
      groups:
        partners:
          - /internal/margin
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
consumers:
  - name: partner-co
    groups: [partners]
    credentials:
      - {{ type: api_key, key: partner-key }}
"#
    ));
    // Anonymous: the floor alone.
    let (status, doc) = get_json(&dp, "/api").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["floor"], "***");
    assert_eq!(doc["user"]["email"], "***");
    assert_eq!(doc["internal"]["margin"], 0.2, "group pointer not applied");

    // The group member: floor + group additions (union, never less).
    let resp = dwara_core::proxy::handle(
        &dp,
        ip(),
        Request::builder()
            .uri("/api")
            .header("x-api-key", "partner-key")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["floor"], "***");
    assert_eq!(doc["user"]["email"], "***");
    assert_eq!(
        doc["internal"]["margin"], "***",
        "the group addition applies"
    );
}

// --- the inverted gates: everything unprovable fails closed -----------------

#[tokio::test]
async fn masking_fails_closed_on_encoded_and_non_json_responses() {
    // The DW-028 review's flagged surface: transforms pass through
    // content-encoded bodies; masking MUST NOT — the gateway cannot
    // prove fields absent from bytes it cannot read.
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_ENCODING, "gzip")
                .body(Full::new(Bytes::from_static(b"\x1f\x8b-not-really-gzip")))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/x]"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_mask_failed");

    // Non-JSON bodied responses (including SSE streams) are equally
    // unprovable: the masking route pins its proxied responses to the
    // JSON contract.
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "text/event-stream")
                .body(Full::new(Bytes::from_static(
                    b"data: {\"secret\":\"s\"}\n\n",
                )))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/x]"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_mask_failed");
}

#[tokio::test]
async fn masking_fails_closed_over_cap_invalid_json_and_pointer_misses() {
    let port = json_backend(r#"{"pad":"0123456789abcdef"}"#).await;
    // Declared length over a tiny cap: refused without reading.
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 8
      fields: [/pad]"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_mask_failed");

    // JSON-typed but unparseable.
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(b"not json")))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/x]"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_mask_failed");

    // Pointer miss: schema drift, the strict miss-is-the-leak rule.
    let port = json_backend(r#"{"other":1}"#).await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/secret]"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_mask_failed");
}

#[tokio::test]
async fn masking_passes_bodiless_statuses_and_gateway_authored_bodies() {
    // 204 has no body: nothing to leak, it passes.
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/x]"#,
    ));
    let (status, _) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A respond action is gateway-authored (operator config bytes, no
    // upstream data): masking does not apply to it, whatever the
    // content type.
    let dp = dataplane_from(
        r#"
routes:
  - name: fixed
    service: svc
    match:
      path: { type: prefix, value: /api }
    action:
      type: respond
      status: 200
    masking:
      max_bytes: 4096
      fields: [/never]
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{ address: 127.0.0.1, port: 1 }]
"#,
    );
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::OK, "respond body is not a leak surface");
    let _ = body;
}

#[tokio::test]
async fn masking_buffers_chunked_responses_and_refuses_them_over_cap() {
    // A chunked upstream response (no Content-Length) — the acceptance
    // list's unnamed-length case. Within the cap the frames are
    // buffered (split MID-VALUE to prove the buffer spans frames) and
    // masked: absence of a declared length never bypasses the policy.
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(ChunkedBody::new(&[r#"{"secret":"hu"#, r#"nter2","ok":1}"#]))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/secret]"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["secret"], "***", "chunked within cap is masked");
    assert_eq!(doc["ok"], 1);

    // Past the cap with NO declared length: the refusal must come from
    // the streaming check, not the size_hint shortcut.
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(ChunkedBody::new(&[r#"{"pad":"0123"#, r#"456789abcdef"}"#]))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 8
      fields: [/pad]"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_mask_failed");
}

// --- ordering: before compression (DW-027), before transforms (DW-028) -----

#[tokio::test]
async fn masking_runs_before_the_gateways_own_compression() {
    // The DW-027 interaction: the gateway's compression runs AFTER
    // masking in the tail, so a masked response still compresses (the
    // encoding gate only trips on UPSTREAM-pre-encoded bodies).
    let port =
        json_backend(r#"{"secret":"hunter2","pad":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#).await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/secret]
    compression:
      min_size: 8
      content_types: ["application/json"]"#,
    ));
    let resp = dwara_core::proxy::handle(
        &dp,
        ip(),
        Request::builder()
            .uri("/api")
            .header("accept-encoding", "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(CONTENT_ENCODING).unwrap(),
        "gzip",
        "the gateway compressed the MASKED body"
    );
    let (_, body) = body_of(resp).await;
    let mut decoder = flate2::read::GzDecoder::new(&body[..]);
    let mut plain = String::new();
    std::io::Read::read_to_string(&mut decoder, &mut plain).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&plain).unwrap();
    assert_eq!(doc["secret"], "***", "the secret never left the gateway");
    assert_eq!(doc["pad"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

#[tokio::test]
async fn masking_runs_before_operator_response_transforms() {
    // Order proof via the strictness rule: the transform REMOVES the
    // very field masking addresses. Masking first -> the pointer
    // resolves (value becomes the sentinel), the removal then drops
    // the field -> 200 without it. Transform first -> masking would
    // hit an unresolved pointer -> 502. The 200 pins the order.
    let port = json_backend(r#"{"secret":"hunter2","keep":1}"#).await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/secret]
    transforms:
      response:
        body:
          json:
            max_bytes: 4096
            ops:
              - { op: remove, path: /secret }"#,
    ));
    let (status, body) = get(&dp, "/api").await;
    assert_eq!(status, StatusCode::OK, "masking ran before the transform");
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(doc.get("secret").is_none());
    assert_eq!(doc["keep"], 1);
}

// --- the audit trail --------------------------------------------------------

type CapturedEvent = (String, Vec<(String, String)>);

#[derive(Clone, Default)]
struct Capture {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S> tracing_subscriber::Layer<S> for Capture
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap()
            .push((event.metadata().target().to_string(), visitor.fields));
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

/// Install the capture as the PROCESS-global tracing default. The
/// per-thread `set_default` the maintenance suite uses is fine for its
/// single-threaded emission sites; masking's events ride the response
/// tail, whose polling under the concurrent test harness is not
/// guaranteed to stay on the installing thread — a global default
/// makes capture deterministic, and the per-request assertions below
/// filter by the request-id so sibling tests' events (which also land
/// here) cannot perturb the counts.
fn capture() -> Capture {
    use tracing_subscriber::prelude::*;
    let cap = Capture::default();
    let _ =
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(cap.clone()));
    cap
}

fn policy_events(cap: &Capture, code: &str, request_id: &str) -> Vec<Vec<(String, String)>> {
    cap.events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, fields)| {
            t == "dwara::policy"
                && fields.iter().any(|(n, v)| n == "code" && v == code)
                && fields
                    .iter()
                    .any(|(n, v)| n == "request_id" && v == request_id)
        })
        .cloned()
        .map(|(_, f)| f)
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
    &fields
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("field {name} missing in {fields:?}"))
        .1
}

#[tokio::test]
async fn masking_emits_the_dwara_policy_audit_trail() {
    // Success: one info event per masked response carrying route,
    // consumer, count, and the request-id correlation key. The
    // caller-chosen request-id is both asserted ON the event and used
    // to pick THIS request's events out of the capture (sibling tests
    // mask too, and the capture is process-global by design).
    let cap = capture();
    let port = json_backend(r#"{"secret":"hunter2","also":"v","keep":1}"#).await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/secret, /also]"#,
    ));
    let resp = dwara_core::proxy::handle(
        &dp,
        ip(),
        Request::builder()
            .uri("/api")
            .header("x-request-id", "mask-audit-1")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["secret"], "***");
    let events = policy_events(&cap, "response_masked", "mask-audit-1");
    assert_eq!(events.len(), 1, "one audit event per masked response");
    let e = &events[0];
    assert_eq!(field(e, "route"), "m");
    assert_eq!(field(e, "consumer"), "anonymous");
    assert_eq!(field(e, "masked"), "2");
    assert_eq!(field(e, "request_id"), "mask-audit-1");

    // Refusal: one warn event naming the refusal class, server-side
    // only (the client envelope stays generic).
    let port =
        support::spawn_backend_async(move |_req: Request<hyper::body::Incoming>| async move {
            Ok(Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_ENCODING, "br")
                .body(Full::new(Bytes::from_static(b"encoded-bytes")))
                .unwrap())
        })
        .await;
    let dp = dataplane_from(&yaml(
        port,
        r#"    masking:
      max_bytes: 4096
      fields: [/x]"#,
    ));
    let resp = dwara_core::proxy::handle(
        &dp,
        ip(),
        Request::builder()
            .uri("/api")
            .header("x-request-id", "mask-audit-2")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (status, body) = body_of(resp).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope_code(&body), "response_mask_failed");
    let events = policy_events(&cap, "response_mask_failed", "mask-audit-2");
    assert_eq!(events.len(), 1);
    let reason = field(&events[0], "reason");
    assert!(
        reason.contains("content-encoded"),
        "the refusal class names the encoding gate: {reason}"
    );
}

// --- config validation: fail-closed at publish ------------------------------

#[test]
fn masking_validation_rejects_drift_prone_config() {
    use dwara_core::config::parse_gateway;
    use dwara_core::snapshot::CompileError;
    let base = |masking: &str| {
        format!(
            "routes:\n  - name: m\n    service: svc\n    match:\n      path: {{ type: prefix, value: /api }}\n    action: {{ type: proxy }}\n{masking}\nservices:\n  - name: svc\n    upstream: up\nupstreams:\n  - name: up\n    endpoints: [{{ address: 127.0.0.1, port: 1 }}]\n"
        )
    };
    // (masking YAML, the offending field the issue must NAME, message
    // fragment) — the field locator is the operator's only way to the
    // bad line, so it is pinned as tightly as the message.
    let cases: [(&str, &str, &str); 7] = [
        (
            // Nothing masked: an authoring mistake.
            "    masking:\n      max_bytes: 100\n",
            "masking",
            "nothing to mask",
        ),
        (
            // Zero cap fails every response.
            "    masking:\n      max_bytes: 0\n      fields: [/a]\n",
            "masking.max_bytes",
            "max_bytes must be > 0",
        ),
        (
            // Malformed pointer.
            "    masking:\n      max_bytes: 100\n      fields: [no-slash]\n",
            "masking.fields[0]",
            "RFC 6901",
        ),
        (
            // The root pointer would replace the whole document.
            "    masking:\n      max_bytes: 100\n      fields: ['']\n",
            "masking.fields[0]",
            "root pointer",
        ),
        (
            // A typo'd group silently never masks: fail-open config.
            "    masking:\n      max_bytes: 100\n      fields: [/a]\n      groups:\n        partners: [/b]\n",
            "masking.groups",
            "matches no configured consumer",
        ),
        (
            // An empty group entry is an authoring mistake.
            "    masking:\n      max_bytes: 100\n      fields: [/a]\n      groups:\n        g: []\n",
            "masking.groups",
            "carries no pointers",
        ),
        (
            // A malformed pointer inside a group entry.
            "    masking:\n      max_bytes: 100\n      fields: [/a]\n      groups:\n        g: [oops]\n",
            "masking.groups.g[0]",
            "RFC 6901",
        ),
    ];
    for (masking, want_field, want_msg) in cases {
        let gateway = parse_gateway(&base(masking)).expect("syntax parses");
        let state = dwara_core::snapshot::ConfigState::new();
        let err = state.compile_and_publish(&gateway).expect_err("rejected");
        let CompileError::Validation(issues) = err else {
            panic!("expected validation issues for '{masking}'");
        };
        assert!(
            issues
                .iter()
                .any(|i| i.field == want_field && i.message.contains(want_msg)),
            "case '{masking}' should name field '{want_field}' with '{want_msg}'; got {issues:?}"
        );
    }
}
