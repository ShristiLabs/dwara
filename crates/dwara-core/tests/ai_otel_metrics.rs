//! AI-07 integration tests: OTel GenAI semantic-convention span
//! attributes and the new AI metric families on the `/metrics` surface.
//!
//! Drives `proxy::handle` directly against an in-process mock provider
//! and asserts:
//!
//! - the `gen_ai.chat` span exists and carries the gen_ai.* attributes
//!   (system, request.model, request.max_tokens, response.model,
//!   usage.*, response.finish_reasons, response.id);
//! - `dwara_ai_request_duration_seconds{provider,route}` is emitted
//!   with the serving provider and route labels;
//! - `dwara_ai_tokens_per_request{provider,model,kind}` is emitted with
//!   both `prompt` and `completion` kind series;
//! - the existing TTFT histogram `dwara_ai_first_token_seconds{provider}`
//!   remains a histogram (bucket series present) for streaming.
//!
//! Span capture uses `set_global_default` (the proxy may move the
//! request future across worker threads on the multi-thread runtime),
//! so the two tests are serialized with `serial_test` to keep their
//! spans from interleaving in the shared capture.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use serde_json::json;
use support::{dataplane_from, spawn_backend_async};
use tracing_subscriber::layer::SubscriberExt as _;

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

// --- capturing subscriber --------------------------------------------------

#[derive(Default)]
struct FieldVisitor {
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

/// Per-span field list: (field name, stringified value).
type SpanFields = Vec<(String, String)>;

/// A capturing layer that stores per-span fields in a shared vec. Fields
/// recorded later via `Span::record` (the gen_ai.* response attributes)
/// are appended and folded so the last value wins.
#[derive(Clone, Default)]
struct FieldCapture {
    spans: Arc<Mutex<Vec<(String, SpanFields)>>>,
}

impl FieldCapture {
    fn fields_of(&self, name: &str) -> Vec<(String, String)> {
        let spans = self.spans.lock().unwrap();
        let (_, fields) = spans.iter().find(|(n, _)| n == name).unwrap_or_else(|| {
            panic!(
                "span {name} not captured; spans: {:?}",
                spans.iter().map(|(n, _)| n).collect::<Vec<_>>()
            )
        });
        let mut folded: Vec<(String, String)> = Vec::new();
        for (k, v) in fields {
            if let Some(existing) = folded.iter_mut().find(|(ek, _)| ek == k) {
                existing.1 = v.clone();
            } else {
                folded.push((k.clone(), v.clone()));
            }
        }
        folded
    }
}

impl<S> tracing_subscriber::Layer<S> for FieldCapture
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);
        self.spans
            .lock()
            .unwrap()
            .push((attrs.metadata().name().to_string(), visitor.fields));
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        attrs: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);
        let name = ctx.metadata(span).map(|m| m.name()).unwrap_or("");
        let mut spans = self.spans.lock().unwrap();
        if let Some(entry) = spans.iter_mut().rev().find(|(n, _)| n == name) {
            entry.1.extend(visitor.fields);
        }
    }
}

/// The process-global span capture. `set_global_default` can only
/// succeed once per process, so the capture is shared across tests in
/// this binary. Each test clears the shared vec before it starts; the
/// `serial_test` attribute keeps the two tests from interleaving.
static GLOBAL_CAPTURE: OnceLock<FieldCapture> = OnceLock::new();

fn capture_spans() -> FieldCapture {
    GLOBAL_CAPTURE
        .get_or_init(|| {
            let cap = FieldCapture::default();
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(cap.clone()),
            );
            cap
        })
        .clone()
}

fn clear_spans(cap: &FieldCapture) {
    cap.spans.lock().unwrap().clear();
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
    &fields
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("field {name} missing in {fields:?}"))
        .1
}

/// Assert every needle substring is present in the haystack (order-
/// independent, so prometheus's alphabetical label rendering does not
/// make the assertion brittle).
fn has_all(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().all(|n| haystack.contains(n))
}

// --- mock provider + config ------------------------------------------------

/// A mock OpenAI provider that answers a canned success body with usage
/// and a finish reason.
async fn mock_openai_provider() -> u16 {
    spawn_backend_async(move |req: Request<Incoming>| async move {
        let (_parts, body) = req.into_parts();
        let _ = body.collect().await.unwrap().to_bytes();
        let resp = json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}
        });
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(resp.to_string())))
                .unwrap(),
        )
    })
    .await
}

fn ai_yaml(openai_port: u16) -> String {
    format!(
        "routes:\n\
         - name: chat\n\
         \x20 service: ai-svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: ai\n\
         services:\n\
         - name: ai-svc\n\
         \x20 upstream: openai-pool\n\
         upstreams:\n\
         - name: openai-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {openai_port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: openai\n\
         \x20   kind: openai\n\
         \x20   upstream: openai-pool\n\
         \x20   auth:\n\
         \x20     header: Authorization\n\
         \x20     value: Bearer sk-openai-test\n\
         \x20 models:\n\
         \x20   gpt-4o-mini:\n\
         \x20     provider: openai\n\
         \x20     provider_model: gpt-4o-mini-2024-07-18\n"
    )
}

fn ai_post(body: serde_json::Value) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

async fn body_text(resp: hyper::Response<dwara_core::proxy::ProxyBody>) -> String {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body read")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

// --- tests -----------------------------------------------------------------

/// A successful non-streaming AI request emits the gen_ai.* span
/// attributes and the new AI-07 metric families with correct labels.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread")]
async fn gen_ai_span_attributes_and_new_metrics_on_success() {
    let openai_port = mock_openai_provider().await;
    let dp = dataplane_from(&ai_yaml(openai_port));
    let cap = capture_spans();
    clear_spans(&cap);

    let resp = dwara_core::proxy::handle(
        &dp,
        peer(),
        ai_post(json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 64,
            "temperature": 0.7,
            "top_p": 0.9
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = body_text(resp).await;

    // gen_ai.* span attributes (AI-07).
    let fields = cap.fields_of("gen_ai.chat");
    assert_eq!(field(&fields, "gen_ai.system"), "openai");
    assert_eq!(field(&fields, "gen_ai.request.model"), "gpt-4o-mini");
    assert_eq!(field(&fields, "gen_ai.request.max_tokens"), "64");
    assert_eq!(field(&fields, "gen_ai.request.temperature"), "0.7");
    assert_eq!(field(&fields, "gen_ai.request.top_p"), "0.9");
    assert_eq!(
        field(&fields, "gen_ai.response.model"),
        "gpt-4o-mini-2024-07-18"
    );
    assert_eq!(field(&fields, "gen_ai.usage.prompt_tokens"), "11");
    assert_eq!(field(&fields, "gen_ai.usage.completion_tokens"), "3");
    assert_eq!(field(&fields, "gen_ai.usage.total_tokens"), "14");
    assert_eq!(field(&fields, "gen_ai.response.id"), "chatcmpl-mock");
    assert_eq!(field(&fields, "gen_ai.response.finish_reasons"), "stop");

    // New AI-07 metric families with correct labels (prometheus renders
    // labels alphabetically, so check substrings order-independently).
    let metrics = dp.observability().render();
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_request_duration_seconds_bucket{",
                "provider=\"openai\"",
                "route=\"chat\"",
            ]
        ),
        "request_duration histogram missing or mislabeled"
    );
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_tokens_per_request_bucket{",
                "provider=\"openai\"",
                "model=\"gpt-4o-mini-2024-07-18\"",
                "kind=\"prompt\"",
            ]
        ),
        "tokens_per_request prompt series missing or mislabeled"
    );
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_tokens_per_request_bucket{",
                "provider=\"openai\"",
                "model=\"gpt-4o-mini-2024-07-18\"",
                "kind=\"completion\"",
            ]
        ),
        "tokens_per_request completion series missing or mislabeled"
    );
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_request_duration_seconds_count{",
                "provider=\"openai\"",
                "route=\"chat\"",
            ]
        ),
        "request_duration count missing"
    );
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_tokens_per_request_count{",
                "provider=\"openai\"",
                "model=\"gpt-4o-mini-2024-07-18\"",
                "kind=\"prompt\"",
            ]
        ),
        "tokens_per_request prompt count missing"
    );
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_tokens_per_request_count{",
                "provider=\"openai\"",
                "model=\"gpt-4o-mini-2024-07-18\"",
                "kind=\"completion\"",
            ]
        ),
        "tokens_per_request completion count missing"
    );
}

/// The TTFT histogram `dwara_ai_first_token_seconds{provider}` remains
/// a histogram (bucket + count series) for a streaming request, and the
/// streaming path also records the new AI-07 histograms.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread")]
async fn ttft_histogram_present_for_streaming() {
    let port = spawn_backend_async(move |req: Request<Incoming>| async move {
        let (_parts, body) = req.into_parts();
        let _ = body.collect().await.unwrap().to_bytes();
        let frames = [
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n",
            "data: [DONE]\n\n",
        ]
        .join("");
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Full::new(Bytes::from(frames)))
                .unwrap(),
        )
    })
    .await;
    let dp = dataplane_from(&ai_yaml(port));

    let resp = dwara_core::proxy::handle(
        &dp,
        peer(),
        ai_post(json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // Drain the stream so the stream body's close() fires.
    let _ = body_text(resp).await;

    let metrics = dp.observability().render();
    // TTFT is a histogram: bucket, count, sum series all present.
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_first_token_seconds_bucket{",
                "provider=\"openai\"",
            ]
        ),
        "TTFT histogram bucket missing"
    );
    assert!(
        has_all(
            &metrics,
            &["dwara_ai_first_token_seconds_count{", "provider=\"openai\"",]
        ),
        "TTFT histogram count missing"
    );
    // Streaming also records the request_duration histogram at commit.
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_request_duration_seconds_count{",
                "provider=\"openai\"",
                "route=\"chat\"",
            ]
        ),
        "streaming request_duration count missing"
    );
    // Streaming tokens_per_request (terminal usage reported).
    assert!(
        has_all(
            &metrics,
            &[
                "dwara_ai_tokens_per_request_count{",
                "provider=\"openai\"",
                "model=\"gpt-4o-mini-2024-07-18\"",
                "kind=\"prompt\"",
            ]
        ),
        "streaming tokens_per_request prompt count missing"
    );
}
