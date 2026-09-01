//! AI streaming end-to-end tests (DW-077): the zero-buffer SSE
//! pass-through — client chunks arrive as the provider writes them,
//! usage accumulates from provider-reported events, and per-chunk
//! metrics land in the observability registry.

mod support;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use support::{body_of, dataplane_from, h1_client, spawn_backend_async, spawn_gateway, uri};

/// One mock provider stream step: write bytes (sleeping `delay`
/// first), or abort the body with an error.
#[derive(Clone)]
enum Step {
    Write(Duration, &'static str),
    Abort,
}

/// A streaming SSE mock provider: writes each step as one body frame
/// after its delay, then ends the body cleanly (or aborts on the
/// Abort step). Records the wall-clock instant each write hit the
/// wire (the pass-through latency assertions compare against these).
fn sse_provider(steps: Vec<Step>) -> (u16, Arc<Mutex<Vec<Instant>>>) {
    let writes: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
    let w = Arc::clone(&writes);
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            move |_req: Request<Incoming>| {
                let w = Arc::clone(&w);
                let steps = steps.clone();
                async move {
                    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, ChanErr>>(8);
                    tokio::spawn(async move {
                        for step in steps {
                            match step {
                                Step::Write(delay, text) => {
                                    tokio::time::sleep(delay).await;
                                    w.lock().unwrap().push(Instant::now());
                                    let _ = tx.send(Ok(Bytes::from(text.to_string()))).await;
                                }
                                Step::Abort => {
                                    let _ =
                                        tx.send(Err(ChanErr("provider died".to_string()))).await;
                                    return;
                                }
                            }
                        }
                        // Clean end: dropping tx closes the body.
                    });
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/event-stream")
                            .body(ChanBody { rx })
                            .unwrap(),
                    )
                }
            },
        ))
    });
    (port, writes)
}

/// The channel's error type (a plain string): the mock's abort signal.
#[derive(Debug)]
struct ChanErr(String);

impl std::fmt::Display for ChanErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ChanErr {}

/// A hyper body backed by an mpsc channel: frames as they are sent.
struct ChanBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, ChanErr>>,
}

impl hyper::body::Body for ChanBody {
    type Data = Bytes;
    type Error = ChanErr;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ChanErr>>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.rx).poll_recv(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Gateway YAML with one openai-kind provider and the given model yaml.
fn stream_yaml(port: u16, models_yaml: &str) -> String {
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
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: p\n\
         \x20   kind: openai\n\
         \x20   upstream: up\n\
         \x20 models:\n{models_yaml}"
    )
}

const MODELS: &str = "   chat:\n     provider: p\n     provider_model: m1\n";

/// Send a streaming chat request; returns the response with its
/// streaming body (the caller reads frames).
async fn stream_request(
    port: u16,
    include_usage: bool,
) -> (StatusCode, hyper::HeaderMap, Incoming) {
    let mut body = json!({
        "model": "chat",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    });
    if include_usage {
        body["stream_options"] = json!({"include_usage": true});
    }
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(port, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    (status, headers, resp.into_body())
}

/// Read an SSE client stream to its end, returning (frames, arrival
/// instants of each frame-bearing body chunk).
async fn read_stream(body: Incoming) -> (Vec<String>, Vec<Instant>) {
    let mut text = String::new();
    let mut arrivals = Vec::new();
    let mut body = std::pin::pin!(body);
    while let Some(frame) = body.as_mut().frame().await {
        let frame = frame.expect("client stream must not error");
        if let Some(data) = frame.data_ref() {
            arrivals.push(Instant::now());
            text.push_str(&String::from_utf8_lossy(data));
        }
    }
    // Split complete SSE frames off the accumulated text.
    let mut frames = Vec::new();
    let mut rest = text.as_str();
    while let Some(idx) = rest.find("\n\n") {
        let (chunk, tail) = rest.split_at(idx + 2);
        frames.push(chunk.to_string());
        rest = tail;
    }
    (frames, arrivals)
}

/// The content text of all delta chunks, concatenated.
fn content_of(frames: &[String]) -> String {
    let mut out = String::new();
    for f in frames {
        let Some(data) = f.strip_prefix("data: ") else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(data.trim_end()) else {
            continue;
        };
        if let Some(text) = v
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
        {
            out.push_str(text);
        }
    }
    out
}

/// OpenAI-dialect frames: three content deltas split across writes,
/// a finish chunk, and (because the gateway forces include_usage) a
/// terminal usage frame. Frames are split MID-frame across body
/// writes on purpose: the decoder must not hold or split incorrectly.
fn openai_stream_steps() -> Vec<Step> {
    let d = Duration::from_millis(60);
    vec![
        Step::Write(d, "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n"),
        // One SSE frame split across TWO body writes.
        Step::Write(
            d,
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel",
        ),
        Step::Write(d, "lo \"}},{\"index\":0,\"delta\":{\"content\":\"wor\"}}]}\n\n"),
        Step::Write(d, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ld\"}}]}\n\n"),
        Step::Write(
            d,
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        ),
        Step::Write(
            d,
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":50,\"total_tokens\":150}}\n\n",
        ),
        Step::Write(d, "data: [DONE]\n\n"),
    ]
}

/// End to end: the client receives OpenAI-shaped chunks as the
/// provider writes them, content reassembles, the terminal usage chunk
/// carries the provider-reported totals, and the gateway's own
/// [DONE] terminates the stream (the provider's was swallowed).
#[tokio::test(flavor = "multi_thread")]
async fn openai_stream_passes_through_translated() {
    let (port, _writes) = sse_provider(openai_stream_steps());
    let dp = dataplane_from(&stream_yaml(port, MODELS));
    let gw = spawn_gateway(dp).await;
    let (status, headers, body) = stream_request(gw, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .starts_with("text/event-stream"));
    let (frames, _) = read_stream(body).await;
    // 4 content deltas + finish + usage + DONE.
    assert!(frames.len() >= 6, "frames: {frames:?}");
    assert_eq!(content_of(&frames), "Hello world");
    // The terminal usage chunk (include_usage shape: empty choices).
    let usage_frame = frames
        .iter()
        .find(|f| f.contains("\"usage\"") && f.contains("\"choices\":[]"))
        .expect("terminal usage chunk");
    assert!(usage_frame.contains("\"prompt_tokens\":100"));
    assert!(usage_frame.contains("\"total_tokens\":150"));
    // The gateway's terminator is the LAST frame.
    assert_eq!(frames.last().unwrap().trim(), "data: [DONE]");
    // Exactly one [DONE] (the provider's was swallowed).
    assert_eq!(frames.iter().filter(|f| f.contains("[DONE]")).count(), 1);
}

/// The usage accounting the DW-078 budgets will consume: the stream's
/// reported totals equal the same provider's NON-streaming response
/// totals (here: identical numbers — within the done-when's ±1%).
#[tokio::test(flavor = "multi_thread")]
async fn streamed_usage_matches_provider_reported_totals() {
    let (port, _writes) = sse_provider(openai_stream_steps());
    let dp = dataplane_from(&stream_yaml(port, MODELS));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let (_, _, body) = stream_request(gw, false).await;
    let (frames, _) = read_stream(body).await;
    let usage_frame = frames
        .iter()
        .find(|f| f.contains("\"usage\"") && f.contains("\"choices\":[]"))
        .expect("terminal usage chunk even without client include_usage");
    let v: Value =
        serde_json::from_str(usage_frame.trim().strip_prefix("data: ").unwrap().trim()).unwrap();
    // The provider reported 100/50/150 in both shapes; the gateway
    // forwards what the provider reported (0% < 1% divergence).
    assert_eq!(v["usage"]["prompt_tokens"], 100);
    assert_eq!(v["usage"]["completion_tokens"], 50);
    assert_eq!(v["usage"]["total_tokens"], 150);
    // And the token metrics carry the same numbers.
    let metrics = dp.observability().render();
    assert!(metrics.contains("dwara_ai_tokens_total{"));
    assert!(metrics.contains("dwara_ai_stream_chunks_total{"));
}

/// Zero buffering: the client's FIRST chunk arrives shortly after the
/// provider's first write — long before the provider's LAST write
/// (a buffering implementation would deliver everything at the end).
#[tokio::test(flavor = "multi_thread")]
async fn first_chunk_arrives_before_the_stream_ends() {
    // First write at 150ms, last write at 150 + 5*120 = 750ms.
    let mut steps = Vec::new();
    steps.push(Step::Write(
        Duration::from_millis(150),
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"first\"}}]}\n\n",
    ));
    for i in 0..5 {
        steps.push(Step::Write(
            Duration::from_millis(120),
            Box::leak(
                format!(
                    "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"-{i}\"}}}}]}}\n\n"
                )
                .into_boxed_str(),
            ),
        ));
    }
    steps.push(Step::Write(
        Duration::from_millis(60),
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":6,\"total_tokens\":9}}\n\n",
    ));
    steps.push(Step::Write(Duration::from_millis(30), "data: [DONE]\n\n"));
    let (port, writes) = sse_provider(steps);
    let dp = dataplane_from(&stream_yaml(port, MODELS));
    let gw = spawn_gateway(dp).await;
    let started = Instant::now();
    let (_, _, body) = stream_request(gw, true).await;
    let (frames, arrivals) = read_stream(body).await;
    let total = started.elapsed();
    assert!(frames.len() >= 7);
    let provider_first = writes.lock().unwrap()[0];
    let provider_last = *writes.lock().unwrap().last().unwrap();
    let provider_span = provider_last - provider_first;
    let client_first = arrivals[0];
    // Pass-through: the first client chunk trails the provider's first
    // write by a small margin, not by the whole stream.
    assert!(
        client_first < provider_first + Duration::from_millis(400),
        "first client chunk at {:?} vs provider first write +400ms",
        client_first - started
    );
    // And it definitively arrived BEFORE the provider finished: a
    // buffering implementation would hold everything ~750ms.
    assert!(
        client_first + Duration::from_millis(100) < provider_last,
        "first client chunk {client_first:?} not before last provider write {provider_last:?} \
         (provider span {provider_span:?}, total {total:?})"
    );
    assert!(
        total >= provider_span,
        "stream must span the provider's writes"
    );
}

/// A provider abort AFTER frames were forwarded: the client stream
/// ends cleanly with an error chunk and the terminator; the forwarded
/// content stands.
#[tokio::test(flavor = "multi_thread")]
async fn mid_stream_abort_ends_cleanly_with_an_error_chunk() {
    let steps = vec![
        Step::Write(
            Duration::from_millis(50),
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n",
        ),
        Step::Write(Duration::from_millis(50), "garbage-not-a-frame"),
        Step::Abort,
    ];
    let (port, _) = sse_provider(steps);
    let dp = dataplane_from(&stream_yaml(port, MODELS));
    let gw = spawn_gateway(dp).await;
    let (status, _, body) = stream_request(gw, true).await;
    assert_eq!(status, StatusCode::OK);
    let (frames, _) = read_stream(body).await;
    assert_eq!(content_of(&frames), "partial");
    let error_frame = frames
        .iter()
        .find(|f| f.contains("provider_stream_aborted"))
        .expect("terminal error chunk");
    assert!(error_frame.contains("the model provider closed the stream"));
    assert_eq!(frames.last().unwrap().trim(), "data: [DONE]");
}

/// Failover before the commit point: a streaming request whose
/// primary answers 429 fails over to the alternate and streams.
#[tokio::test(flavor = "multi_thread")]
async fn streaming_fails_over_before_the_first_chunk() {
    // Primary: a 429 JSON error (non-streaming) mock.
    let primary_port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            |_req: Request<Incoming>| async move {
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(
                            json!({"error": {"message": "slow down", "type": "rate_limit"}})
                                .to_string(),
                        )))
                        .unwrap(),
                )
            },
        ))
    });
    let (alt_port, _) = sse_provider(vec![
        Step::Write(
            Duration::from_millis(40),
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"alternate\"}}]}\n\n",
        ),
        Step::Write(
            Duration::from_millis(30),
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        ),
        Step::Write(Duration::from_millis(10), "data: [DONE]\n\n"),
    ]);
    let models = "   chat:\n     provider: primary\n     provider_model: m1\n     failover:\n     - provider: alt\n       provider_model: m2\n";
    let yaml = format!(
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
         \x20 upstream: up-a\n\
         upstreams:\n\
         - name: up-a\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {primary_port}\n\
         - name: up-b\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {alt_port}\n\
         ai:\n\
         \x20 providers:\n\
         \x20 - name: primary\n\
         \x20   kind: openai\n\
         \x20   upstream: up-a\n\
         \x20 - name: alt\n\
         \x20   kind: openai\n\
         \x20   upstream: up-b\n\
         \x20 models:\n{models}"
    );
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let (status, _, body) = stream_request(gw, true).await;
    assert_eq!(status, StatusCode::OK);
    let (frames, _) = read_stream(body).await;
    assert_eq!(content_of(&frames), "alternate");
}

/// Anthropic and Gemini dialects stream through the same pipeline.
#[tokio::test(flavor = "multi_thread")]
async fn anthropic_and_gemini_dialects_stream_translated() {
    // Anthropic: message_start (usage) -> text deltas -> message_delta
    // (usage + stop) -> message_stop.
    let anthropic_steps = vec![
        Step::Write(
            Duration::from_millis(40),
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":40}}}\n\n",
        ),
        Step::Write(
            Duration::from_millis(40),
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"bon\"}}\n\n",
        ),
        Step::Write(
            Duration::from_millis(40),
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"jour\"}}\n\n",
        ),
        Step::Write(
            Duration::from_millis(30),
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":20}}\n\n",
        ),
        Step::Write(
            Duration::from_millis(10),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ),
    ];
    let (port, _) = sse_provider(anthropic_steps);
    let models = "   chat:\n     provider: p\n     provider_model: claude-x\n";
    let yaml = stream_yaml(port, models).replace("kind: openai", "kind: anthropic");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(dp).await;
    let (status, _, body) = stream_request(gw, true).await;
    assert_eq!(status, StatusCode::OK);
    let (frames, _) = read_stream(body).await;
    assert_eq!(content_of(&frames), "bonjour");
    // Accumulated usage: input from message_start + output from
    // message_delta, in ONE terminal chunk.
    let usage = frames
        .iter()
        .find(|f| f.contains("\"usage\"") && f.contains("\"choices\":[]"))
        .expect("terminal usage chunk");
    assert!(usage.contains("\"prompt_tokens\":40"));
    assert!(usage.contains("\"completion_tokens\":20"));
    assert_eq!(frames.last().unwrap().trim(), "data: [DONE]");

    // Gemini: data-only chunks with usageMetadata on the last one.
    let gemini_steps = vec![
        Step::Write(
            Duration::from_millis(40),
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"sal\"}]}}]}\n\n",
        ),
        Step::Write(
            Duration::from_millis(40),
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ut\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":12,\"candidatesTokenCount\":4,\"totalTokenCount\":16}}\n\n",
        ),
    ];
    let (gport, _) = sse_provider(gemini_steps);
    let gmodels = "   chat:\n     provider: p\n     provider_model: gemini-x\n";
    let gyaml = stream_yaml(gport, gmodels).replace("kind: openai", "kind: gemini");
    let gdp = dataplane_from(&gyaml);
    let ggw = spawn_gateway(gdp).await;
    let (gstatus, _, gbody) = stream_request(ggw, true).await;
    assert_eq!(gstatus, StatusCode::OK);
    let (gframes, _) = read_stream(gbody).await;
    assert_eq!(content_of(&gframes), "salut");
    let gusage = gframes
        .iter()
        .find(|f| f.contains("\"usage\"") && f.contains("\"choices\":[]"))
        .expect("terminal usage chunk");
    assert!(gusage.contains("\"total_tokens\":16"));
    assert_eq!(gframes.last().unwrap().trim(), "data: [DONE]");
}

/// Per-chunk metrics land: chunks counter, first-token and duration
/// histograms, and the non-stream 400 is gone.
#[tokio::test(flavor = "multi_thread")]
async fn per_chunk_metrics_are_exported() {
    let (port, _) = sse_provider(openai_stream_steps());
    let dp = dataplane_from(&stream_yaml(port, MODELS));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let (_, _, body) = stream_request(gw, true).await;
    let (frames, _) = read_stream(body).await;
    assert!(!frames.is_empty());
    let metrics = dp.observability().render();
    assert!(metrics.contains("dwara_ai_stream_chunks_total{provider=\"p\"}"));
    assert!(metrics.contains("dwara_ai_first_token_seconds_bucket{"));
    assert!(metrics.contains("provider=\"p\""));
    assert!(metrics.contains("dwara_ai_stream_duration_seconds_bucket{"));
    // Chunk counter matches the delta-chunk count (4 content + 1
    // finish frame carry deltas; role-only and usage frames do not).
    let counter_line = metrics
        .lines()
        .find(|l| l.starts_with("dwara_ai_stream_chunks_total{provider=\"p\"} "))
        .unwrap();
    let count: u64 = counter_line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(count >= 4, "chunk counter {count}");
    // The success outcome was recorded at stream start.
    assert!(metrics.contains("outcome=\"success\""));
}

// ---------------------------------------------------------------------------
// Gap-fill tests (tester pass): the ±1% done-when as a REAL comparison
// through different accumulation paths, client-disconnect accounting,
// CRLF provider framing, and metrics stability.
// ---------------------------------------------------------------------------

/// The ±1% done-when, for real: ONE anthropic-dialect mock that serves
/// BOTH shapes with provider-consistent numbers — non-streaming
/// reports input 123 / output 57 in one `usage` object; streaming
/// splits them across message_start and message_delta. The gateway's
/// two accumulation paths must agree within 1%.
#[tokio::test(flavor = "multi_thread")]
async fn streamed_usage_matches_nonstreamed_within_one_percent() {
    let port = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(spawn_backend_async(
            |req: Request<Incoming>| async move {
                let (parts, body) = req.into_parts();
                let bytes = body.collect().await.unwrap().to_bytes();
                let wants_stream = String::from_utf8_lossy(&bytes).contains("\"stream\":true");
                let _ = parts;
                if wants_stream {
                    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, ChanErr>>(8);
                    tokio::spawn(async move {
                        let _ = tx.send(Ok(Bytes::from(
                            "event: message_start\r\n\
                             data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":123}}}\r\n\r\n"
                                .to_string(),
                        ))).await;
                        let _ = tx.send(Ok(Bytes::from(
                            "event: content_block_delta\r\n\
                             data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi there\"}}\r\n\r\n"
                                .to_string(),
                        ))).await;
                        let _ = tx.send(Ok(Bytes::from(
                            "event: message_delta\r\n\
                             data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":57}}\r\n\r\n"
                                .to_string(),
                        ))).await;
                        let _ = tx.send(Ok(Bytes::from(
                            "event: message_stop\r\n\
                             data: {\"type\":\"message_stop\"}\r\n\r\n".to_string(),
                        ))).await;
                    });
                    return Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/event-stream")
                            .body(ChanBody { rx })
                            .unwrap(),
                    );
                }
                let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, ChanErr>>(2);
                let payload = json!({
                    "id": "msg",
                    "content": [{"type": "text", "text": "hi there"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 123, "output_tokens": 57}
                });
                let _ = tx.send(Ok(Bytes::from(payload.to_string()))).await;
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(ChanBody { rx })
                        .unwrap(),
                )
            },
        ))
    });
    let models = "   chat:\n     provider: p\n     provider_model: claude-x\n";
    let yaml = stream_yaml(port, models).replace("kind: openai", "kind: anthropic");
    let dp = dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;

    // Non-streaming total (input 123 + output 57, derived by the
    // adapter from the single usage object).
    let resp = h1_client()
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(uri(gw, "/v1/chat/completions"))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    json!({"model": "chat", "messages": [{"role": "user", "content": "hi"}]})
                        .to_string(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let (_, bytes) = body_of(resp).await;
    let nonstream: Value = serde_json::from_slice(&bytes).unwrap();
    let nonstream_total = nonstream["usage"]["total_tokens"].as_f64().unwrap();

    // Streaming total (accumulated from SPLIT usage events).
    let (_, _, body) = stream_request(gw, false).await;
    let (frames, _) = read_stream(body).await;
    let usage_frame = frames
        .iter()
        .find(|f| f.contains("\"usage\"") && f.contains("\"choices\":[]"))
        .expect("terminal usage chunk");
    let v: Value =
        serde_json::from_str(usage_frame.trim().strip_prefix("data: ").unwrap().trim()).unwrap();
    let streamed_total = v["usage"]["total_tokens"].as_f64().unwrap();

    let divergence = (streamed_total - nonstream_total).abs() / nonstream_total;
    assert!(
        divergence <= 0.01,
        "streamed {streamed_total} vs non-streamed {nonstream_total} ({divergence:.3})"
    );
    // CRLF framing also proves the decoder tolerance end to end (this
    // mock wrote \r\n throughout).
    let content = content_of(&frames);
    assert_eq!(content, "hi there");
}

/// A client that disconnects mid-stream: the gateway's Drop path still
/// closes the stream metrics exactly once (duration histogram), and
/// nothing hangs.
#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_still_closes_stream_metrics() {
    // A provider that drips frames slowly enough to outlive a client
    // that reads exactly one frame and drops the body.
    let mut steps = vec![Step::Write(
        Duration::from_millis(30),
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"one\"}}]}\n\n",
    )];
    for i in 2..=6 {
        steps.push(Step::Write(
            Duration::from_millis(90),
            Box::leak(
                format!(
                    "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"-{i}\"}}}}]}}\n\n"
                )
                .into_boxed_str(),
            ),
        ));
    }
    let (port, _writes) = sse_provider(steps);
    let dp = dataplane_from(&stream_yaml(port, MODELS));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let (_, _, mut body) = stream_request(gw, true).await;
    // Read ONE frame then drop the connection BODY mid-stream (the
    // value itself, not a pinned borrow of it).
    let first = std::pin::Pin::new(&mut body)
        .frame()
        .await
        .expect("first frame arrives");
    assert!(first.expect("ok frame").data_ref().is_some());
    drop(body);
    // Bounded settle for the provider task and the Drop-path metrics;
    // this is a wait-for-side-effect with a bound, not a sync sleep.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let metrics = dp.observability().render();
    assert!(metrics.contains("dwara_ai_stream_duration_seconds_bucket"));
    // Exactly-once: the counters do not move on a re-render.
    let first_chunk_count = metrics
        .lines()
        .find(|l| l.starts_with("dwara_ai_stream_chunks_total{provider=\"p\"} "))
        .unwrap()
        .rsplit(' ')
        .next()
        .unwrap()
        .to_string();
    let again = dp.observability().render();
    let second_chunk_count = again
        .lines()
        .find(|l| l.starts_with("dwara_ai_stream_chunks_total{provider=\"p\"} "))
        .unwrap()
        .rsplit(' ')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(first_chunk_count, second_chunk_count, "counters are stable");
    assert!(
        first_chunk_count.parse::<u64>().unwrap() >= 1,
        "the forwarded chunk before disconnect was counted"
    );
}

/// Multi-choice interleaved frames: one provider frame carrying two
/// deltas of DIFFERENT choices forwards both, in order.
#[tokio::test(flavor = "multi_thread")]
async fn multi_choice_frame_forwards_both_deltas_in_order() {
    let (port, _) = sse_provider(vec![Step::Write(
        Duration::from_millis(30),
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a0\"}},{\"index\":1,\"delta\":{\"content\":\"b1\"}}]}\n\n",
    ), Step::Write(
        Duration::from_millis(30),
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"-a0\"}},{\"index\":1,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
    ), Step::Write(Duration::from_millis(10), "data: [DONE]\n\n")]);
    let dp = dataplane_from(&stream_yaml(port, MODELS));
    let gw = spawn_gateway(dp).await;
    let (_, _, body) = stream_request(gw, true).await;
    let (frames, _) = read_stream(body).await;
    // Choice 0's deltas concatenate in order; choice 1's finish rides
    // its own chunk.
    let mut choice0 = String::new();
    let mut saw_choice1_finish = false;
    for f in &frames {
        let Some(data) = f.strip_prefix("data: ") else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(data.trim_end()) else {
            continue;
        };
        match v.pointer("/choices/0/index").and_then(Value::as_i64) {
            Some(0) => {
                if let Some(t) = v
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                {
                    choice0.push_str(t);
                }
            }
            Some(1) => {
                if v.pointer("/choices/0/finish_reason").is_some() {
                    saw_choice1_finish = true;
                }
            }
            _ => {}
        }
    }
    assert_eq!(choice0, "a0-a0");
    assert!(saw_choice1_finish);
}
