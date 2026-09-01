//! The Anthropic messages adapter (DW-075).
//!
//! Speaks the Anthropic messages API (`POST /v1/messages`). The
//! translation is the deepest of the three dialects:
//!
//! - System messages lift to the top-level `system` field (joined with
//!   a blank line when several appear).
//! - Tool RESULTS (OpenAI `role: tool` messages) become USER turns
//!   carrying a `tool_result` content block; assistant tool calls
//!   become `tool_use` blocks whose `input` is the parsed arguments
//!   object.
//! - `max_tokens` is REQUIRED by Anthropic and absent from many OpenAI
//!   client calls: the adapter substitutes
//!   [`DEFAULT_MAX_TOKENS`] and says so in the module docs — the
//!   provider refuses an unbounded generation, so a floor is the only
//!   way to honor the request at all.
//! - Finish reasons map `end_turn`/`stop_sequence` -> stop,
//!   `max_tokens` -> length, `tool_use` -> tool calls,
//!   `refusal` -> content filter.
//! - Usage maps `input_tokens`/`output_tokens` to
//!   prompt/completion; `total` is derived (sum) because Anthropic
//!   does not send one.
//!
//! Streaming (verified in tests, wired at the gateway in DW-077): the
//! messages-API SSE stream (`message_start` -> `content_block_*` ->
//! `message_delta` -> `message_stop`) translates event-by-event; tool
//! argument fragments arrive as `input_json_delta.partial_json` and
//! are re-expressed as OpenAI-style argument-fragment deltas.

use crate::ai::adapter::{AiError, ProviderAdapter, ProviderErrorBody, ProviderRequest};
use crate::ai::types::{
    ChatMessage, ChatRequest, ChatResponse, ChatRole, Choice, ContentPart, FinishReason,
    StreamDelta, StreamEvent, ToolCall, ToolCallDelta, Usage,
};
use crate::config::ai::AiProviderKind;
use serde_json::{json, Map, Value};

/// The `max_tokens` the adapter substitutes when the client did not
/// send one. Anthropic requires the field; OpenAI clients usually omit
/// it. 4096 is a conservative default that no provider rejects.
pub const DEFAULT_MAX_TOKENS: u64 = 4096;

/// The Anthropic messages adapter. Stateless singleton.
pub struct AnthropicAdapter;

impl ProviderAdapter for AnthropicAdapter {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::Anthropic
    }

    fn build_request(
        &self,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<ProviderRequest, AiError> {
        let mut body = Map::new();
        body.insert("model".into(), json!(provider_model));
        // System messages lift out of the conversation.
        let system: Vec<String> = req
            .messages
            .iter()
            .filter(|m| m.role == ChatRole::System)
            .map(|m| m.text_content())
            .filter(|s| !s.is_empty())
            .collect();
        if !system.is_empty() {
            body.insert("system".into(), json!(system.join("\n\n")));
        }
        let mut messages: Vec<Value> = Vec::new();
        for m in &req.messages {
            match m.role {
                ChatRole::System => continue,
                ChatRole::User | ChatRole::Assistant => messages.push(json!({
                    "role": if m.role == ChatRole::User { "user" } else { "assistant" },
                    "content": message_content_blocks(m),
                })),
                ChatRole::Tool => {
                    // A tool result is a USER turn with a tool_result
                    // block. Anthropic wants the originating tool_use
                    // id; the OpenAI shape only carries tool_call_id,
                    // which IS that id. A tool message without one is
                    // an unanswerable conversation — reject precisely
                    // rather than serializing an empty id the provider
                    // would reject opaquely.
                    let Some(tool_call_id) = m.tool_call_id.as_deref() else {
                        return Err(AiError::InvalidRequest(
                            "a tool message carries no tool_call_id (the id that \
                             names the call it answers)"
                                .to_string(),
                        ));
                    };
                    let text = m.text_content();
                    messages.push(json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": tool_call_id,
                            "content": if text.is_empty() { Value::Null } else { json!(text) },
                        }],
                    }));
                }
            }
        }
        if messages.is_empty() {
            return Err(AiError::InvalidRequest(
                "the conversation has no non-system messages".to_string(),
            ));
        }
        // Anthropic requires alternating user/assistant turns starting
        // with user; consecutive same-role turns merge.
        let messages = merge_consecutive_turns(messages);
        body.insert("messages".into(), Value::Array(messages));
        body.insert(
            "max_tokens".into(),
            json!(req.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS)),
        );
        if !req.tools.is_empty() {
            let tools: Vec<Value> = req
                .tools
                .iter()
                .map(|t| {
                    let mut o = Map::new();
                    o.insert("name".into(), json!(t.name));
                    if let Some(d) = &t.description {
                        o.insert("description".into(), json!(d));
                    }
                    o.insert(
                        "input_schema".into(),
                        t.parameters
                            .clone()
                            .unwrap_or_else(|| json!({"type": "object"})),
                    );
                    Value::Object(o)
                })
                .collect();
            body.insert("tools".into(), Value::Array(tools));
            if let Some(choice) = &req.tool_choice {
                match choice {
                    crate::ai::types::ToolChoice::Auto => {
                        body.insert("tool_choice".into(), json!({"type": "auto"}));
                    }
                    crate::ai::types::ToolChoice::None => {
                        // Anthropic has no "none": omitting
                        // tool_choice with tools declared still lets
                        // the model call them. The honest translation
                        // of "none" is dropping the tools entirely.
                        body.remove("tools");
                    }
                    crate::ai::types::ToolChoice::Any => {
                        body.insert("tool_choice".into(), json!({"type": "any"}));
                    }
                    crate::ai::types::ToolChoice::Tool(name) => {
                        body.insert("tool_choice".into(), json!({"type": "tool", "name": name}));
                    }
                }
            }
        }
        if let Some(t) = req.temperature {
            body.insert("temperature".into(), json!(t));
        }
        if let Some(p) = req.top_p {
            body.insert("top_p".into(), json!(p));
        }
        if let Some(stop) = &req.stop {
            body.insert("stop_sequences".into(), json!(stop));
        }
        if req.stream {
            body.insert("stream".into(), json!(true));
        }
        Ok(ProviderRequest {
            method: http::Method::POST,
            path: "/v1/messages".to_string(),
            headers: vec![
                (http::header::CONTENT_TYPE, "application/json".to_string()),
                // Anthropic requires both version and (for newer
                // features) the beta header is NOT needed here.
                (
                    http::HeaderName::from_static("anthropic-version"),
                    "2023-06-01".to_string(),
                ),
            ],
            body: Value::Object(body),
        })
    }

    fn parse_response(&self, body: &Value) -> Result<ChatResponse, AiError> {
        let obj = body.as_object().ok_or_else(|| {
            AiError::Translation("anthropic response is not a JSON object".to_string())
        })?;
        let content = obj
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| AiError::Translation("anthropic response has no content".to_string()))?;
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        let mut image_parts = Vec::new();
        for block in content {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => text.push_str(
                    block
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                Some("tool_use") => tool_calls.push(ToolCall {
                    id: block
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    name: block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    arguments: block
                        .get("input")
                        .cloned()
                        .unwrap_or(Value::Null)
                        .to_string(),
                }),
                Some("image") => {
                    let source = block.get("source").cloned().unwrap_or(Value::Null);
                    image_parts.push(ContentPart::Image {
                        url: None,
                        // source.type is the ENCODING ("base64"); the
                        // media type lives in source.media_type and is
                        // only derived from source.type when absent.
                        media_type: source
                            .get("media_type")
                            .and_then(Value::as_str)
                            .map(String::from)
                            .or_else(|| {
                                source
                                    .get("type")
                                    .and_then(Value::as_str)
                                    .map(|t| format!("image/{t}"))
                            }),
                        data_b64: source.get("data").and_then(Value::as_str).map(String::from),
                    });
                }
                _ => {}
            }
        }
        let mut message_content: Vec<ContentPart> = vec![ContentPart::Text { text }];
        message_content.extend(image_parts);
        let usage = obj.get("usage").map(|u| Usage {
            prompt_tokens: u.get("input_tokens").and_then(Value::as_u64),
            completion_tokens: u.get("output_tokens").and_then(Value::as_u64),
            total_tokens: match (
                u.get("input_tokens").and_then(Value::as_u64),
                u.get("output_tokens").and_then(Value::as_u64),
            ) {
                (Some(i), Some(o)) => Some(i + o),
                (i, o) => i.or(o),
            },
        });
        let finish_reason = match obj.get("stop_reason").and_then(Value::as_str) {
            Some("end_turn") | Some("stop_sequence") | None => FinishReason::Stop,
            Some("max_tokens") => FinishReason::Length,
            Some("tool_use") => FinishReason::ToolCalls,
            Some("refusal") => FinishReason::ContentFilter,
            Some(other) => FinishReason::Other(other.to_string()),
        };
        Ok(ChatResponse {
            id: obj.get("id").and_then(Value::as_str).map(String::from),
            model: obj.get("model").and_then(Value::as_str).map(String::from),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: ChatRole::Assistant,
                    content: message_content,
                    name: None,
                    tool_calls,
                    tool_call_id: None,
                },
                finish_reason,
            }],
            usage,
        })
    }

    fn parse_error(&self, body: &Value) -> ProviderErrorBody {
        // Anthropic: {"type": "error", "error": {"type", "message"}}.
        let e = body
            .get("error")
            .and_then(|e| e.as_object())
            .or_else(|| body.as_object());
        ProviderErrorBody {
            message: e
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("provider returned an error")
                .to_string(),
            error_type: e
                .and_then(|e| e.get("type"))
                .and_then(Value::as_str)
                .map(String::from),
            code: None,
        }
    }

    fn parse_stream_event(&self, data: &Value) -> Result<Vec<StreamEvent>, AiError> {
        let obj = data.as_object().ok_or_else(|| {
            AiError::Translation("anthropic stream event is not a JSON object".to_string())
        })?;
        let kind = obj.get("type").and_then(Value::as_str).unwrap_or("");
        let mut out = Vec::new();
        match kind {
            "message_start" => {
                // The opening event carries input token usage.
                if let Some(u) = obj.get("message").and_then(|m| m.get("usage")) {
                    out.push(StreamEvent::Usage(Usage {
                        prompt_tokens: u.get("input_tokens").and_then(Value::as_u64),
                        completion_tokens: None,
                        total_tokens: None,
                    }));
                }
                // First delta carries the role, OpenAI-style.
                out.push(StreamEvent::Delta(StreamDelta {
                    index: 0,
                    role: Some(ChatRole::Assistant),
                    content: None,
                    tool_calls: Vec::new(),
                    finish_reason: None,
                }));
            }
            "content_block_start" => {
                let index = obj.get("index").and_then(Value::as_u64).unwrap_or(0);
                if let Some(block) = obj.get("content_block") {
                    if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                        out.push(StreamEvent::Delta(StreamDelta {
                            index: 0,
                            role: None,
                            content: None,
                            tool_calls: vec![ToolCallDelta {
                                index,
                                id: block.get("id").and_then(Value::as_str).map(String::from),
                                name: block.get("name").and_then(Value::as_str).map(String::from),
                                arguments: String::new(),
                            }],
                            finish_reason: None,
                        }));
                    }
                }
            }
            "content_block_delta" => {
                let index = obj.get("index").and_then(Value::as_u64).unwrap_or(0);
                let delta = obj.get("delta").cloned().unwrap_or(Value::Null);
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => out.push(StreamEvent::Delta(StreamDelta {
                        index: 0,
                        role: None,
                        content: delta.get("text").and_then(Value::as_str).map(String::from),
                        tool_calls: Vec::new(),
                        finish_reason: None,
                    })),
                    Some("input_json_delta") => out.push(StreamEvent::Delta(StreamDelta {
                        index: 0,
                        role: None,
                        content: None,
                        tool_calls: vec![ToolCallDelta {
                            index,
                            id: None,
                            name: None,
                            arguments: delta
                                .get("partial_json")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        }],
                        finish_reason: None,
                    })),
                    _ => {}
                }
            }
            "message_delta" => {
                let delta = obj.get("delta").cloned().unwrap_or(Value::Null);
                let finish = match delta.get("stop_reason").and_then(Value::as_str) {
                    Some("end_turn") | Some("stop_sequence") => FinishReason::Stop,
                    Some("max_tokens") => FinishReason::Length,
                    Some("tool_use") => FinishReason::ToolCalls,
                    Some("refusal") => FinishReason::ContentFilter,
                    other => other
                        .map(|s| FinishReason::Other(s.to_string()))
                        .unwrap_or(FinishReason::Stop),
                };
                out.push(StreamEvent::Delta(StreamDelta {
                    index: 0,
                    role: None,
                    content: None,
                    tool_calls: Vec::new(),
                    finish_reason: Some(finish),
                }));
                if let Some(u) = obj.get("usage") {
                    out.push(StreamEvent::Usage(Usage {
                        prompt_tokens: None,
                        completion_tokens: u.get("output_tokens").and_then(Value::as_u64),
                        total_tokens: None,
                    }));
                }
            }
            "message_stop" => out.push(StreamEvent::Done),
            _ => {}
        }
        Ok(out)
    }
}

/// Content blocks for a user/assistant message. Assistant tool calls
/// become `tool_use` blocks (arguments object parsed from the string
/// form); user images become `image` source blocks when they carry
/// base64 data (directly, or via a decomposable `data:` URI).
fn message_content_blocks(m: &ChatMessage) -> Value {
    let mut blocks: Vec<Value> = Vec::new();
    let mut text = String::new();
    for part in &m.content {
        match part {
            ContentPart::Text { text: t } => text.push_str(t),
            ContentPart::Image {
                data_b64,
                media_type,
                url,
            } => {
                // data_b64 when present; else decompose a data: URI
                // (the facade already decomposes, this is the defensive
                // path for programmatically-built canonical requests).
                // A REMOTE URL has no Anthropic translation (their API
                // takes base64 sources only) and is dropped.
                let decomposed = url.as_deref().and_then(crate::ai::types::split_data_uri);
                let data = data_b64
                    .clone()
                    .or_else(|| decomposed.as_ref().map(|(_, data)| data.clone()));
                if let Some(data) = data {
                    let mime = media_type
                        .clone()
                        .or_else(|| decomposed.as_ref().map(|(mime, _)| mime.clone()));
                    blocks.push(json!({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": mime.unwrap_or_else(|| "image/png".into()),
                            "data": data,
                        }
                    }));
                }
            }
        }
    }
    if !text.is_empty() {
        blocks.insert(0, json!({"type": "text", "text": text}));
    }
    if m.role == ChatRole::Assistant {
        for tc in &m.tool_calls {
            let input: Value = tc.arguments.trim().parse().unwrap_or_else(|_| json!({}));
            blocks.push(json!({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": input,
            }));
        }
    }
    Value::Array(blocks)
}

/// Merge consecutive same-role turns into one (Anthropic requires
/// strict user/assistant alternation; OpenAI conversations do not).
fn merge_consecutive_turns(messages: Vec<Value>) -> Vec<Value> {
    let mut merged: Vec<Value> = Vec::with_capacity(messages.len());
    for m in messages {
        let role = m
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let content = m.get("content").cloned().unwrap_or(Value::Null);
        if let Some(last) = merged.last_mut() {
            if last.get("role").and_then(Value::as_str) == Some(role.as_str()) {
                let existing = last.get("content").and_then(Value::as_array).cloned();
                let mut combined = existing.unwrap_or_default();
                match content {
                    Value::Array(arr) => combined.extend(arr),
                    other => combined.push(other),
                }
                if let Some(obj) = last.as_object_mut() {
                    obj.insert("content".into(), Value::Array(combined));
                }
                continue;
            }
        }
        merged.push(m);
    }
    merged
}
