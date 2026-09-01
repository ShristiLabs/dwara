//! The OpenAI provider adapter (DW-075).
//!
//! Speaks the OpenAI chat-completions dialect TOWARD a provider
//! (`POST /v1/chat/completions`). Because the canonical request type is
//! a superset of this dialect, the translation is near-identity: the
//! adapter's job is to swap the client's model alias for the mapped
//! provider model, re-emit the canonical fields in OpenAI spelling,
//! and pass the preserved dialect-specific parameters (`other`)
//! through — the lossless OpenAI-to-OpenAI path. The same dialect is
//! spoken by OpenAI-COMPATIBLE servers (vLLM, Ollama's compatibility
//! endpoint, and others): point the provider's upstream at one of
//! those and this adapter needs no changes.

use crate::ai::adapter::{AiError, ProviderAdapter, ProviderErrorBody, ProviderRequest};
use crate::ai::types::{
    ChatMessage, ChatRequest, ChatResponse, ChatRole, Choice, ContentPart, FinishReason,
    StreamDelta, StreamEvent, ToolCallDelta, Usage,
};
use crate::config::ai::AiProviderKind;
use serde_json::{json, Map, Value};

/// The OpenAI chat-completions adapter. Stateless singleton.
pub struct OpenAiAdapter;

impl ProviderAdapter for OpenAiAdapter {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::Openai
    }

    fn build_request(
        &self,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<ProviderRequest, AiError> {
        let mut body = Map::new();
        body.insert("model".into(), json!(provider_model));
        let messages: Vec<Value> = req.messages.iter().map(message_to_openai).collect();
        body.insert("messages".into(), Value::Array(messages));
        if !req.tools.is_empty() {
            let tools: Vec<Value> = req
                .tools
                .iter()
                .map(|t| {
                    let mut f = Map::new();
                    f.insert("name".into(), json!(t.name));
                    if let Some(d) = &t.description {
                        f.insert("description".into(), json!(d));
                    }
                    if let Some(p) = &t.parameters {
                        f.insert("parameters".into(), p.clone());
                    }
                    json!({"type": "function", "function": Value::Object(f)})
                })
                .collect();
            body.insert("tools".into(), Value::Array(tools));
            if let Some(choice) = &req.tool_choice {
                body.insert(
                    "tool_choice".into(),
                    match choice {
                        crate::ai::types::ToolChoice::Auto => json!("auto"),
                        crate::ai::types::ToolChoice::None => json!("none"),
                        crate::ai::types::ToolChoice::Any => json!("required"),
                        crate::ai::types::ToolChoice::Tool(name) => json!({
                            "type": "function",
                            "function": {"name": name}
                        }),
                    },
                );
            }
        }
        if let Some(t) = req.temperature {
            body.insert("temperature".into(), json!(t));
        }
        if let Some(p) = req.top_p {
            body.insert("top_p".into(), json!(p));
        }
        if let Some(m) = req.max_tokens {
            body.insert("max_tokens".into(), json!(m));
        }
        if let Some(stop) = &req.stop {
            body.insert("stop".into(), json!(stop));
        }
        if req.stream {
            body.insert("stream".into(), json!(true));
            if req.stream_options_include_usage {
                body.insert("stream_options".into(), json!({"include_usage": true}));
            }
        }
        // Dialect-specific parameters pass through verbatim (the
        // canonical surface preserved them for exactly this adapter).
        for (k, v) in &req.other {
            body.insert(k.clone(), v.clone());
        }
        Ok(ProviderRequest {
            method: http::Method::POST,
            path: "/v1/chat/completions".to_string(),
            headers: vec![],
            body: Value::Object(body),
        })
    }

    fn parse_response(&self, body: &Value) -> Result<ChatResponse, AiError> {
        let obj = body.as_object().ok_or_else(|| {
            AiError::Translation("openai response is not a JSON object".to_string())
        })?;
        let choices_arr = obj
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| AiError::Translation("openai response has no choices".to_string()))?;
        let mut choices = Vec::with_capacity(choices_arr.len());
        for c in choices_arr {
            let index = c.get("index").and_then(Value::as_u64).unwrap_or(0);
            let message = c
                .get("message")
                .ok_or_else(|| AiError::Translation("openai choice has no message".to_string()))?;
            choices.push(Choice {
                index,
                message: parse_openai_message(message)?,
                finish_reason: parse_finish_reason(c.get("finish_reason")),
            });
        }
        let usage = obj.get("usage").map(parse_usage);
        Ok(ChatResponse {
            id: obj.get("id").and_then(Value::as_str).map(String::from),
            model: obj.get("model").and_then(Value::as_str).map(String::from),
            choices,
            usage,
        })
    }

    fn parse_error(&self, body: &Value) -> ProviderErrorBody {
        // OpenAI: {"error": {"message", "type", "code"}} (or a bare
        // message string under error).
        match body.get("error") {
            Some(Value::Object(e)) => ProviderErrorBody {
                message: e
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("provider returned an error")
                    .to_string(),
                error_type: e.get("type").and_then(Value::as_str).map(String::from),
                code: e.get("code").map(|c| match c {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                }),
            },
            Some(Value::String(s)) => ProviderErrorBody {
                message: s.clone(),
                error_type: None,
                code: None,
            },
            _ => ProviderErrorBody {
                message: "provider returned an error".to_string(),
                error_type: None,
                code: None,
            },
        }
    }

    fn parse_stream_event(&self, data: &Value) -> Result<Vec<StreamEvent>, AiError> {
        let obj = data.as_object().ok_or_else(|| {
            AiError::Translation("openai stream chunk is not a JSON object".to_string())
        })?;
        let mut out = Vec::new();
        if let Some(choices) = obj.get("choices").and_then(Value::as_array) {
            for c in choices {
                let index = c.get("index").and_then(Value::as_u64).unwrap_or(0);
                let delta = c.get("delta").cloned().unwrap_or(Value::Null);
                let mut sd = StreamDelta {
                    index,
                    role: None,
                    content: None,
                    tool_calls: Vec::new(),
                    finish_reason: None,
                };
                if let Some(role) = delta.get("role").and_then(Value::as_str) {
                    sd.role = match role {
                        "assistant" => Some(ChatRole::Assistant),
                        _ => None,
                    };
                }
                if let Some(text) = delta.get("content").and_then(Value::as_str) {
                    sd.content = Some(text.to_string());
                }
                if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                    for tc in calls {
                        sd.tool_calls.push(ToolCallDelta {
                            index: tc.get("index").and_then(Value::as_u64).unwrap_or(0),
                            id: tc.get("id").and_then(Value::as_str).map(String::from),
                            name: tc
                                .get("function")
                                .and_then(|f| f.get("name"))
                                .and_then(Value::as_str)
                                .map(String::from),
                            arguments: tc
                                .get("function")
                                .and_then(|f| f.get("arguments"))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        });
                    }
                }
                sd.finish_reason = c
                    .get("finish_reason")
                    .filter(|v| !v.is_null())
                    .map(|v| parse_finish_reason(Some(v)));
                out.push(StreamEvent::Delta(sd));
            }
        }
        if let Some(usage) = obj.get("usage").filter(|u| !u.is_null()) {
            out.push(StreamEvent::Usage(parse_usage(usage)));
        }
        Ok(out)
    }

    fn stream_done_sentinel(&self) -> Option<&'static str> {
        Some("[DONE]")
    }
}

/// Parse one OpenAI wire message into the canonical shape.
pub(crate) fn parse_openai_message(v: &Value) -> Result<ChatMessage, AiError> {
    let obj = v
        .as_object()
        .ok_or_else(|| AiError::Translation("openai message is not an object".to_string()))?;
    let role = match obj.get("role").and_then(Value::as_str) {
        Some("system") => ChatRole::System,
        Some("user") => ChatRole::User,
        Some("assistant") => ChatRole::Assistant,
        Some("tool") => ChatRole::Tool,
        _ => ChatRole::Assistant,
    };
    let mut content = Vec::new();
    match obj.get("content") {
        Some(Value::String(s)) => content.push(ContentPart::Text { text: s.clone() }),
        Some(Value::Array(parts)) => {
            for p in parts {
                match p.get("type").and_then(Value::as_str) {
                    Some("text") => content.push(ContentPart::Text {
                        text: p
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    }),
                    Some("image_url") => content.push(ContentPart::Image {
                        url: p
                            .get("image_url")
                            .and_then(|i| i.get("url"))
                            .and_then(Value::as_str)
                            .map(String::from),
                        media_type: None,
                        data_b64: None,
                    }),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    let mut tool_calls = Vec::new();
    if let Some(calls) = obj.get("tool_calls").and_then(Value::as_array) {
        for tc in calls {
            let func = tc.get("function").cloned().unwrap_or(Value::Null);
            tool_calls.push(crate::ai::types::ToolCall {
                id: tc
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                name: func
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: func
                    .get("arguments")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
    }
    Ok(ChatMessage {
        role,
        content,
        name: obj.get("name").and_then(Value::as_str).map(String::from),
        tool_calls,
        tool_call_id: obj
            .get("tool_call_id")
            .and_then(Value::as_str)
            .map(String::from),
    })
}

/// Serialize a canonical message to the OpenAI provider dialect
/// (shared shape with the facade's `message_to_openai`, kept separate
/// because the provider path must NOT invent fields the client never
/// sent).
pub(crate) fn message_to_openai(m: &ChatMessage) -> Value {
    let mut obj = Map::new();
    obj.insert("role".into(), json!(m.role.as_str()));
    if m.content.len() == 1 {
        if let ContentPart::Text { text } = &m.content[0] {
            obj.insert("content".into(), json!(text));
        }
    } else if !m.content.is_empty() {
        let parts: Vec<Value> = m
            .content
            .iter()
            .map(|p| match p {
                ContentPart::Text { text } => json!({"type": "text", "text": text}),
                ContentPart::Image { url, .. } => json!({
                    "type": "image_url",
                    "image_url": {"url": url.clone().unwrap_or_default()}
                }),
            })
            .collect();
        obj.insert("content".into(), Value::Array(parts));
    } else {
        obj.insert("content".into(), Value::Null);
    }
    if let Some(name) = &m.name {
        obj.insert("name".into(), json!(name));
    }
    if !m.tool_calls.is_empty() {
        let calls: Vec<Value> = m
            .tool_calls
            .iter()
            .map(|tc| {
                json!({
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": tc.arguments}
                })
            })
            .collect();
        obj.insert("tool_calls".into(), Value::Array(calls));
    }
    if let Some(id) = &m.tool_call_id {
        obj.insert("tool_call_id".into(), json!(id));
    }
    Value::Object(obj)
}

/// Parse an OpenAI finish_reason (`null` mid-stream).
fn parse_finish_reason(v: Option<&Value>) -> FinishReason {
    match v.and_then(Value::as_str) {
        Some("stop") | None => FinishReason::Stop,
        Some("length") => FinishReason::Length,
        Some("tool_calls") | Some("function_call") => FinishReason::ToolCalls,
        Some("content_filter") => FinishReason::ContentFilter,
        Some(other) => FinishReason::Other(other.to_string()),
    }
}

/// Parse an OpenAI usage object (provider-reported only).
fn parse_usage(v: &Value) -> Usage {
    Usage {
        prompt_tokens: v.get("prompt_tokens").and_then(Value::as_u64),
        completion_tokens: v.get("completion_tokens").and_then(Value::as_u64),
        total_tokens: v.get("total_tokens").and_then(Value::as_u64),
    }
}
