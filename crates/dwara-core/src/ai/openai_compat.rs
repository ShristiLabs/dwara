//! The OpenAI-compatibility facade (DW-075).
//!
//! The CLIENT-facing dialect: every AI route accepts an OpenAI
//! chat-completions request and answers in the OpenAI response shape,
//! regardless of which provider actually served the call. This module
//! owns that dialect's parse (`parse_chat_request`) and serialization
//! (`response_to_openai`, `stream_event_to_openai_chunk`,
//! `error_body`) — the inverse of [`crate::ai::adapters::openai`],
//! which speaks the SAME dialect but toward the provider (where the
//! model identifier is the mapped provider model, not the alias).
//!
//! Errors are emitted in an OpenAI-client-compatible shape
//! (`{"error":{"message","type","code","request_id"}}`): the standard
//! OpenAI SDKs parse `error.message/type/code`, and the extra
//! `request_id` member carries the gateway's correlation ID without
//! breaking those parsers.

use crate::ai::adapter::AiError;
use crate::ai::types::{
    ChatMessage, ChatRequest, ChatResponse, ChatRole, ContentPart, FinishReason, StreamEvent,
    ToolCall, ToolChoice, ToolSpec,
};
use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Parse an OpenAI chat-completions request body into the canonical
/// [`ChatRequest`]. Unknown top-level parameters are preserved in
/// `other` (the OpenAI provider adapter re-emits them; other dialects
/// drop them — see the types docs).
pub fn parse_chat_request(body: &Value) -> Result<ChatRequest, AiError> {
    let obj = body
        .as_object()
        .ok_or_else(|| AiError::InvalidRequest("request body must be a JSON object".to_string()))?;
    let model = obj
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| AiError::InvalidRequest("'model' must be a non-empty string".to_string()))?
        .to_string();
    let messages_value = obj
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| AiError::InvalidRequest("'messages' must be an array".to_string()))?;
    if messages_value.is_empty() {
        return Err(AiError::InvalidRequest(
            "'messages' must contain at least one message".to_string(),
        ));
    }
    let mut messages = Vec::with_capacity(messages_value.len());
    for (i, m) in messages_value.iter().enumerate() {
        messages.push(
            parse_message(m).map_err(|e| AiError::InvalidRequest(format!("messages[{i}]: {e}")))?,
        );
    }
    let mut tools = Vec::new();
    if let Some(arr) = obj.get("tools").and_then(Value::as_array) {
        for t in arr {
            tools.push(parse_tool(t)?);
        }
    }
    let tool_choice = match obj.get("tool_choice") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => match s.as_str() {
            "auto" => Some(ToolChoice::Auto),
            "none" => Some(ToolChoice::None),
            "required" => Some(ToolChoice::Any),
            other => {
                return Err(AiError::InvalidRequest(format!(
                    "tool_choice '{other}' is not one of auto|none|required"
                )))
            }
        },
        Some(v @ Value::Object(_)) => {
            // {"type":"function","function":{"name":...}}
            let name = v
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str);
            match (v.get("type").and_then(Value::as_str), name) {
                (Some("function"), Some(n)) => Some(ToolChoice::Tool(n.to_string())),
                (Some("function"), None) => {
                    return Err(AiError::InvalidRequest(
                        "tool_choice object form requires function.name".to_string(),
                    ))
                }
                _ => None,
            }
        }
        Some(_) => {
            return Err(AiError::InvalidRequest(
                "tool_choice must be a string or an object".to_string(),
            ))
        }
    };
    let stop = match obj.get("stop") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(vec![s.clone()]),
        Some(Value::Array(a)) => Some(
            a.iter()
                .map(|v| {
                    v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                        AiError::InvalidRequest("stop array entries must be strings".to_string())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => {
            return Err(AiError::InvalidRequest(
                "stop must be a string or an array of strings".to_string(),
            ))
        }
    };
    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let stream_options_include_usage = obj
        .get("stream_options")
        .and_then(|o| o.get("include_usage"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Preserve every parameter the canonical surface does not model so
    // an OpenAI-to-OpenAI path is lossless.
    const KNOWN: &[&str] = &[
        "model",
        "messages",
        "tools",
        "tool_choice",
        "temperature",
        "top_p",
        "max_tokens",
        "stop",
        "stream",
        "stream_options",
    ];
    let other = obj
        .iter()
        .filter(|(k, _)| !KNOWN.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(ChatRequest {
        model,
        messages,
        tools,
        tool_choice,
        temperature: obj.get("temperature").and_then(Value::as_f64),
        top_p: obj.get("top_p").and_then(Value::as_f64),
        max_tokens: obj
            .get("max_tokens")
            .and_then(Value::as_u64)
            .or_else(|| obj.get("max_completion_tokens").and_then(Value::as_u64)),
        stop,
        stream,
        stream_options_include_usage,
        other,
    })
}

/// Parse one OpenAI message object.
fn parse_message(v: &Value) -> Result<ChatMessage, String> {
    let obj = v.as_object().ok_or("must be an object")?;
    let role = match obj.get("role").and_then(Value::as_str) {
        Some("system") => ChatRole::System,
        Some("user") => ChatRole::User,
        Some("assistant") => ChatRole::Assistant,
        Some("tool") => ChatRole::Tool,
        _ => return Err("role must be one of system|user|assistant|tool".into()),
    };
    let mut content = Vec::new();
    match obj.get("content") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => content.push(ContentPart::Text { text: s.clone() }),
        Some(Value::Array(parts)) => {
            for p in parts {
                let pobj = p.as_object().ok_or("content parts must be objects")?;
                match pobj.get("type").and_then(Value::as_str) {
                    Some("text") => content.push(ContentPart::Text {
                        text: pobj
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    }),
                    Some("image_url") => {
                        let url = pobj
                            .get("image_url")
                            .and_then(|i| i.get("url"))
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        content.push(ContentPart::image_from_openai_url(url));
                    }
                    _ => return Err("content part type must be text or image_url".into()),
                }
            }
        }
        Some(_) => return Err("content must be a string or an array of parts".into()),
    }
    let mut tool_calls = Vec::new();
    if let Some(arr) = obj.get("tool_calls").and_then(Value::as_array) {
        for tc in arr {
            let fn_obj = tc
                .get("function")
                .ok_or("tool_calls entries require function")?;
            tool_calls.push(ToolCall {
                id: tc
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                name: fn_obj
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                arguments: fn_obj
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

/// Parse one OpenAI tool definition.
fn parse_tool(v: &Value) -> Result<ToolSpec, AiError> {
    let obj = v
        .as_object()
        .ok_or_else(|| AiError::InvalidRequest("tools entries must be objects".to_string()))?;
    let func = obj.get("function").ok_or_else(|| {
        AiError::InvalidRequest("tools entries require a function block".to_string())
    })?;
    Ok(ToolSpec {
        name: func
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        description: func
            .get("description")
            .and_then(Value::as_str)
            .map(String::from),
        parameters: func.get("parameters").cloned(),
    })
}

/// Serialize a canonical [`ChatResponse`] into the OpenAI response
/// shape. `model_alias` is echoed as the model (the provider's internal
/// identifier never leaks); `request_id` rides along for correlation.
pub fn response_to_openai(resp: &ChatResponse, model_alias: &str, request_id: &str) -> Value {
    let choices: Vec<Value> = resp
        .choices
        .iter()
        .map(|c| {
            json!({
                "index": c.index,
                "message": message_to_openai(&c.message),
                "finish_reason": finish_reason_to_openai(&c.finish_reason),
            })
        })
        .collect();
    let usage = resp.usage.map(|u| {
        json!({
            "prompt_tokens": u.prompt_tokens.unwrap_or(0),
            "completion_tokens": u.completion_tokens.unwrap_or(0),
            "total_tokens": u.total_tokens.unwrap_or(0),
        })
    });
    json!({
        "id": resp.id.clone().unwrap_or_else(|| format!("chatcmpl-{request_id}")),
        "object": "chat.completion",
        "created": unix_now(),
        "model": model_alias,
        "choices": choices,
        "usage": usage,
    })
}

/// Serialize one canonical message (assistant-style) to the OpenAI
/// shape.
fn message_to_openai(m: &ChatMessage) -> Value {
    let mut obj = Map::new();
    obj.insert("role".into(), json!(m.role.as_str()));
    if m.content
        .iter()
        .all(|p| matches!(p, ContentPart::Text { .. }))
        && !m.content.is_empty()
    {
        obj.insert("content".into(), json!(m.text_content()));
    } else if m.content.is_empty() {
        obj.insert("content".into(), Value::Null);
    } else {
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

/// Map a canonical finish reason to the OpenAI token.
fn finish_reason_to_openai(r: &FinishReason) -> Value {
    match r {
        FinishReason::Stop => json!("stop"),
        FinishReason::Length => json!("length"),
        FinishReason::ToolCalls => json!("tool_calls"),
        FinishReason::ContentFilter => json!("content_filter"),
        FinishReason::Other(_) => json!("stop"),
    }
}

/// Serialize one canonical stream event as an OpenAI
/// `chat.completion.chunk` (DW-077 wires the gateway SSE pipeline;
/// shape verified here and in the adapter stream tests).
pub fn stream_event_to_openai_chunk(
    event: &StreamEvent,
    id: &str,
    model_alias: &str,
    created: u64,
) -> Value {
    match event {
        StreamEvent::Delta(d) => {
            let mut delta = Map::new();
            if let Some(role) = &d.role {
                delta.insert("role".into(), json!(role.as_str()));
            }
            if let Some(content) = &d.content {
                delta.insert("content".into(), json!(content));
            }
            if !d.tool_calls.is_empty() {
                let calls: Vec<Value> = d
                    .tool_calls
                    .iter()
                    .map(|tc| {
                        let mut o = Map::new();
                        o.insert("index".into(), json!(tc.index));
                        if let Some(id) = &tc.id {
                            o.insert("id".into(), json!(id));
                        }
                        let mut f = Map::new();
                        if let Some(name) = &tc.name {
                            f.insert("name".into(), json!(name));
                        }
                        f.insert("arguments".into(), json!(tc.arguments));
                        o.insert("function".into(), Value::Object(f));
                        Value::Object(o)
                    })
                    .collect();
                delta.insert("tool_calls".into(), Value::Array(calls));
            }
            json!({
                "id": id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model_alias,
                "choices": [{
                    "index": d.index,
                    "delta": Value::Object(delta),
                    "finish_reason": d.finish_reason.as_ref().map(finish_reason_to_openai),
                }]
            })
        }
        StreamEvent::Usage(u) => json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model_alias,
            "choices": [],
            "usage": {
                "prompt_tokens": u.prompt_tokens.unwrap_or(0),
                "completion_tokens": u.completion_tokens.unwrap_or(0),
                "total_tokens": u.total_tokens.unwrap_or(0),
            }
        }),
        StreamEvent::Done => json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model_alias,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }]
        }),
    }
}

/// Build the OpenAI-shaped error body every AI-route failure answers
/// with. `error_type` follows the OpenAI taxonomy
/// (`invalid_request_error`, `model_error`, `api_error`, ...).
pub fn error_body(message: &str, error_type: &str, code: Option<&str>, request_id: &str) -> Value {
    let mut err = Map::new();
    err.insert("message".into(), json!(message));
    err.insert("type".into(), json!(error_type));
    if let Some(c) = code {
        err.insert("code".into(), json!(c));
    }
    err.insert("request_id".into(), json!(request_id));
    json!({ "error": Value::Object(err) })
}

/// The OpenAI error-type token for an [`AiError`], for pass-through
/// error mapping.
pub fn error_type_of(err: &AiError) -> &'static str {
    match err {
        AiError::InvalidRequest(_) => "invalid_request_error",
        AiError::Translation(_) => "api_error",
        AiError::Provider { .. } => "api_error",
    }
}

/// Current Unix seconds (response `created` fields).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::Choice;

    // White-box: facade parse edge cases that are cheaper to pin here
    // than through full gateway round-trips (tests/ai_gateway.rs owns
    // the end-to-end surface).

    #[test]
    fn parse_minimal_request() {
        let req = parse_chat_request(&json!({
            "model": "gpt-x",
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .unwrap();
        assert_eq!(req.model, "gpt-x");
        assert_eq!(req.messages.len(), 1);
        assert!(!req.stream);
        assert!(req.other.is_empty());
    }

    #[test]
    fn parse_preserves_unknown_params() {
        let req = parse_chat_request(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "seed": 7,
            "response_format": {"type": "json_object"}
        }))
        .unwrap();
        assert_eq!(req.other.get("seed"), Some(&json!(7)));
        assert!(req.other.contains_key("response_format"));
    }

    #[test]
    fn parse_rejects_missing_model_and_empty_messages() {
        assert!(matches!(
            parse_chat_request(&json!({"messages": []})),
            Err(AiError::InvalidRequest(_))
        ));
        assert!(matches!(
            parse_chat_request(&json!({"model": "m", "messages": []})),
            Err(AiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn parse_tool_flow_roundtrip() {
        let req = parse_chat_request(&json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "c1", "type": "function",
                     "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}
                ]},
                {"role": "tool", "tool_call_id": "c1", "content": "72F"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "get_weather", "parameters": {"type": "object"}
            }}],
            "tool_choice": {"type": "function", "function": {"name": "get_weather"}}
        }))
        .unwrap();
        assert_eq!(req.messages[1].tool_calls.len(), 1);
        assert_eq!(req.messages[2].tool_call_id.as_deref(), Some("c1"));
        assert_eq!(req.tools.len(), 1);
        assert_eq!(
            req.tool_choice,
            Some(ToolChoice::Tool("get_weather".into()))
        );
        let resp = ChatResponse {
            id: Some("r1".into()),
            model: Some("provider-model".into()),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage::text(ChatRole::Assistant, "72F and sunny"),
                finish_reason: FinishReason::Stop,
            }],
            usage: Some(crate::ai::types::Usage {
                prompt_tokens: Some(10),
                completion_tokens: Some(5),
                total_tokens: Some(15),
            }),
        };
        let out = response_to_openai(&resp, "alias-x", "req-1");
        assert_eq!(out["model"], "alias-x");
        assert_eq!(out["choices"][0]["message"]["content"], "72F and sunny");
        assert_eq!(out["usage"]["total_tokens"], 15);
    }
}
