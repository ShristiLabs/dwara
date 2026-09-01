//! The Google Gemini adapter (DW-075).
//!
//! Speaks the Gemini `generateContent` API
//! (`POST /v1beta/models/{model}:generateContent` — note the model
//! rides in the PATH, not the body, which is why
//! [`ProviderAdapter::build_request`] takes the provider model
//! explicitly). Translation notes:
//!
//! - System messages lift to `systemInstruction`.
//! - Roles are `user`/`model` only; OpenAI `tool` results become user
//!   turns carrying a `functionResponse` part. Gemini requires the
//!   FUNCTION NAME there, while the OpenAI shape carries only the call
//!   id — the adapter resolves the name by scanning backward through
//!   the conversation for the assistant `tool_calls` entry with that
//!   id, and falls back to the id itself when the history does not
//!   contain it (a client that invented a tool_call_id out of thin
//!   air).
//! - Tool declarations become `functionDeclarations`; the JSON-Schema
//!   `parameters` object is passed through minus `$schema` (which
//!   Gemini rejects).
//! - `data:` URI images become `inline_data` parts; remote image URLs
//!   have no Gemini equivalent in this API and are DROPPED (documented
//!   limitation of the translation, not a silent corruption — the
//!   alternative, fetching the URL, is a side effect a gateway must
//!   not invent).
//! - Finish reasons map `STOP` -> stop, `MAX_TOKENS` -> length,
//!   `SAFETY`/`PROHIBITED_CONTENT` -> content filter, `RECITATION` ->
//!   other. Usage maps `promptTokenCount`/`candidatesTokenCount`.
//! - Streaming uses `:streamGenerateContent?alt=sse`; each SSE data
//!   payload is a `GenerateContentResponse` translated like a
//!   single-choice fragment.

use crate::ai::adapter::{AiError, ProviderAdapter, ProviderErrorBody, ProviderRequest};
use crate::ai::types::{
    ChatMessage, ChatRequest, ChatResponse, ChatRole, Choice, ContentPart, FinishReason,
    StreamDelta, StreamEvent, ToolCall, Usage,
};
use crate::config::ai::AiProviderKind;
use serde_json::{json, Map, Value};

/// The Gemini generateContent adapter. Stateless singleton.
pub struct GeminiAdapter;

impl ProviderAdapter for GeminiAdapter {
    fn kind(&self) -> AiProviderKind {
        AiProviderKind::Gemini
    }

    fn build_request(
        &self,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<ProviderRequest, AiError> {
        let mut body = Map::new();
        let system: Vec<String> = req
            .messages
            .iter()
            .filter(|m| m.role == ChatRole::System)
            .map(|m| m.text_content())
            .filter(|s| !s.is_empty())
            .collect();
        if !system.is_empty() {
            body.insert(
                "systemInstruction".into(),
                json!({"parts": [{"text": system.join("\n\n")}]}),
            );
        }
        let mut contents: Vec<Value> = Vec::new();
        for m in &req.messages {
            match m.role {
                ChatRole::System => continue,
                ChatRole::User => contents.push(json!({
                    "role": "user",
                    "parts": user_parts(m),
                })),
                ChatRole::Assistant => {
                    let mut parts: Vec<Value> = Vec::new();
                    let mut text = String::new();
                    for p in &m.content {
                        if let ContentPart::Text { text: t } = p {
                            text.push_str(t);
                        }
                    }
                    if !text.is_empty() {
                        parts.push(json!({"text": text}));
                    }
                    for tc in &m.tool_calls {
                        parts.push(json!({
                            "functionCall": {"name": tc.name, "args": tc.arguments_object()}
                        }));
                    }
                    contents.push(json!({"role": "model", "parts": parts}));
                }
                ChatRole::Tool => {
                    // Resolve the function NAME from the conversation
                    // history (see module docs).
                    let name = tool_name_for(&req.messages, m);
                    // Gemini's functionResponse.response is an OBJECT
                    // (proto Struct). Tool output that parses to an
                    // object passes through; anything else — a bare
                    // scalar, an array, a parse failure — is wrapped,
                    // so legal OpenAI tool results (a calculator
                    // returning `42`) cannot produce a provider 400.
                    let response: Value = match m.text_content().trim().parse() {
                        Ok(v @ Value::Object(_)) => v,
                        Ok(other) => json!({"result": other}),
                        Err(_) => json!({"result": m.text_content()}),
                    };
                    contents.push(json!({
                        "role": "user",
                        "parts": [{
                            "functionResponse": {"name": name, "response": response}
                        }],
                    }));
                }
            }
        }
        if contents.is_empty() {
            return Err(AiError::InvalidRequest(
                "the conversation has no non-system messages".to_string(),
            ));
        }
        body.insert("contents".into(), Value::Array(contents));
        if !req.tools.is_empty() {
            let decls: Vec<Value> = req
                .tools
                .iter()
                .map(|t| {
                    let mut o = Map::new();
                    o.insert("name".into(), json!(t.name));
                    if let Some(d) = &t.description {
                        o.insert("description".into(), json!(d));
                    }
                    if let Some(p) = &t.parameters {
                        // Gemini rejects $schema; everything else in
                        // the OpenAPI-ish subset passes through.
                        if let Some(pm) = p.as_object() {
                            let filtered: Map<String, Value> = pm
                                .iter()
                                .filter(|(k, _)| k.as_str() != "$schema")
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();
                            o.insert("parameters".into(), Value::Object(filtered));
                        }
                    }
                    Value::Object(o)
                })
                .collect();
            body.insert("tools".into(), json!([{"functionDeclarations": decls}]));
            if let Some(choice) = &req.tool_choice {
                let (mode, allowed) = match choice {
                    crate::ai::types::ToolChoice::Auto => ("AUTO", None),
                    crate::ai::types::ToolChoice::None => ("NONE", None),
                    crate::ai::types::ToolChoice::Any => ("ANY", None),
                    crate::ai::types::ToolChoice::Tool(name) => ("ANY", Some(vec![name.clone()])),
                };
                let mut tc = Map::new();
                tc.insert("mode".into(), json!(mode));
                if let Some(a) = allowed {
                    tc.insert("allowed_function_names".into(), json!(a));
                }
                body.insert("toolConfig".into(), Value::Object(tc));
            }
        }
        let mut generation = Map::new();
        if let Some(t) = req.temperature {
            generation.insert("temperature".into(), json!(t));
        }
        if let Some(p) = req.top_p {
            generation.insert("topP".into(), json!(p));
        }
        if let Some(m) = req.max_tokens {
            generation.insert("maxOutputTokens".into(), json!(m));
        }
        if let Some(stop) = &req.stop {
            generation.insert("stopSequences".into(), json!(stop));
        }
        if !generation.is_empty() {
            body.insert("generationConfig".into(), Value::Object(generation));
        }
        let path = if req.stream {
            format!("/v1beta/models/{provider_model}:streamGenerateContent?alt=sse")
        } else {
            format!("/v1beta/models/{provider_model}:generateContent")
        };
        Ok(ProviderRequest {
            method: http::Method::POST,
            path,
            headers: vec![(http::header::CONTENT_TYPE, "application/json".to_string())],
            body: Value::Object(body),
        })
    }

    fn parse_response(&self, body: &Value) -> Result<ChatResponse, AiError> {
        let obj = body.as_object().ok_or_else(|| {
            AiError::Translation("gemini response is not a JSON object".to_string())
        })?;
        let candidates = obj
            .get("candidates")
            .and_then(Value::as_array)
            .ok_or_else(|| AiError::Translation("gemini response has no candidates".to_string()))?;
        let mut choices = Vec::with_capacity(candidates.len());
        for (i, c) in candidates.iter().enumerate() {
            let mut text = String::new();
            let mut tool_calls = Vec::new();
            if let Some(parts) = c
                .get("content")
                .and_then(|c| c.get("parts"))
                .and_then(Value::as_array)
            {
                for p in parts {
                    if let Some(t) = p.get("text").and_then(Value::as_str) {
                        text.push_str(t);
                    }
                    if let Some(fc) = p.get("functionCall") {
                        tool_calls.push(ToolCall {
                            // Gemini function calls carry no id; a
                            // stable synthetic one keeps the OpenAI
                            // tool-call round trip (result by id)
                            // working across this one response.
                            id: format!("call-{i}-{}", tool_calls.len()),
                            name: fc
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            arguments: fc.get("args").cloned().unwrap_or(json!({})).to_string(),
                        });
                    }
                }
            }
            let finish_reason = match c.get("finishReason").and_then(Value::as_str) {
                Some("STOP") | None => FinishReason::Stop,
                Some("MAX_TOKENS") => FinishReason::Length,
                Some("SAFETY") | Some("PROHIBITED_CONTENT") => FinishReason::ContentFilter,
                Some(other) => FinishReason::Other(other.to_string()),
            };
            choices.push(Choice {
                index: i as u64,
                message: ChatMessage {
                    role: ChatRole::Assistant,
                    content: vec![ContentPart::Text { text }],
                    name: None,
                    tool_calls,
                    tool_call_id: None,
                },
                finish_reason,
            });
        }
        let usage = obj.get("usageMetadata").map(|u| Usage {
            prompt_tokens: u.get("promptTokenCount").and_then(Value::as_u64),
            completion_tokens: u.get("candidatesTokenCount").and_then(Value::as_u64),
            total_tokens: u.get("totalTokenCount").and_then(Value::as_u64),
        });
        Ok(ChatResponse {
            id: obj
                .get("responseId")
                .and_then(Value::as_str)
                .map(String::from),
            model: None,
            choices,
            usage,
        })
    }

    fn parse_error(&self, body: &Value) -> ProviderErrorBody {
        // Gemini: {"error": {"code", "message", "status"}}.
        let e = body.get("error").and_then(|e| e.as_object());
        ProviderErrorBody {
            message: e
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("provider returned an error")
                .to_string(),
            error_type: e
                .and_then(|e| e.get("status"))
                .and_then(Value::as_str)
                .map(String::from),
            code: e.and_then(|e| e.get("code")).map(|c| match c {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            }),
        }
    }

    fn parse_stream_event(&self, data: &Value) -> Result<Vec<StreamEvent>, AiError> {
        // A streaming chunk is a GenerateContentResponse: candidates
        // with parts fragments plus (on the final chunk) usageMetadata
        // and a finishReason. A chunk with NO candidates (feedback-only
        // chunks Gemini can emit) translates to zero events rather
        // than an error — a stream must not die on a skippable frame.
        let resp = match self.parse_response(data) {
            Ok(r) => r,
            Err(_) if data.get("candidates").is_none() => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for choice in &resp.choices {
            let mut content = None;
            if !choice.message.content.is_empty() {
                content = Some(choice.message.text_content());
            }
            if content.is_some() || !choice.message.tool_calls.is_empty() {
                out.push(StreamEvent::Delta(StreamDelta {
                    index: choice.index,
                    role: None,
                    content,
                    tool_calls: choice
                        .message
                        .tool_calls
                        .iter()
                        .map(|tc| crate::ai::types::ToolCallDelta {
                            index: choice.index,
                            id: Some(tc.id.clone()),
                            name: Some(tc.name.clone()),
                            arguments: tc.arguments.clone(),
                        })
                        .collect(),
                    finish_reason: None,
                }));
            }
            if choice.finish_reason != FinishReason::Stop || resp.usage.is_some() {
                out.push(StreamEvent::Delta(StreamDelta {
                    index: choice.index,
                    role: None,
                    content: None,
                    tool_calls: Vec::new(),
                    finish_reason: Some(choice.finish_reason.clone()),
                }));
            }
        }
        if let Some(u) = resp.usage {
            out.push(StreamEvent::Usage(u));
        }
        Ok(out)
    }
}

/// User-turn parts: text and `data:` URI images (see module docs for
/// the remote-URL limitation).
fn user_parts(m: &ChatMessage) -> Value {
    let mut parts: Vec<Value> = Vec::new();
    let mut text = String::new();
    for p in &m.content {
        match p {
            ContentPart::Text { text: t } => text.push_str(t),
            ContentPart::Image {
                url,
                media_type,
                data_b64,
            } => {
                if let Some(data) = data_b64 {
                    parts.push(json!({
                        "inline_data": {
                            "mime_type": media_type.clone().unwrap_or_else(|| "image/png".into()),
                            "data": data,
                        }
                    }));
                } else if let Some(url) = url {
                    if let Some((mime, data)) = crate::ai::types::split_data_uri(url) {
                        parts.push(json!({
                            "inline_data": {"mime_type": mime, "data": data}
                        }));
                    }
                    // Remote image URLs are dropped (module docs).
                }
            }
        }
    }
    if !text.is_empty() {
        parts.insert(0, json!({"text": text}));
    }
    Value::Array(parts)
}

/// Find the function NAME a Tool message's tool_call_id refers to:
/// scan backward for the assistant message carrying that call.
fn tool_name_for(history: &[ChatMessage], tool_msg: &ChatMessage) -> String {
    let id = tool_msg.tool_call_id.as_deref().unwrap_or("");
    for m in history.iter().rev() {
        if m.role == ChatRole::Assistant {
            for tc in &m.tool_calls {
                if tc.id == id {
                    return tc.name.clone();
                }
            }
        }
    }
    id.to_string()
}
