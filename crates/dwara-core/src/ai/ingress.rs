//! AI-05 (#195): Multi-dialect ingress parsers.
//!
//! The gateway historically accepted only OpenAI-shaped chat requests
//! (`openai_compat::parse_chat_request`). This module adds parsers for
//! Anthropic Messages API and Gemini generateContent native request
//! formats, translating them to the canonical `ChatRequest`. This lets
//! clients using native Anthropic or Gemini SDKs use the gateway
//! without switching to the OpenAI format.
//!
//! The parsers are the INVERSE of the provider adapters
//! (`adapters/anthropic.rs`, `adapters/gemini.rs`): the adapter
//! translates canonical -> provider-native for the outbound request;
//! the ingress parser translates client-native -> canonical for the
//! inbound request.

use serde_json::Value;

use crate::ai::types::{ChatMessage, ChatRequest, ChatRole, ContentPart, ToolChoice, ToolSpec};

/// Parse an Anthropic Messages API request into the canonical
/// `ChatRequest`. The Anthropic native format has:
/// - `model`: string (required)
/// - `messages`: array of {role, content} (required)
/// - `system`: string or array of {type: "text", text} (optional, top-level)
/// - `max_tokens`: int (required)
/// - `temperature`, `top_p`: float (optional)
/// - `stop_sequences`: array of strings (optional)
/// - `stream`: bool (optional)
/// - `tools`: array of {name, description, input_schema} (optional)
/// - `tool_choice`: {type: "auto"|"any"|"tool", name: string} (optional)
pub fn parse_anthropic_request(body: &Value) -> Result<ChatRequest, String> {
    let obj = body
        .as_object()
        .ok_or("request body must be a JSON object")?;

    let model = obj
        .get("model")
        .and_then(|v| v.as_str())
        .ok_or("missing 'model' field")?
        .to_string();

    // System message (top-level, Anthropic convention).
    let mut messages = Vec::new();
    if let Some(system) = obj.get("system") {
        let system_text = match system {
            Value::String(s) => s.clone(),
            Value::Array(parts) => parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        };
        if !system_text.is_empty() {
            messages.push(ChatMessage::text(ChatRole::System, system_text));
        }
    }

    // Messages.
    let raw_messages = obj
        .get("messages")
        .and_then(|v| v.as_array())
        .ok_or("missing 'messages' field")?;
    for msg in raw_messages {
        let role_str = msg
            .get("role")
            .and_then(|v| v.as_str())
            .ok_or("message missing 'role'")?;
        let role = match role_str {
            "user" => ChatRole::User,
            "assistant" => ChatRole::Assistant,
            other => return Err(format!("unknown role '{other}'")),
        };
        let content = parse_anthropic_content(msg.get("content"))?;
        let tool_calls = parse_anthropic_tool_calls(msg.get("content"));
        messages.push(ChatMessage {
            role,
            content,
            name: None,
            tool_calls,
            tool_call_id: None,
        });
    }

    if messages.is_empty() {
        return Err("messages must be non-empty".to_string());
    }

    // Tools.
    let tools = obj
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| {
                    let name = t.get("name")?.as_str()?.to_string();
                    let description = t
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from);
                    let parameters = t.get("input_schema").cloned();
                    Some(ToolSpec {
                        name,
                        description,
                        parameters,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Tool choice.
    let tool_choice = obj.get("tool_choice").and_then(parse_anthropic_tool_choice);

    // Other fields.
    let temperature = obj.get("temperature").and_then(|v| v.as_f64());
    let top_p = obj.get("top_p").and_then(|v| v.as_f64());
    let max_tokens = obj.get("max_tokens").and_then(|v| v.as_u64());
    let stop = obj
        .get("stop_sequences")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

    // Preserve unknown fields in `other`.
    let known = [
        "model",
        "messages",
        "system",
        "max_tokens",
        "temperature",
        "top_p",
        "stop_sequences",
        "stream",
        "tools",
        "tool_choice",
    ];
    let other = obj
        .iter()
        .filter(|(k, _)| !known.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(ChatRequest {
        model,
        messages,
        tools,
        tool_choice,
        temperature,
        top_p,
        max_tokens,
        stop,
        stream,
        stream_options_include_usage: false,
        other,
    })
}

/// Parse Anthropic content blocks into `ContentPart`s.
fn parse_anthropic_content(content: Option<&Value>) -> Result<Vec<ContentPart>, String> {
    match content {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => Ok(vec![ContentPart::Text { text: s.clone() }]),
        Some(Value::Array(parts)) => {
            let mut result = Vec::new();
            for part in parts {
                let part_type = part.get("type").and_then(|t| t.as_str()).unwrap_or("text");
                match part_type {
                    "text" => {
                        let text = part.get("text").and_then(|t| t.as_str()).unwrap_or("");
                        result.push(ContentPart::Text {
                            text: text.to_string(),
                        });
                    }
                    "image" => {
                        if let Some(source) = part.get("source") {
                            let media_type = source
                                .get("media_type")
                                .and_then(|m| m.as_str())
                                .map(String::from);
                            let data_b64 = source
                                .get("data")
                                .and_then(|d| d.as_str())
                                .map(String::from);
                            let url = source.get("url").and_then(|u| u.as_str()).map(String::from);
                            result.push(ContentPart::Image {
                                url,
                                media_type,
                                data_b64,
                            });
                        }
                    }
                    "tool_use" => {
                        // Tool calls are handled separately; skip here.
                    }
                    "tool_result" => {
                        // Tool results are handled as text content.
                        if let Some(content) = part.get("content") {
                            let text = match content {
                                Value::String(s) => s.clone(),
                                Value::Array(parts) => parts
                                    .iter()
                                    .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                                    .collect::<Vec<_>>()
                                    .join(""),
                                _ => String::new(),
                            };
                            result.push(ContentPart::Text { text });
                        }
                    }
                    _ => {}
                }
            }
            Ok(result)
        }
        _ => Err("content must be a string or array".to_string()),
    }
}

/// Parse tool_use blocks from Anthropic content as tool calls.
fn parse_anthropic_tool_calls(content: Option<&Value>) -> Vec<crate::ai::types::ToolCall> {
    let mut calls = Vec::new();
    if let Some(Value::Array(parts)) = content {
        for part in parts {
            if part.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                if let (Some(id), Some(name), Some(input)) = (
                    part.get("id").and_then(|i| i.as_str()),
                    part.get("name").and_then(|n| n.as_str()),
                    part.get("input"),
                ) {
                    let arguments = serde_json::to_string(input).unwrap_or_default();
                    calls.push(crate::ai::types::ToolCall {
                        id: id.to_string(),
                        name: name.to_string(),
                        arguments,
                    });
                }
            }
        }
    }
    calls
}

/// Parse Anthropic tool_choice.
fn parse_anthropic_tool_choice(v: &Value) -> Option<ToolChoice> {
    let tc_type = v.get("type").and_then(|t| t.as_str())?;
    match tc_type {
        "auto" => Some(ToolChoice::Auto),
        "any" => Some(ToolChoice::Any),
        "tool" => v
            .get("name")
            .and_then(|n| n.as_str())
            .map(|name| ToolChoice::Tool(name.to_string())),
        _ => None,
    }
}

/// Parse a Gemini generateContent request into the canonical
/// `ChatRequest`. The Gemini native format has:
/// - `contents`: array of {role, parts} (required)
/// - `systemInstruction`: {parts: [{text}]} (optional)
/// - `tools`: array of {functionDeclarations: [{name, description, parameters}]}
/// - `toolConfig`: {mode: "AUTO"|"NONE"|"ANY", allowed_function_names}
/// - `generationConfig`: {temperature, topP, maxOutputTokens, stopSequences}
pub fn parse_gemini_request(body: &Value) -> Result<ChatRequest, String> {
    let obj = body
        .as_object()
        .ok_or("request body must be a JSON object")?;

    // System instruction.
    let mut messages = Vec::new();
    if let Some(sys) = obj.get("systemInstruction") {
        let system_text = sys
            .get("parts")
            .and_then(|p| p.as_array())
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        if !system_text.is_empty() {
            messages.push(ChatMessage::text(ChatRole::System, system_text));
        }
    }

    // Contents.
    let contents = obj
        .get("contents")
        .and_then(|v| v.as_array())
        .ok_or("missing 'contents' field")?;
    for msg in contents {
        let role_str = msg.get("role").and_then(|v| v.as_str()).unwrap_or("user");
        let role = match role_str {
            "user" => ChatRole::User,
            "model" => ChatRole::Assistant,
            "function" => ChatRole::Tool,
            other => return Err(format!("unknown role '{other}'")),
        };
        let content = parse_gemini_parts(msg.get("parts"));
        let tool_calls = parse_gemini_function_calls(msg.get("parts"));
        messages.push(ChatMessage {
            role,
            content,
            name: None,
            tool_calls,
            tool_call_id: None,
        });
    }

    if messages.is_empty() {
        return Err("contents must be non-empty".to_string());
    }

    // Tools.
    let tools = obj
        .get("tools")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|t| t.get("functionDeclarations"))
        .and_then(|f| f.as_array())
        .map(|decls| {
            decls
                .iter()
                .filter_map(|d| {
                    let name = d.get("name")?.as_str()?.to_string();
                    let description = d
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from);
                    let parameters = d.get("parameters").cloned();
                    Some(ToolSpec {
                        name,
                        description,
                        parameters,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Tool config.
    let tool_choice = obj
        .get("toolConfig")
        .and_then(|tc| tc.get("mode"))
        .and_then(|m| m.as_str())
        .and_then(|mode| match mode {
            "AUTO" => Some(ToolChoice::Auto),
            "NONE" => Some(ToolChoice::None),
            "ANY" => Some(ToolChoice::Any),
            _ => None,
        });

    // Generation config.
    let gen_cfg = obj.get("generationConfig");
    let temperature = gen_cfg
        .and_then(|g| g.get("temperature"))
        .and_then(|v| v.as_f64());
    let top_p = gen_cfg.and_then(|g| g.get("topP")).and_then(|v| v.as_f64());
    let max_tokens = gen_cfg
        .and_then(|g| g.get("maxOutputTokens"))
        .and_then(|v| v.as_u64());
    let stop = gen_cfg
        .and_then(|g| g.get("stopSequences"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });

    // Preserve unknown fields.
    let known = [
        "contents",
        "systemInstruction",
        "tools",
        "toolConfig",
        "generationConfig",
    ];
    let other = obj
        .iter()
        .filter(|(k, _)| !known.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(ChatRequest {
        model: String::new(), // Gemini requests don't include the model in the body
        messages,
        tools,
        tool_choice,
        temperature,
        top_p,
        max_tokens,
        stop,
        stream: false,
        stream_options_include_usage: false,
        other,
    })
}

/// Parse Gemini parts into ContentParts.
fn parse_gemini_parts(parts: Option<&Value>) -> Vec<ContentPart> {
    let mut result = Vec::new();
    if let Some(Value::Array(parts)) = parts {
        for part in parts {
            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                result.push(ContentPart::Text {
                    text: text.to_string(),
                });
            } else if let Some(inline) = part.get("inlineData").or_else(|| part.get("inline_data"))
            {
                let media_type = inline
                    .get("mimeType")
                    .or_else(|| inline.get("mime_type"))
                    .and_then(|m| m.as_str())
                    .map(String::from);
                let data_b64 = inline
                    .get("data")
                    .and_then(|d| d.as_str())
                    .map(String::from);
                result.push(ContentPart::Image {
                    url: None,
                    media_type,
                    data_b64,
                });
            } else if let Some(file) = part.get("fileData").or_else(|| part.get("file_data")) {
                let url = file
                    .get("fileUri")
                    .or_else(|| file.get("file_uri"))
                    .and_then(|u| u.as_str())
                    .map(String::from);
                let media_type = file
                    .get("mimeType")
                    .or_else(|| file.get("mime_type"))
                    .and_then(|m| m.as_str())
                    .map(String::from);
                result.push(ContentPart::Image {
                    url,
                    media_type,
                    data_b64: None,
                });
            }
        }
    }
    result
}

/// Parse Gemini functionCall parts as tool calls.
fn parse_gemini_function_calls(parts: Option<&Value>) -> Vec<crate::ai::types::ToolCall> {
    let mut calls = Vec::new();
    if let Some(Value::Array(parts)) = parts {
        for (i, part) in parts.iter().enumerate() {
            if let Some(fc) = part.get("functionCall") {
                let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                let args = fc.get("args").cloned().unwrap_or(Value::Null);
                let arguments = serde_json::to_string(&args).unwrap_or_default();
                calls.push(crate::ai::types::ToolCall {
                    id: format!("call-{i}-{name}"),
                    name: name.to_string(),
                    arguments,
                });
            }
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_anthropic_simple_request() {
        let body = json!({
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Hello, world!"}
            ]
        });
        let req = parse_anthropic_request(&body).unwrap();
        assert_eq!(req.model, "claude-3-5-sonnet-20241022");
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.max_tokens, Some(1024));
    }

    #[test]
    fn parse_anthropic_with_system() {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 1024,
            "system": "You are a helpful assistant.",
            "messages": [
                {"role": "user", "content": "Hi"}
            ]
        });
        let req = parse_anthropic_request(&body).unwrap();
        assert_eq!(req.messages.len(), 2);
        assert_eq!(req.messages[0].role, ChatRole::System);
    }

    #[test]
    fn parse_anthropic_with_tools() {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "What's the weather?"}],
            "tools": [{
                "name": "get_weather",
                "description": "Get weather",
                "input_schema": {"type": "object", "properties": {}}
            }],
            "tool_choice": {"type": "any"}
        });
        let req = parse_anthropic_request(&body).unwrap();
        assert_eq!(req.tools.len(), 1);
        assert_eq!(req.tools[0].name, "get_weather");
        assert_eq!(req.tool_choice, Some(ToolChoice::Any));
    }

    #[test]
    fn parse_gemini_simple_request() {
        let body = json!({
            "contents": [
                {"role": "user", "parts": [{"text": "Hello, world!"}]}
            ]
        });
        let req = parse_gemini_request(&body).unwrap();
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.messages[0].role, ChatRole::User);
    }

    #[test]
    fn parse_gemini_with_system_instruction() {
        let body = json!({
            "systemInstruction": {"parts": [{"text": "You are helpful."}]},
            "contents": [
                {"role": "user", "parts": [{"text": "Hi"}]}
            ]
        });
        let req = parse_gemini_request(&body).unwrap();
        assert_eq!(req.messages.len(), 2);
        assert_eq!(req.messages[0].role, ChatRole::System);
    }

    #[test]
    fn parse_gemini_with_tools() {
        let body = json!({
            "contents": [{"role": "user", "parts": [{"text": "Weather?"}]}],
            "tools": [{
                "functionDeclarations": [{
                    "name": "get_weather",
                    "description": "Get weather",
                    "parameters": {"type": "object"}
                }]
            }],
            "toolConfig": {"mode": "ANY"},
            "generationConfig": {"temperature": 0.7, "maxOutputTokens": 1024}
        });
        let req = parse_gemini_request(&body).unwrap();
        assert_eq!(req.tools.len(), 1);
        assert_eq!(req.tools[0].name, "get_weather");
        assert_eq!(req.tool_choice, Some(ToolChoice::Any));
        assert_eq!(req.temperature, Some(0.7));
        assert_eq!(req.max_tokens, Some(1024));
    }
}
