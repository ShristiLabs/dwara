//! AI provider-adapter translation tests (DW-075).
//!
//! Every test drives the PUBLIC adapter trait against recorded
//! provider wire shapes — the exact JSON/SSE bytes each provider's
//! sandbox emits — so a provider-side schema change is caught as a
//! translation failure here, not as a runtime 502. The gateway-level
//! behavior (routing, auth injection, error mapping) is covered by
//! `tests/ai_gateway.rs`.

mod support;

use dwara_core::ai::adapter::{adapter_for, AiError, ProviderAdapter};
use dwara_core::ai::openai_compat;
use dwara_core::ai::sse::SseDecoder;
use dwara_core::ai::types::{
    ChatMessage, ChatRequest, ChatRole, ContentPart, FinishReason, StreamEvent, ToolCall,
    ToolChoice, ToolSpec, Usage,
};
use dwara_core::config::ai::{AiConfig, AiModel, AiProvider, AiProviderAuth, AiProviderKind};
use serde_json::{json, Value};

/// A canonical request exercising the full surface: system + user +
/// assistant tool call + tool result, tools, tool_choice, sampling.
fn canonical_request() -> ChatRequest {
    ChatRequest {
        model: "alias-x".to_string(),
        messages: vec![
            ChatMessage::text(ChatRole::System, "be terse"),
            ChatMessage::text(ChatRole::User, "weather in SF?"),
            ChatMessage {
                role: ChatRole::Assistant,
                content: vec![],
                name: None,
                tool_calls: vec![ToolCall {
                    id: "call-1".to_string(),
                    name: "get_weather".to_string(),
                    arguments: r#"{"city":"SF"}"#.to_string(),
                }],
                tool_call_id: None,
            },
            ChatMessage {
                role: ChatRole::Tool,
                content: vec![ContentPart::Text {
                    text: "72F".to_string(),
                }],
                name: None,
                tool_calls: vec![],
                tool_call_id: Some("call-1".to_string()),
            },
        ],
        tools: vec![ToolSpec {
            name: "get_weather".to_string(),
            description: Some("current weather".to_string()),
            parameters: Some(json!({"type": "object", "properties": {"city": {"type": "string"}}})),
        }],
        tool_choice: Some(ToolChoice::Auto),
        temperature: Some(0.2),
        top_p: Some(0.9),
        max_tokens: Some(256),
        stop: Some(vec!["END".to_string()]),
        stream: false,
        stream_options_include_usage: false,
        other: [("seed".to_string(), json!(7))].into_iter().collect(),
    }
}

/// Feed a recorded SSE byte stream through the decoder and one
/// adapter, returning the canonical events.
fn replay_stream(adapter: &'static dyn ProviderAdapter, sse: &str) -> Vec<StreamEvent> {
    let mut dec = SseDecoder::new();
    let mut events = Vec::new();
    for frame in dec.push(sse.as_bytes()) {
        // The OpenAI sentinel terminates the stream without being JSON.
        if Some(frame.data.as_str()) == adapter.stream_done_sentinel() {
            events.push(StreamEvent::Done);
            continue;
        }
        let data: Value = serde_json::from_str(&frame.data).expect("recorded data is JSON");
        events.extend(
            adapter
                .parse_stream_event(&data)
                .expect("recorded event parses"),
        );
    }
    events.extend(
        dec.finish()
            .into_iter()
            .filter_map(|f| serde_json::from_str::<Value>(&f.data).ok())
            .flat_map(|d| adapter.parse_stream_event(&d).unwrap_or_default()),
    );
    events
}

#[test]
fn openai_build_request_swaps_model_and_preserves_extras() {
    let adapter = adapter_for(AiProviderKind::Openai);
    let req = canonical_request();
    let out = adapter.build_request(&req, "gpt-4o-mini").unwrap();
    assert_eq!(out.path, "/v1/chat/completions");
    let body = &out.body;
    assert_eq!(body["model"], "gpt-4o-mini");
    assert_eq!(body["messages"].as_array().unwrap().len(), 4);
    assert_eq!(
        body["messages"][2]["tool_calls"][0]["function"]["name"],
        "get_weather"
    );
    assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
    assert_eq!(body["tool_choice"], "auto");
    assert_eq!(body["temperature"], 0.2);
    assert_eq!(body["max_tokens"], 256);
    assert_eq!(body["stop"], json!(["END"]));
    // Dialect extras pass through verbatim on the lossless path.
    assert_eq!(body["seed"], 7);
}

#[test]
fn openai_parse_response_normalizes_text_tools_usage() {
    let adapter = adapter_for(AiProviderKind::Openai);
    let resp = adapter
        .parse_response(&json!({
            "id": "chatcmpl-abc",
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call-9",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16}
        }))
        .unwrap();
    assert_eq!(resp.id.as_deref(), Some("chatcmpl-abc"));
    let choice = &resp.choices[0];
    assert_eq!(choice.finish_reason, FinishReason::ToolCalls);
    assert_eq!(choice.message.tool_calls.len(), 1);
    assert_eq!(choice.message.tool_calls[0].arguments, "{\"city\":\"SF\"}");
    assert_eq!(
        resp.usage,
        Some(Usage {
            prompt_tokens: Some(12),
            completion_tokens: Some(4),
            total_tokens: Some(16)
        })
    );
}

#[test]
fn openai_parse_error_extracts_fields() {
    let adapter = adapter_for(AiProviderKind::Openai);
    let e = adapter.parse_error(&json!({
        "error": {"message": "rate limited", "type": "requests", "code": "429"}
    }));
    assert_eq!(e.message, "rate limited");
    assert_eq!(e.error_type.as_deref(), Some("requests"));
    assert_eq!(e.code.as_deref(), Some("429"));
}

#[test]
fn openai_stream_translation_carries_argument_fragments() {
    let adapter = adapter_for(AiProviderKind::Openai);
    let events = replay_stream(
        adapter,
        concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n",
            "data: [DONE]\n\n"
        ),
    );
    let deltas: Vec<&dwara_core::ai::types::StreamDelta> = events
        .iter()
        .filter_map(|e| match e {
            StreamEvent::Delta(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(deltas.len(), 4);
    assert_eq!(deltas[0].role, Some(ChatRole::Assistant));
    // Content fragments arrive per-chunk and concatenate in order.
    let text: String = deltas.iter().filter_map(|d| d.content.clone()).collect();
    assert_eq!(text, "Hello");
    assert_eq!(deltas[3].finish_reason, Some(FinishReason::Stop));
    // Usage rides a dedicated terminal event.
    assert!(events.iter().any(|e| matches!(
        e,
        StreamEvent::Usage(Usage {
            prompt_tokens: Some(3),
            completion_tokens: Some(2),
            total_tokens: Some(5)
        })
    )));
    // The [DONE] sentinel translated to the canonical Done marker.
    assert!(matches!(events.last(), Some(StreamEvent::Done)));
}

#[test]
fn anthropic_build_request_lifts_system_and_maps_tools() {
    let adapter = adapter_for(AiProviderKind::Anthropic);
    let req = canonical_request();
    let out = adapter.build_request(&req, "claude-sonnet-4-5").unwrap();
    assert_eq!(out.path, "/v1/messages");
    let body = &out.body;
    assert_eq!(body["model"], "claude-sonnet-4-5");
    assert_eq!(body["system"], "be terse");
    // The system message lifted OUT of the conversation.
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0]["role"], "user");
    // Assistant tool calls become tool_use blocks with parsed args.
    let blocks = messages[1]["content"].as_array().unwrap();
    assert_eq!(blocks[0]["type"], "tool_use");
    assert_eq!(blocks[0]["input"], json!({"city": "SF"}));
    // Tool results become user turns with tool_result blocks.
    assert_eq!(messages[2]["role"], "user");
    assert_eq!(messages[2]["content"][0]["type"], "tool_result");
    assert_eq!(messages[2]["content"][0]["tool_use_id"], "call-1");
    // max_tokens is REQUIRED by Anthropic: the client sent one, it
    // passes through.
    assert_eq!(body["max_tokens"], 256);
    assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
    assert_eq!(body["tool_choice"], json!({"type": "auto"}));
    assert_eq!(body["stop_sequences"], json!(["END"]));
    // Dialect extras are NOT invented for Anthropic.
    assert!(body.get("seed").is_none());
    // The version header rides along.
    assert!(out
        .headers
        .iter()
        .any(|(n, v)| n.as_str() == "anthropic-version" && v == "2023-06-01"));
}

#[test]
fn anthropic_substitutes_max_tokens_when_absent() {
    let adapter = adapter_for(AiProviderKind::Anthropic);
    let mut req = canonical_request();
    req.max_tokens = None;
    let out = adapter.build_request(&req, "claude-sonnet-4-5").unwrap();
    assert_eq!(
        out.body["max_tokens"],
        dwara_core::ai::adapters::anthropic::DEFAULT_MAX_TOKENS
    );
}

#[test]
fn anthropic_merges_consecutive_same_role_turns() {
    let adapter = adapter_for(AiProviderKind::Anthropic);
    let req = ChatRequest {
        model: "m".into(),
        messages: vec![
            ChatMessage::text(ChatRole::User, "first"),
            ChatMessage::text(ChatRole::User, "second"),
            ChatMessage::text(ChatRole::Assistant, "reply"),
        ],
        tools: vec![],
        tool_choice: None,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop: None,
        stream: false,
        stream_options_include_usage: false,
        other: Default::default(),
    };
    let out = adapter.build_request(&req, "m").unwrap();
    let messages = out.body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["content"][0]["text"], "first");
    assert_eq!(messages[0]["content"][1]["text"], "second");
}

#[test]
fn anthropic_parse_response_maps_blocks_stop_reason_and_usage() {
    let adapter = adapter_for(AiProviderKind::Anthropic);
    let resp = adapter
        .parse_response(&json!({
            "id": "msg_01",
            "model": "claude-sonnet-4-5",
            "content": [
                {"type": "text", "text": "It is "},
                {"type": "text", "text": "72F"},
                {"type": "tool_use", "id": "toolu_01", "name": "get_weather",
                 "input": {"city": "SF"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 6}
        }))
        .unwrap();
    let choice = &resp.choices[0];
    assert_eq!(choice.message.text_content(), "It is 72F");
    assert_eq!(choice.finish_reason, FinishReason::ToolCalls);
    assert_eq!(choice.message.tool_calls[0].id, "toolu_01");
    assert_eq!(choice.message.tool_calls[0].arguments, "{\"city\":\"SF\"}");
    // Anthropic sends input/output; total is derived.
    assert_eq!(
        resp.usage,
        Some(Usage {
            prompt_tokens: Some(10),
            completion_tokens: Some(6),
            total_tokens: Some(16)
        })
    );
}

#[test]
fn anthropic_stream_translation_assembles_tool_fragments() {
    let adapter = adapter_for(AiProviderKind::Anthropic);
    let events = replay_stream(
        adapter,
        concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":25}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"ci\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"ty\\\": \\\"SF\\\"}\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":31}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        ),
    );
    // Concatenated argument fragments reconstruct the arguments JSON.
    let mut args = String::new();
    let mut finish = None;
    let mut usage = Usage::default();
    let mut done = false;
    for e in &events {
        match e {
            StreamEvent::Delta(d) => {
                for tc in &d.tool_calls {
                    assert_eq!(tc.index, 0);
                    args.push_str(&tc.arguments);
                }
                if let Some(f) = &d.finish_reason {
                    finish = Some(f.clone());
                }
            }
            StreamEvent::Usage(u) => usage.merge(*u),
            StreamEvent::Done => done = true,
        }
    }
    assert_eq!(args, "{\"city\": \"SF\"}");
    assert_eq!(finish, Some(FinishReason::ToolCalls));
    assert_eq!(usage.prompt_tokens, Some(25));
    assert_eq!(usage.completion_tokens, Some(31));
    assert!(done);
    // The tool_use block start carried id + name for the delta stream.
    let start = events.iter().find_map(|e| match e {
        StreamEvent::Delta(d) if !d.tool_calls.is_empty() && d.tool_calls[0].id.is_some() => {
            Some(d.tool_calls[0].clone())
        }
        _ => None,
    });
    let start = start.expect("content_block_start produced a delta");
    assert_eq!(start.id.as_deref(), Some("toolu_1"));
    assert_eq!(start.name.as_deref(), Some("get_weather"));
}

#[test]
fn gemini_build_request_maps_conversation_and_resolves_tool_names() {
    let adapter = adapter_for(AiProviderKind::Gemini);
    let req = canonical_request();
    let out = adapter.build_request(&req, "gemini-2.5-flash").unwrap();
    assert_eq!(out.path, "/v1beta/models/gemini-2.5-flash:generateContent");
    let body = &out.body;
    assert_eq!(body["systemInstruction"]["parts"][0]["text"], "be terse");
    let contents = body["contents"].as_array().unwrap();
    // user question, model functionCall turn, user functionResponse.
    assert_eq!(contents.len(), 3);
    assert_eq!(contents[0]["role"], "user");
    assert_eq!(contents[1]["role"], "model");
    assert_eq!(
        contents[1]["parts"][0]["functionCall"]["name"],
        "get_weather"
    );
    assert_eq!(
        contents[1]["parts"][0]["functionCall"]["args"]["city"],
        "SF"
    );
    // The Tool message's NAME was resolved from the conversation
    // history by its tool_call_id (the OpenAI shape carries only id).
    assert_eq!(contents[2]["role"], "user");
    assert_eq!(
        contents[2]["parts"][0]["functionResponse"]["name"],
        "get_weather"
    );
    // Non-JSON tool output is wrapped (Gemini requires an object).
    assert_eq!(
        contents[2]["parts"][0]["functionResponse"]["response"],
        json!({"result": "72F"})
    );
    // Tools become functionDeclarations.
    assert_eq!(
        body["tools"][0]["functionDeclarations"][0]["name"],
        "get_weather"
    );
    assert_eq!(body["generationConfig"]["maxOutputTokens"], 256);
    assert_eq!(body["generationConfig"]["stopSequences"], json!(["END"]));
}

#[test]
fn gemini_stream_path_switches_and_images_translate() {
    let adapter = adapter_for(AiProviderKind::Gemini);
    let mut req = canonical_request();
    req.stream = true;
    req.messages.push(ChatMessage {
        role: ChatRole::User,
        content: vec![ContentPart::Image {
            url: Some("data:image/png;base64,aGk=".to_string()),
            media_type: None,
            data_b64: None,
        }],
        name: None,
        tool_calls: vec![],
        tool_call_id: None,
    });
    let out = adapter.build_request(&req, "gemini-2.5-flash").unwrap();
    assert_eq!(
        out.path,
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
    );
    // The data: URI decomposed into inline_data.
    let last = out.body["contents"].as_array().unwrap().last().unwrap();
    assert_eq!(last["parts"][0]["inline_data"]["mime_type"], "image/png");
    assert_eq!(last["parts"][0]["inline_data"]["data"], "aGk=");
}

#[test]
fn gemini_parse_response_and_stream() {
    let adapter = adapter_for(AiProviderKind::Gemini);
    let resp = adapter
        .parse_response(&json!({
            "candidates": [{
                "content": {"parts": [
                    {"text": "72F and "},
                    {"text": "sunny"},
                    {"functionCall": {"name": "get_weather", "args": {"city": "SF"}}}
                ]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 8, "candidatesTokenCount": 3, "totalTokenCount": 11}
        }))
        .unwrap();
    let choice = &resp.choices[0];
    assert_eq!(choice.message.text_content(), "72F and sunny");
    assert_eq!(choice.message.tool_calls[0].name, "get_weather");
    assert_eq!(
        resp.usage,
        Some(Usage {
            prompt_tokens: Some(8),
            completion_tokens: Some(3),
            total_tokens: Some(11)
        })
    );
    // Stream chunks reuse the response grammar.
    let events = replay_stream(
        adapter,
        concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"72\"}]}}]}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"F\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":1,\"totalTokenCount\":9}}\n\n"
        ),
    );
    let text: String = events
        .iter()
        .filter_map(|e| match e {
            StreamEvent::Delta(d) => d.content.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(text, "72F");
    assert!(events.iter().any(|e| matches!(
        e,
        StreamEvent::Usage(Usage {
            total_tokens: Some(9),
            ..
        })
    )));
}

#[test]
fn gemini_parse_error_uses_status_and_code() {
    let adapter = adapter_for(AiProviderKind::Gemini);
    let e = adapter.parse_error(&json!({
        "error": {"code": 429, "message": "Resource exhausted", "status": "RESOURCE_EXHAUSTED"}
    }));
    assert_eq!(e.message, "Resource exhausted");
    assert_eq!(e.error_type.as_deref(), Some("RESOURCE_EXHAUSTED"));
    assert_eq!(e.code.as_deref(), Some("429"));
}

/// The done-when at the translation layer: ONE canonical request, all
/// three dialects, ONE normalized response the facade serializes
/// identically (modulo provider-reported fields the client cannot
/// control).
#[test]
fn same_canonical_request_serves_all_three_dialects() {
    let cases = [
        (
            AiProviderKind::Openai,
            json!({
                "id": "r1", "model": "provider-openai",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "72F"},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}
            }),
        ),
        (
            AiProviderKind::Anthropic,
            json!({
                "id": "r1", "model": "provider-anthropic",
                "content": [{"type": "text", "text": "72F"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 2}
            }),
        ),
        (
            AiProviderKind::Gemini,
            json!({
                "candidates": [{"content": {"parts": [{"text": "72F"}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 2, "totalTokenCount": 12}
            }),
        ),
    ];
    let req = ChatRequest {
        model: "alias-x".into(),
        messages: vec![ChatMessage::text(ChatRole::User, "weather?")],
        tools: vec![],
        tool_choice: None,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop: None,
        stream: false,
        stream_options_include_usage: false,
        other: Default::default(),
    };
    for (kind, provider_body) in cases {
        let adapter = adapter_for(kind);
        let out = adapter.build_request(&req, "provider-model").unwrap();
        // The provider model never carries the alias.
        let serialized = serde_json::to_string(&out.body).unwrap();
        assert!(!serialized.contains("alias-x"), "{kind:?} leaked the alias");
        let resp = adapter.parse_response(&provider_body).unwrap();
        let client_body = openai_compat::response_to_openai(&resp, "alias-x", "req-t");
        // The client always sees the OpenAI shape with ITS alias.
        assert_eq!(client_body["model"], "alias-x");
        assert_eq!(client_body["object"], "chat.completion");
        assert_eq!(client_body["choices"][0]["message"]["content"], "72F");
        assert_eq!(client_body["choices"][0]["finish_reason"], "stop");
        assert_eq!(client_body["usage"]["total_tokens"], 12);
    }
}

#[test]
fn ai_runtime_compiles_and_resolves() {
    let cfg = AiConfig {
        providers: vec![AiProvider {
            name: "p1".into(),
            kind: AiProviderKind::Anthropic,
            upstream: "up1".into(),
            auth: Some(AiProviderAuth {
                header: "x-api-key".into(),
                value: "inline-secret".into(),
            }),
        }],
        models: [(
            "alias-a".to_string(),
            AiModel {
                provider: "p1".into(),
                provider_model: "claude-sonnet-4-5".into(),
                failover: vec![],
                canary: vec![],
            },
        )]
        .into_iter()
        .collect(),
    };
    let rt = dwara_core::ai::AiRuntime::compile(Some(&cfg)).unwrap();
    assert_eq!(rt.provider_count(), 1);
    assert_eq!(rt.model_count(), 1);
    let (provider, model) = rt.resolve("alias-a").unwrap();
    assert_eq!(provider.name, "p1");
    assert_eq!(provider.upstream, "up1");
    assert_eq!(model, "claude-sonnet-4-5");
    // The inline secret resolved into the auth header pair.
    assert_eq!(
        provider.auth_headers,
        vec![("x-api-key".to_string(), "inline-secret".to_string())]
    );
    assert!(rt.resolve("alias-missing").is_none());
    // Absent block: no runtime.
    assert!(dwara_core::ai::AiRuntime::compile(None).is_none());
}

#[test]
fn facade_stream_chunk_shapes_match_openai() {
    use dwara_core::ai::types::{StreamDelta, ToolCallDelta};
    let chunk = openai_compat::stream_event_to_openai_chunk(
        &StreamEvent::Delta(StreamDelta {
            index: 0,
            role: None,
            content: Some("hi".into()),
            tool_calls: vec![ToolCallDelta {
                index: 1,
                id: None,
                name: None,
                arguments: "{\"a\":".into(),
            }],
            finish_reason: None,
        }),
        "chatcmpl-1",
        "alias-x",
        1234,
    );
    assert_eq!(chunk["object"], "chat.completion.chunk");
    assert_eq!(chunk["model"], "alias-x");
    assert_eq!(chunk["choices"][0]["delta"]["content"], "hi");
    assert_eq!(chunk["choices"][0]["delta"]["tool_calls"][0]["index"], 1);
    assert_eq!(
        chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
        "{\"a\":"
    );
}

#[test]
fn translation_errors_are_classified() {
    let adapter = adapter_for(AiProviderKind::Openai);
    let err = adapter
        .parse_response(&json!({"no_choices": true}))
        .unwrap_err();
    assert!(matches!(err, AiError::Translation(_)));
    assert_eq!(err.kind(), "translation");
}

// ---------------------------------------------------------------------------
// Gap-fill tests (tester pass): tool_choice variants, multimodal parts,
// multi-choice responses, empty-content messages, and the DW-076
// composition seam (the done-when's "behind a trait" criterion pinned
// at the type level).
// ---------------------------------------------------------------------------

#[test]
fn tool_choice_variants_map_per_dialect() {
    let cases = [
        (
            ToolChoice::Auto,
            json!("auto"),
            json!({"type": "auto"}),
            "AUTO",
        ),
        (
            ToolChoice::Any,
            json!("required"),
            json!({"type": "any"}),
            "ANY",
        ),
        (
            ToolChoice::Tool("get_weather".into()),
            json!({"type": "function", "function": {"name": "get_weather"}}),
            json!({"type": "tool", "name": "get_weather"}),
            "ANY",
        ),
    ];
    for (choice, openai_expect, anthropic_expect, gemini_mode) in cases {
        let mut req = canonical_request();
        req.tool_choice = Some(choice);
        let openai = adapter_for(AiProviderKind::Openai)
            .build_request(&req, "m")
            .unwrap();
        assert_eq!(openai.body["tool_choice"], openai_expect);
        let anthropic = adapter_for(AiProviderKind::Anthropic)
            .build_request(&req, "m")
            .unwrap();
        assert_eq!(anthropic.body["tool_choice"], anthropic_expect);
        let gemini = adapter_for(AiProviderKind::Gemini)
            .build_request(&req, "m")
            .unwrap();
        assert_eq!(gemini.body["toolConfig"]["mode"], gemini_mode);
        if gemini_mode == "ANY" {
            // A named tool pin carries the allowlist.
            if let ToolChoice::Tool(name) = req.tool_choice.clone().unwrap() {
                assert_eq!(
                    gemini.body["toolConfig"]["allowed_function_names"],
                    json!([name])
                );
            }
        }
    }
    // "none": OpenAI says none, Anthropic DROPS the tools entirely (its
    // dialect has no none), Gemini sets mode NONE.
    let mut req = canonical_request();
    req.tool_choice = Some(ToolChoice::None);
    let openai = adapter_for(AiProviderKind::Openai)
        .build_request(&req, "m")
        .unwrap();
    assert_eq!(openai.body["tool_choice"], "none");
    let anthropic = adapter_for(AiProviderKind::Anthropic)
        .build_request(&req, "m")
        .unwrap();
    assert!(anthropic.body.get("tools").is_none());
    assert!(anthropic.body.get("tool_choice").is_none());
    let gemini = adapter_for(AiProviderKind::Gemini)
        .build_request(&req, "m")
        .unwrap();
    assert_eq!(gemini.body["toolConfig"]["mode"], "NONE");
}

#[test]
fn multimodal_parts_translate_per_dialect() {
    let mut req = canonical_request();
    req.messages[1].content.push(ContentPart::Image {
        url: Some("data:image/png;base64,aGk=".into()),
        media_type: None,
        data_b64: None,
    });
    let openai = adapter_for(AiProviderKind::Openai)
        .build_request(&req, "m")
        .unwrap();
    // OpenAI: a mixed message serializes content as a parts array with
    // the data: URI verbatim.
    assert_eq!(openai.body["messages"][1]["content"][0]["type"], "text");
    assert_eq!(
        openai.body["messages"][1]["content"][1]["image_url"]["url"],
        "data:image/png;base64,aGk="
    );
    let anthropic = adapter_for(AiProviderKind::Anthropic)
        .build_request(&req, "m")
        .unwrap();
    let blocks = anthropic.body["messages"][0]["content"].as_array().unwrap();
    let image_block = blocks
        .iter()
        .find(|b| b["type"] == "image")
        .expect("image block");
    assert_eq!(image_block["source"]["type"], "base64");
    assert_eq!(image_block["source"]["media_type"], "image/png");
    assert_eq!(image_block["source"]["data"], "aGk=");
    let gemini = adapter_for(AiProviderKind::Gemini)
        .build_request(&req, "m")
        .unwrap();
    let parts = gemini.body["contents"][0]["parts"].as_array().unwrap();
    let inline = parts
        .iter()
        .find(|p| p.get("inline_data").is_some())
        .expect("inline_data");
    assert_eq!(inline["inline_data"]["mime_type"], "image/png");
    assert_eq!(inline["inline_data"]["data"], "aGk=");
    // A REMOTE image URL has no Gemini translation and is dropped (the
    // documented limitation), while the text part survives.
    let mut remote = canonical_request();
    remote.messages[1].content.push(ContentPart::Image {
        url: Some("https://example.com/cat.png".into()),
        media_type: None,
        data_b64: None,
    });
    let gemini_remote = adapter_for(AiProviderKind::Gemini)
        .build_request(&remote, "m")
        .unwrap();
    let gparts = gemini_remote.body["contents"][0]["parts"]
        .as_array()
        .unwrap();
    assert!(
        gparts.iter().all(|p| p.get("inline_data").is_none()),
        "remote URL must not fabricate inline data: {gparts:?}"
    );
    assert_eq!(gparts[0]["text"], "weather in SF?");
    // OpenAI passes the remote URL through unchanged (its dialect has
    // URL images natively).
    let openai_remote = adapter_for(AiProviderKind::Openai)
        .build_request(&remote, "m")
        .unwrap();
    assert_eq!(
        openai_remote.body["messages"][1]["content"][1]["image_url"]["url"],
        "https://example.com/cat.png"
    );
}

#[test]
fn openai_multiple_choices_normalize_in_order() {
    let adapter = adapter_for(AiProviderKind::Openai);
    let resp = adapter
        .parse_response(&json!({
            "id": "r",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "first"}, "finish_reason": "stop"},
                {"index": 1, "message": {"role": "assistant", "content": "second"}, "finish_reason": "length"}
            ]
        }))
        .unwrap();
    assert_eq!(resp.choices.len(), 2);
    assert_eq!(resp.choices[0].index, 0);
    assert_eq!(resp.choices[0].message.text_content(), "first");
    assert_eq!(resp.choices[1].finish_reason, FinishReason::Length);
    let out = openai_compat::response_to_openai(&resp, "alias", "req");
    assert_eq!(out["choices"].as_array().unwrap().len(), 2);
    assert_eq!(out["choices"][1]["message"]["content"], "second");
    // Anthropic/Gemini single-choice responses still land at index 0.
    let anthropic = adapter_for(AiProviderKind::Anthropic)
        .parse_response(&json!({
            "content": [{"type": "text", "text": "one"}], "stop_reason": "end_turn"
        }))
        .unwrap();
    assert_eq!(anthropic.choices.len(), 1);
    assert_eq!(anthropic.choices[0].index, 0);
}

#[test]
fn empty_content_assistant_message_round_trips() {
    // An assistant message with tool calls and NO content: OpenAI
    // serializes content as null; the facade re-emits null (not an
    // empty string) so SDKs see the documented shape.
    let msg = ChatMessage {
        role: ChatRole::Assistant,
        content: vec![],
        name: None,
        tool_calls: vec![ToolCall {
            id: "c".into(),
            name: "f".into(),
            arguments: "{}".into(),
        }],
        tool_call_id: None,
    };
    let openai = adapter_for(AiProviderKind::Openai)
        .build_request(
            &ChatRequest {
                model: "m".into(),
                messages: vec![ChatMessage::text(ChatRole::User, "q"), msg.clone()],
                tools: vec![],
                tool_choice: None,
                temperature: None,
                top_p: None,
                max_tokens: None,
                stop: None,
                stream: false,
                stream_options_include_usage: false,
                other: Default::default(),
            },
            "m",
        )
        .unwrap();
    assert!(openai.body["messages"][1]["content"].is_null());
    assert_eq!(openai.body["messages"][1]["tool_calls"][0]["id"], "c");
    // Anthropic: an empty-content assistant turn carries only the
    // tool_use block (no empty text block).
    let anthropic = adapter_for(AiProviderKind::Anthropic)
        .build_request(
            &ChatRequest {
                model: "m".into(),
                messages: vec![ChatMessage::text(ChatRole::User, "q"), msg],
                tools: vec![],
                tool_choice: None,
                temperature: None,
                top_p: None,
                max_tokens: None,
                stop: None,
                stream: false,
                stream_options_include_usage: false,
                other: Default::default(),
            },
            "m",
        )
        .unwrap();
    let blocks = anthropic.body["messages"][1]["content"].as_array().unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0]["type"], "tool_use");
    // A provider response with EMPTY text normalizes to an empty
    // string message, not a translation error.
    let resp = adapter_for(AiProviderKind::Anthropic)
        .parse_response(&json!({
            "content": [], "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 0}
        }))
        .unwrap();
    assert_eq!(resp.choices[0].message.text_content(), "");
    let out = openai_compat::response_to_openai(&resp, "alias", "req");
    assert_eq!(out["choices"][0]["message"]["content"], "");
}

#[test]
fn failover_composition_uses_only_the_trait_surface() {
    // The done-when's "behind a trait" criterion, pinned by USING the
    // trait exactly the way DW-076 will: a composing layer receives
    // `&dyn ProviderAdapter` per attempt, translates once, and reroutes
    // on failure WITHOUT touching any adapter internals. If this
    // function compiles, the seam is sufficient; the behavior asserts
    // the reroute lands on the second provider's dialect.
    fn translate_for_attempt(
        adapter: &dyn ProviderAdapter,
        req: &ChatRequest,
        provider_model: &str,
    ) -> Result<dwara_core::ai::adapter::ProviderRequest, AiError> {
        adapter.build_request(req, provider_model)
    }
    let req = ChatRequest {
        model: "alias".into(),
        messages: vec![ChatMessage::text(ChatRole::User, "hi")],
        tools: vec![],
        tool_choice: None,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop: None,
        stream: false,
        stream_options_include_usage: false,
        other: Default::default(),
    };
    // Attempt 1 "fails" (a provider 5xx the composer observed); the
    // SAME canonical request translates through attempt 2's adapter.
    let primary = adapter_for(AiProviderKind::Openai);
    let secondary = adapter_for(AiProviderKind::Gemini);
    let mut served_by = None;
    for (adapter, model) in [(primary, "openai-m"), (secondary, "gemini-m")] {
        match translate_for_attempt(adapter, &req, model) {
            Ok(pr) if pr.path.ends_with("generateContent") => {
                // The composer picked the gemini attempt after the
                // openai endpoint returned 5xx (simulated: first loop
                // iteration "fails").
                served_by = Some(pr);
                break;
            }
            Ok(_) => continue, // attempt failed at the (simulated) provider
            Err(e) => panic!("translation must not fail at composition: {e}"),
        }
    }
    let served = served_by.expect("composition rerouted to the secondary provider");
    assert!(served.body["contents"].is_array(), "gemini dialect body");
    // The alias never appears in either provider's translation.
    let openai_out = translate_for_attempt(primary, &req, "openai-m").unwrap();
    assert!(!serde_json::to_string(&openai_out.body)
        .unwrap()
        .contains("\"alias\""));
    assert!(!serde_json::to_string(&served.body)
        .unwrap()
        .contains("\"alias\""));
}

// ---------------------------------------------------------------------------
// Review-loop tests (reviewer findings 1 and 2).
// ---------------------------------------------------------------------------

#[test]
fn gemini_wraps_non_object_tool_output_for_function_response() {
    // Gemini's functionResponse.response is an object (proto Struct):
    // bare scalars and arrays — legal OpenAI tool results — must be
    // wrapped; only objects pass through unwrapped.
    let cases: [(&str, Value); 4] = [
        ("42", json!({"result": 42})),
        ("\"ok\"", json!({"result": "ok"})),
        ("[1,2]", json!({"result": [1, 2]})),
        ("{\"a\":1}", json!({"a": 1})),
    ];
    let adapter = adapter_for(AiProviderKind::Gemini);
    for (content, expected) in cases {
        let req = ChatRequest {
            model: "m".into(),
            messages: vec![
                ChatMessage::text(ChatRole::User, "q"),
                ChatMessage {
                    role: ChatRole::Assistant,
                    content: vec![],
                    name: None,
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "calc".into(),
                        arguments: "{}".into(),
                    }],
                    tool_call_id: None,
                },
                ChatMessage {
                    role: ChatRole::Tool,
                    content: vec![ContentPart::Text {
                        text: content.to_string(),
                    }],
                    name: None,
                    tool_calls: vec![],
                    tool_call_id: Some("c1".into()),
                },
            ],
            tools: vec![],
            tool_choice: None,
            temperature: None,
            top_p: None,
            max_tokens: None,
            stop: None,
            stream: false,
            stream_options_include_usage: false,
            other: Default::default(),
        };
        let out = adapter.build_request(&req, "m").unwrap();
        let last = out.body["contents"].as_array().unwrap().last().unwrap();
        assert_eq!(
            last["parts"][0]["functionResponse"]["response"], expected,
            "tool content {content}"
        );
    }
}

#[test]
fn anthropic_image_response_block_reads_the_real_media_type() {
    // source.type is the ENCODING ("base64"); the media type lives in
    // source.media_type and must not be derived from source.type when
    // present.
    let adapter = adapter_for(AiProviderKind::Anthropic);
    let resp = adapter
        .parse_response(&json!({
            "content": [
                {"type": "text", "text": "here"},
                {"type": "image", "source": {
                    "type": "base64", "media_type": "image/png", "data": "aGk="
                }}
            ],
            "stop_reason": "end_turn"
        }))
        .unwrap();
    let image = resp.choices[0]
        .message
        .content
        .iter()
        .find_map(|p| match p {
            ContentPart::Image { media_type, .. } => Some(media_type.clone()),
            _ => None,
        })
        .expect("image part present");
    assert_eq!(image.as_deref(), Some("image/png"));
}
