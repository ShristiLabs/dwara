//! Integration tests for the A2A (agent-to-agent) scaffold (DW-114).
//!
//! Covers Agent Card parsing, the A2AAdapter translation (canonical
//! <-> A2A JSON), the stubbed task lifecycle, config validation, and
//! the feature-gate behavior (the block is accepted but inert without
//! the `a2a` cargo feature). The task lifecycle is STUBBED pending
//! spec freeze -- every task-state transition returns an A2AStub
//! error, which these tests assert.

#![cfg(feature = "a2a")]

use dwara_core::ai::a2a::{
    handle_a2a_request, A2AAdapter, A2ASession, AgentCardParser, CompiledA2a, CompiledA2aAgent,
    TaskLifecycle,
};
use dwara_core::ai::adapter::ProviderAdapter;
use dwara_core::ai::types::{ChatMessage, ChatRequest, ChatRole};
use dwara_core::config::ai::{A2aAgent, A2aAgentCard, A2aConfig, A2aSessions, AiProviderKind};
use dwara_core::config::parse_gateway;
use dwara_core::snapshot::validate;
use serde_json::json;
use std::collections::BTreeMap;

// --- Agent Card parsing --------------------------------------------------

#[test]
fn agent_card_parses_valid_inline() {
    let card_json = json!({
        "name": "research-agent",
        "description": "A research assistant agent",
        "url": "https://agent.example.com",
        "version": "1.0.0",
        "capabilities": {"streaming": true, "pushNotifications": false},
        "authentication": {"schemes": ["bearer"]}
    });
    let card = AgentCardParser::parse_inline(&card_json).expect("valid card parses");
    assert_eq!(card.name, "research-agent");
    assert_eq!(card.url, "https://agent.example.com");
    assert_eq!(
        card.description.as_deref(),
        Some("A research assistant agent")
    );
    assert_eq!(card.version.as_deref(), Some("1.0.0"));
    assert_eq!(card.capabilities["streaming"], json!(true));
    assert_eq!(card.authentication["schemes"][0], json!("bearer"));
}

#[test]
fn agent_card_parses_minimal_card() {
    let card_json = json!({"name": "min", "url": "https://a.example.com"});
    let card = AgentCardParser::parse_inline(&card_json).expect("minimal card parses");
    assert_eq!(card.name, "min");
    assert_eq!(card.url, "https://a.example.com");
    assert!(card.description.is_none());
    assert!(card.version.is_none());
    assert!(card.capabilities.is_null());
    assert!(card.authentication.is_null());
}

#[test]
fn agent_card_rejects_non_object() {
    let err = AgentCardParser::parse_inline(&json!("not an object")).unwrap_err();
    assert!(err.reason.contains("not a JSON object"));
}

#[test]
fn agent_card_rejects_missing_name() {
    let err = AgentCardParser::parse_inline(&json!({"url": "https://a.example.com"})).unwrap_err();
    assert!(err.reason.contains("missing the required 'name'"));
}

#[test]
fn agent_card_rejects_missing_url() {
    let err = AgentCardParser::parse_inline(&json!({"name": "a"})).unwrap_err();
    assert!(err.reason.contains("missing the required 'url'"));
}

#[test]
fn agent_card_parses_from_source_inline() {
    let source = A2aAgentCard {
        path: None,
        inline: Some(json!({"name": "src", "url": "https://b.example.com"})),
    };
    let card = AgentCardParser::parse_source(Some(&source)).expect("source parses");
    assert_eq!(card.name, "src");
}

#[test]
fn agent_card_rejects_empty_source() {
    let source = A2aAgentCard {
        path: None,
        inline: None,
    };
    let err = AgentCardParser::parse_source(Some(&source)).unwrap_err();
    assert!(err.reason.contains("neither inline nor path"));
}

#[test]
fn agent_card_rejects_missing_source() {
    let err = AgentCardParser::parse_source(None).unwrap_err();
    assert!(err.reason.contains("no card"));
}

// --- A2AAdapter build_request (canonical -> A2A JSON) -------------------

fn user_request(text: &str) -> ChatRequest {
    ChatRequest {
        model: "my-alias".to_string(),
        messages: vec![ChatMessage::text(ChatRole::User, text)],
        tools: Vec::new(),
        tool_choice: None,
        temperature: Some(0.7),
        top_p: None,
        max_tokens: Some(1024),
        stop: None,
        stream: false,
        stream_options_include_usage: false,
        other: BTreeMap::new(),
    }
}

#[test]
fn adapter_kind_is_a2a() {
    let adapter = A2AAdapter;
    assert_eq!(adapter.kind(), AiProviderKind::A2a);
}

#[test]
fn adapter_build_request_translates_to_task_submit() {
    let adapter = A2AAdapter;
    let req = user_request("Hello, agent");
    let provider_req = adapter
        .build_request(&req, "research-agent-v1")
        .expect("builds");
    assert_eq!(provider_req.method, http::Method::POST);
    assert_eq!(provider_req.path, "/tasks/submit");
    let body = &provider_req.body;
    assert_eq!(body["jsonrpc"], json!("2.0"));
    assert_eq!(body["method"], json!("tasks/submit"));
    assert_eq!(body["params"]["model"], json!("research-agent-v1"));
    assert_eq!(body["params"]["message"]["role"], json!("user"));
    assert_eq!(body["params"]["message"]["content"], json!("Hello, agent"));
    assert_eq!(body["params"]["temperature"], json!(0.7));
    assert_eq!(body["params"]["max_tokens"], json!(1024));
    // Single-message request has no history.
    assert!(body["params"].get("history").is_none());
}

#[test]
fn adapter_build_request_preserves_history() {
    let adapter = A2AAdapter;
    let req = ChatRequest {
        model: "m".to_string(),
        messages: vec![
            ChatMessage::text(ChatRole::System, "You are helpful"),
            ChatMessage::text(ChatRole::User, "first"),
            ChatMessage::text(ChatRole::Assistant, "ok"),
            ChatMessage::text(ChatRole::User, "second"),
        ],
        tools: Vec::new(),
        tool_choice: None,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop: None,
        stream: true,
        stream_options_include_usage: false,
        other: BTreeMap::new(),
    };
    let provider_req = adapter.build_request(&req, "agent").expect("builds");
    let params = &provider_req.body["params"];
    // The last message is the task message; the rest are history.
    assert_eq!(params["message"]["content"], json!("second"));
    let history = params["history"].as_array().expect("history is array");
    assert_eq!(history.len(), 3);
    assert_eq!(history[0]["role"], json!("system"));
    assert_eq!(history[2]["role"], json!("assistant"));
    assert_eq!(params["stream"], json!(true));
}

// --- A2AAdapter parse_response (A2A JSON -> canonical) ------------------

#[test]
fn adapter_parse_response_envelope() {
    let adapter = A2AAdapter;
    let body = json!({
        "jsonrpc": "2.0",
        "id": "task-1",
        "result": {
            "model": "research-agent-v1",
            "state": "completed",
            "message": {
                "role": "assistant",
                "content": "Here is your answer"
            },
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
        }
    });
    let resp = adapter.parse_response(&body).expect("parses");
    assert_eq!(resp.id.as_deref(), Some("task-1"));
    assert_eq!(resp.model.as_deref(), Some("research-agent-v1"));
    assert_eq!(resp.choices.len(), 1);
    assert_eq!(resp.choices[0].message.role, ChatRole::Assistant);
    assert_eq!(
        resp.choices[0].message.text_content(),
        "Here is your answer"
    );
    let usage = resp.usage.expect("usage present");
    assert_eq!(usage.prompt_tokens, Some(10));
    assert_eq!(usage.completion_tokens, Some(20));
    assert_eq!(usage.total_tokens, Some(30));
}

#[test]
fn adapter_parse_response_bare_message() {
    let adapter = A2AAdapter;
    let body = json!({
        "message": {"role": "assistant", "content": "bare response"}
    });
    let resp = adapter.parse_response(&body).expect("parses");
    assert_eq!(resp.choices[0].message.text_content(), "bare response");
}

#[test]
fn adapter_parse_response_rejects_non_object() {
    let adapter = A2AAdapter;
    let err = adapter.parse_response(&json!("nope")).unwrap_err();
    assert!(err.to_string().contains("not a JSON object"));
}

#[test]
fn adapter_parse_response_rejects_missing_message() {
    let adapter = A2AAdapter;
    let err = adapter.parse_response(&json!({"result": {}})).unwrap_err();
    assert!(err.to_string().contains("no message"));
}

#[test]
fn adapter_parse_error_extracts_jsonrpc_error() {
    let adapter = A2AAdapter;
    let body = json!({
        "error": {"code": -32601, "message": "method not found", "data": "not_found"}
    });
    let err = adapter.parse_error(&body);
    assert_eq!(err.message, "method not found");
    assert_eq!(err.error_type.as_deref(), Some("not_found"));
    assert_eq!(err.code.as_deref(), Some("-32601"));
}

#[test]
fn adapter_parse_error_falls_back_to_generic() {
    let adapter = A2AAdapter;
    let err = adapter.parse_error(&json!("oops"));
    assert!(!err.message.is_empty());
}

// --- A2AAdapter parse_stream_event --------------------------------------

#[test]
fn adapter_parse_stream_event_delta() {
    let adapter = A2AAdapter;
    let data = json!({
        "delta": {"role": "assistant", "content": "chunk"},
        "state": "working"
    });
    let events = adapter.parse_stream_event(&data).expect("parses");
    assert_eq!(events.len(), 1);
    match &events[0] {
        dwara_core::ai::types::StreamEvent::Delta(d) => {
            assert_eq!(d.content.as_deref(), Some("chunk"));
            assert_eq!(d.role, Some(ChatRole::Assistant));
        }
        other => panic!("expected Delta, got {other:?}"),
    }
}

#[test]
fn adapter_parse_stream_event_usage() {
    let adapter = A2AAdapter;
    let data = json!({"usage": {"prompt_tokens": 5, "completion_tokens": 5}});
    let events = adapter.parse_stream_event(&data).expect("parses");
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        dwara_core::ai::types::StreamEvent::Usage(_)
    ));
}

// --- A2A stub: task lifecycle returns stub error -------------------------

#[test]
fn task_lifecycle_transitions_return_stub() {
    let states = [
        TaskLifecycle::Submitted,
        TaskLifecycle::Working,
        TaskLifecycle::Completed,
        TaskLifecycle::Failed,
        TaskLifecycle::Canceled,
    ];
    for s in &states {
        let err = s.submit().unwrap_err();
        assert_eq!(err.transition, "submit");
        assert!(err.reason.contains("not yet frozen"));
        let err = s.get_status().unwrap_err();
        assert_eq!(err.transition, "get_status");
        let err = s.cancel().unwrap_err();
        assert_eq!(err.transition, "cancel");
    }
}

#[test]
fn session_task_methods_return_stub() {
    let session = A2ASession::new("my-agent", 3600, 1000);
    assert!(session.id().starts_with("a2a-"));
    let err = session.submit_task().unwrap_err();
    assert_eq!(err.transition, "submit_task");
    let err = session.get_task_status().unwrap_err();
    assert_eq!(err.transition, "get_task_status");
    let err = session.cancel_task().unwrap_err();
    assert_eq!(err.transition, "cancel_task");
}

#[test]
fn handle_a2a_request_returns_stub() {
    let agent = CompiledA2aAgent {
        name: "a".to_string(),
        url: "https://agent.example.com".to_string(),
        card: None,
        upstream: "u".to_string(),
        sessions_ttl_secs: 3600,
        sessions_max_concurrent: 1000,
    };
    let req = user_request("hi");
    let err = handle_a2a_request(&agent, &req).unwrap_err();
    assert_eq!(err.transition, "handle_a2a_request");
}

// --- CompiledA2a compile -------------------------------------------------

#[test]
fn compiled_a2a_none_when_absent() {
    assert!(CompiledA2a::compile(None).is_none());
}

#[test]
fn compiled_a2a_none_when_disabled() {
    let cfg = A2aConfig {
        enabled: false,
        agents: vec![A2aAgent {
            name: "a".to_string(),
            url: "https://a.example.com".to_string(),
            card: None,
            upstream: "u".to_string(),
        }],
        sessions: None,
    };
    assert!(CompiledA2a::compile(Some(&cfg)).is_none());
}

#[test]
fn compiled_a2a_compiles_enabled_agents() {
    let cfg = A2aConfig {
        enabled: true,
        agents: vec![A2aAgent {
            name: "research".to_string(),
            url: "https://agent.example.com".to_string(),
            card: Some(A2aAgentCard {
                path: None,
                inline: Some(json!({"name": "research", "url": "https://agent.example.com"})),
            }),
            upstream: "agent-pool".to_string(),
        }],
        sessions: Some(A2aSessions {
            ttl_secs: Some(7200),
            max_concurrent: Some(500),
        }),
    };
    let compiled = CompiledA2a::compile(Some(&cfg)).expect("compiles");
    assert_eq!(compiled.sessions_ttl_secs, 7200);
    assert_eq!(compiled.sessions_max_concurrent, 500);
    let agent = compiled.agent("research").expect("agent present");
    assert_eq!(agent.url, "https://agent.example.com");
    assert_eq!(agent.upstream, "agent-pool");
    assert!(agent.card.is_some());
}

#[test]
fn compiled_a2a_uses_defaults_when_sessions_absent() {
    let cfg = A2aConfig {
        enabled: true,
        agents: vec![A2aAgent {
            name: "a".to_string(),
            url: "https://a.example.com".to_string(),
            card: None,
            upstream: "u".to_string(),
        }],
        sessions: None,
    };
    let compiled = CompiledA2a::compile(Some(&cfg)).expect("compiles");
    assert_eq!(compiled.sessions_ttl_secs, 3600);
    assert_eq!(compiled.sessions_max_concurrent, 1000);
}

#[test]
fn compiled_a2a_compiles_without_card() {
    let cfg = A2aConfig {
        enabled: true,
        agents: vec![A2aAgent {
            name: "a".to_string(),
            url: "https://a.example.com".to_string(),
            card: None,
            upstream: "u".to_string(),
        }],
        sessions: None,
    };
    let compiled = CompiledA2a::compile(Some(&cfg)).expect("compiles");
    let agent = compiled.agent("a").expect("agent present");
    assert!(agent.card.is_none());
}

// --- Config validation ---------------------------------------------------

fn a2a_gateway_yaml(a2a_block: &str) -> String {
    format!(
        "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9000\n\
         - name: agent-pool\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9001\n\
         {a2a_block}"
    )
}

#[test]
fn valid_a2a_config_passes_validation() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: my-agent\n\
         \x20       url: https://agent.example.com\n\
         \x20       upstream: agent-pool\n\
         \x20       card:\n\
         \x20         inline:\n\
         \x20           name: my-agent\n\
         \x20           url: https://agent.example.com\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    let a2a_issues: Vec<_> = issues
        .iter()
        .filter(|i| i.field.starts_with("ai.a2a"))
        .collect();
    assert!(
        a2a_issues.is_empty(),
        "expected no a2a validation issues, got: {a2a_issues:?}"
    );
}

#[test]
fn validation_rejects_duplicate_agent_names() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: dup\n\
         \x20       url: https://a.example.com\n\
         \x20       upstream: agent-pool\n\
         \x20     - name: dup\n\
         \x20       url: https://b.example.com\n\
         \x20       upstream: agent-pool\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "ai.a2a.agents[].name" && i.message.contains("duplicate")),
        "expected duplicate-name issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_empty_agent_name() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: ''\n\
         \x20       url: https://a.example.com\n\
         \x20       upstream: agent-pool\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "ai.a2a.agents[].name" && i.message.contains("non-empty")),
        "expected empty-name issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_unknown_upstream() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: a\n\
         \x20       url: https://a.example.com\n\
         \x20       upstream: no-such-upstream\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(
            |i| i.field == "ai.a2a.agents[].upstream" && i.message.contains("unknown upstream")
        ),
        "expected unknown-upstream issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_non_http_url() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: a\n\
         \x20       url: ftp://a.example.com\n\
         \x20       upstream: agent-pool\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "ai.a2a.agents[].url" && i.message.contains("http or https")),
        "expected non-http-url issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_non_object_inline_card() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: a\n\
         \x20       url: https://a.example.com\n\
         \x20       upstream: agent-pool\n\
         \x20       card:\n\
         \x20         inline: \"not-an-object\"\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "ai.a2a.agents[].card.inline"),
        "expected inline-card issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_zero_session_ttl() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: a\n\
         \x20       url: https://a.example.com\n\
         \x20       upstream: agent-pool\n\
         \x20   sessions:\n\
         \x20     ttl_secs: 0\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "ai.a2a.sessions.ttl_secs"),
        "expected ttl_secs issue, got: {issues:?}"
    );
}

#[test]
fn validation_rejects_zero_max_concurrent() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: a\n\
         \x20       url: https://a.example.com\n\
         \x20       upstream: agent-pool\n\
         \x20   sessions:\n\
         \x20     max_concurrent: 0\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "ai.a2a.sessions.max_concurrent"),
        "expected max_concurrent issue, got: {issues:?}"
    );
}

// --- Feature gate: without a2a feature, config is accepted but inert ----
// (This test file is compiled only with --features a2a, so the inert
// path is verified structurally: CompiledA2a::compile returns None
// when the feature is off. The snapshot validation warning for the
// inert block is gated by #[cfg(not(feature = "a2a"))] in snapshot.rs;
// it is exercised by the default-feature CI run, not here.)

#[test]
fn a2a_config_parses_via_yaml() {
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: my-agent\n\
         \x20       url: https://agent.example.com\n\
         \x20       upstream: agent-pool\n\
         \x20       card:\n\
         \x20         inline:\n\
         \x20           name: my-agent\n\
         \x20           url: https://agent.example.com\n\
         \x20           version: '2.0'\n\
         \x20   sessions:\n\
         \x20     ttl_secs: 1800\n\
         \x20     max_concurrent: 200\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let a2a = gateway
        .ai
        .as_ref()
        .and_then(|ai| ai.a2a.as_ref())
        .expect("a2a block present");
    assert!(a2a.enabled);
    assert_eq!(a2a.agents.len(), 1);
    assert_eq!(a2a.agents[0].name, "my-agent");
    assert_eq!(a2a.agents[0].upstream, "agent-pool");
    assert_eq!(a2a.sessions.as_ref().unwrap().ttl_secs, Some(1800));
    assert_eq!(a2a.sessions.as_ref().unwrap().max_concurrent, Some(200));
}

#[test]
fn a2a_agents_appear_as_providers_in_runtime() {
    use dwara_core::ai::AiRuntime;
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 providers:\n\
         \x20   - name: openai-pool\n\
         \x20     kind: openai\n\
         \x20     upstream: up\n\
         \x20 models:\n\
         \x20   my-alias:\n\
         \x20     provider: my-agent\n\
         \x20     provider_model: research-v1\n\
         \x20 a2a:\n\
         \x20   enabled: true\n\
         \x20   agents:\n\
         \x20     - name: my-agent\n\
         \x20       url: https://agent.example.com\n\
         \x20       upstream: agent-pool\n\
         \x20       card:\n\
         \x20         inline:\n\
         \x20           name: my-agent\n\
         \x20           url: https://agent.example.com\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let ai = gateway.ai.as_ref().expect("ai block present");
    let rt = AiRuntime::compile(Some(ai), &gateway).expect("runtime compiles");
    // The A2A agent appears as a provider of kind a2a.
    let provider = rt.provider("my-agent").expect("a2a provider wired");
    assert_eq!(provider.kind, AiProviderKind::A2a);
    assert_eq!(provider.upstream, "agent-pool");
    // The alias resolves to the A2A provider.
    let (resolved_provider, model) = rt.resolve("my-alias").expect("alias resolves");
    assert_eq!(resolved_provider.name, "my-agent");
    assert_eq!(model, "research-v1");
    // The compiled A2A surface is present.
    let a2a = rt.a2a().expect("a2a surface compiled");
    assert!(a2a.agent("my-agent").is_some());
}

#[test]
fn a2a_runtime_absent_when_disabled() {
    use dwara_core::ai::AiRuntime;
    let yaml = a2a_gateway_yaml(
        "ai:\n\
         \x20 providers:\n\
         \x20   - name: openai-pool\n\
         \x20     kind: openai\n\
         \x20     upstream: up\n\
         \x20 models:\n\
         \x20   my-alias:\n\
         \x20     provider: openai-pool\n\
         \x20     provider_model: gpt-4o-mini\n\
         \x20 a2a:\n\
         \x20   enabled: false\n\
         \x20   agents:\n\
         \x20     - name: my-agent\n\
         \x20       url: https://agent.example.com\n\
         \x20       upstream: agent-pool\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let ai = gateway.ai.as_ref().expect("ai block present");
    let rt = AiRuntime::compile(Some(ai), &gateway).expect("runtime compiles");
    // Disabled block: no A2A surface, no A2A provider wired.
    assert!(rt.a2a().is_none());
    assert!(rt.provider("my-agent").is_none());
}

// --- AgentCard round-trip through the parser (file path) ----------------

#[test]
fn agent_card_parses_from_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("card.json");
    let card_json = json!({
        "name": "file-agent",
        "url": "https://file.example.com",
        "version": "3.0"
    });
    std::fs::write(&path, card_json.to_string()).expect("write card");
    let card = AgentCardParser::parse_path(path.to_str().unwrap()).expect("parses");
    assert_eq!(card.name, "file-agent");
    assert_eq!(card.version.as_deref(), Some("3.0"));
}

#[test]
fn agent_card_rejects_missing_file() {
    let err = AgentCardParser::parse_path("/nonexistent/path/card.json").unwrap_err();
    assert!(err.reason.contains("could not read"));
}

#[test]
fn agent_card_rejects_malformed_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "not json {{{").expect("write bad card");
    let err = AgentCardParser::parse_path(path.to_str().unwrap()).unwrap_err();
    assert!(err.reason.contains("not valid JSON"));
}
