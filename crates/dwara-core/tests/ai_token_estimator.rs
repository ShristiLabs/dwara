//! PERF-01 integration tests: local token estimation for AI budget
//! pre-checks.
//!
//! Covers two layers:
//!
//! 1. The estimator itself ([`dwara_core::ai::token_estimator`]):
//!    empty requests, short messages, tool definitions, long prompts,
//!    and the conservative-overestimate property.
//! 2. The budget pre-check with estimation
//!    ([`BudgetGuard::check_with_estimate`]): a holder near the limit
//!    is rejected before provider contact when the estimate would push
//!    the window over.

mod support;

use dwara_core::ai::token_estimator::estimate_prompt_tokens;
use dwara_core::ai::types::{ChatMessage, ChatRequest, ChatRole, ContentPart, ToolSpec};
use std::collections::BTreeMap;

// --- estimator unit tests (public API) -------------------------------------

fn req(messages: Vec<ChatMessage>) -> ChatRequest {
    ChatRequest {
        model: "test-model".to_string(),
        messages,
        tools: Vec::new(),
        tool_choice: None,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop: None,
        stream: false,
        stream_options_include_usage: false,
        response_format: None,
        prompt: None,
        prompt_variables: BTreeMap::new(),
        other: Default::default(),
    }
}

#[test]
fn empty_request_estimates_zero() {
    let est = estimate_prompt_tokens(&req(Vec::new()));
    assert_eq!(est, 0, "empty request should estimate 0 tokens");
}

#[test]
fn short_message_estimates_reasonably() {
    let r = req(vec![ChatMessage::text(ChatRole::User, "Hello, world!")]);
    let est = estimate_prompt_tokens(&r);
    // "Hello, world!" = 13 chars + "user" = 4 + overhead 16 = 33 / 4 = 9.
    assert!((8..=12).contains(&est), "short message estimate was {est}");
}

#[test]
fn longer_message_estimates_proportionally() {
    let short = estimate_prompt_tokens(&req(vec![ChatMessage::text(ChatRole::User, "hi")]));
    let long = estimate_prompt_tokens(&req(vec![ChatMessage::text(
        ChatRole::User,
        "a".repeat(4000),
    )]));
    assert!(
        long > short + 900,
        "long prompt should estimate significantly more: {long} vs {short}"
    );
}

#[test]
fn tool_definitions_add_tokens() {
    let r_with_tools = ChatRequest {
        model: "x".to_string(),
        messages: vec![ChatMessage::text(ChatRole::User, "hi")],
        tools: vec![ToolSpec {
            name: "get_weather".to_string(),
            description: Some("Get the weather for a city".to_string()),
            parameters: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "The city name"}
                },
                "required": ["city"]
            })),
        }],
        tool_choice: None,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop: None,
        stream: false,
        stream_options_include_usage: false,
        response_format: None,
        prompt: None,
        prompt_variables: BTreeMap::new(),
        other: Default::default(),
    };
    let with_tools = estimate_prompt_tokens(&r_with_tools);
    let mut without = r_with_tools.clone();
    without.tools.clear();
    let no_tools = estimate_prompt_tokens(&without);
    assert!(
        with_tools > no_tools + 10,
        "tool definitions should add significant tokens: {with_tools} vs {no_tools}"
    );
}

#[test]
fn image_parts_estimated_as_fixed_overhead() {
    let r_text = req(vec![ChatMessage::text(ChatRole::User, "hi")]);
    let r_image = req(vec![ChatMessage {
        role: ChatRole::User,
        content: vec![ContentPart::Image {
            url: Some("data:image/png;base64,iVBORw0K".to_string()),
            media_type: Some("image/png".to_string()),
            data_b64: Some("iVBORw0K".to_string()),
        }],
        name: None,
        tool_calls: Vec::new(),
        tool_call_id: None,
    }]);
    let text_est = estimate_prompt_tokens(&r_text);
    let image_est = estimate_prompt_tokens(&r_image);
    // The image estimate should be significantly larger than the
    // short text (85 tokens for the image vs ~9 for "hi").
    assert!(
        image_est > text_est + 50,
        "image should estimate as fixed overhead: {image_est} vs {text_est}"
    );
}

#[test]
fn estimate_is_conservative_for_long_prompt() {
    let r = req(vec![ChatMessage::text(ChatRole::User, "a".repeat(4000))]);
    let est = estimate_prompt_tokens(&r);
    // 4000 chars / 4 = 1000 tokens minimum + overhead.
    assert!(
        est >= 1000,
        "conservative estimate should be >= 1000, got {est}"
    );
}

// --- budget pre-check with estimate ----------------------------------------

use dwara_core::ai::budget::{AiBudgetEngine, BudgetVerdict};
use dwara_core::config::parse_gateway;

fn gateway_with_policy_budget(tokens_per_min: u64) -> dwara_core::config::Gateway {
    let yaml = format!(
        "policies:\n\
         - name: team-a\n\
         \x20 token_budget:\n\
         \x20   tokens_per_min: {tokens_per_min}\n\
         \x20   scope: policy\n"
    );
    parse_gateway(&yaml).expect("fixture parses")
}

#[test]
fn check_with_estimate_allows_when_room_remains() {
    let gw = gateway_with_policy_budget(10_000);
    let engine = AiBudgetEngine::compile(&gw);
    let guard = engine
        .resolve(None, &["team-a".to_string()], &[], &[], &[], &[])
        .expect("budget resolves");
    let now_s = 0;
    // 500 estimated tokens, 10_000 limit, 0 spent -> allowed.
    assert_eq!(
        guard.check_with_estimate(now_s, 500),
        BudgetVerdict::Allowed
    );
}

#[test]
fn check_with_estimate_rejects_when_estimate_exceeds_remaining() {
    let gw = gateway_with_policy_budget(100);
    let engine = AiBudgetEngine::compile(&gw);
    let guard = engine
        .resolve(None, &["team-a".to_string()], &[], &[], &[], &[])
        .expect("budget resolves");
    let now_s = 0;
    // 101 estimated tokens, 100 limit, 0 spent -> rejected (strictly
    // greater: 0 + 101 > 100).
    assert_eq!(
        guard.check_with_estimate(now_s, 101),
        BudgetVerdict::Denied {
            kind: dwara_core::ai::budget::BudgetKind::Tokens,
            retry_after_s: 60,
        }
    );
}

#[test]
fn check_with_estimate_allows_exact_fit() {
    let gw = gateway_with_policy_budget(100);
    let engine = AiBudgetEngine::compile(&gw);
    let guard = engine
        .resolve(None, &["team-a".to_string()], &[], &[], &[], &[])
        .expect("budget resolves");
    let now_s = 0;
    // 100 estimated tokens, 100 limit, 0 spent -> allowed (not strictly
    // greater: 0 + 100 > 100 is false).
    assert_eq!(
        guard.check_with_estimate(now_s, 100),
        BudgetVerdict::Allowed
    );
}

#[test]
fn check_with_estimate_rejects_after_partial_spend() {
    let gw = gateway_with_policy_budget(100);
    let engine = AiBudgetEngine::compile(&gw);
    let guard = engine
        .resolve(None, &["team-a".to_string()], &[], &[], &[], &[])
        .expect("budget resolves");
    // Spend 80 tokens first.
    guard.spend(
        0,
        dwara_core::ai::types::Usage {
            prompt_tokens: Some(50),
            completion_tokens: Some(30),
            total_tokens: Some(80),
            cached_tokens: None,
        },
        0,
    );
    // 25 estimated tokens, 80 spent, 100 limit -> 80 + 25 = 105 > 100
    // -> rejected.
    assert_eq!(
        guard.check_with_estimate(0, 25),
        BudgetVerdict::Denied {
            kind: dwara_core::ai::budget::BudgetKind::Tokens,
            retry_after_s: 60,
        }
    );
    // 20 estimated tokens, 80 spent, 100 limit -> 80 + 20 = 100, not
    // strictly greater -> allowed.
    assert_eq!(guard.check_with_estimate(0, 20), BudgetVerdict::Allowed);
}

#[test]
fn check_with_estimate_still_rejects_exhausted_window() {
    let gw = gateway_with_policy_budget(100);
    let engine = AiBudgetEngine::compile(&gw);
    let guard = engine
        .resolve(None, &["team-a".to_string()], &[], &[], &[], &[])
        .expect("budget resolves");
    // Exhaust the window.
    guard.spend(
        0,
        dwara_core::ai::types::Usage {
            prompt_tokens: Some(60),
            completion_tokens: Some(50),
            total_tokens: Some(110),
            cached_tokens: None,
        },
        0,
    );
    // Even a tiny estimate should be rejected (window already
    // exhausted).
    assert_eq!(
        guard.check_with_estimate(0, 1),
        BudgetVerdict::Denied {
            kind: dwara_core::ai::budget::BudgetKind::Tokens,
            retry_after_s: 60,
        }
    );
}
