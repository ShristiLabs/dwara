//! Local prompt-token estimation (PERF-01): a lightweight, dependency-
//! free heuristic that estimates the prompt token count of a canonical
//! [`ChatRequest`] BEFORE the upstream provider is contacted. The
//! estimate feeds a budget pre-check that rejects requests exceeding
//! the remaining token-budget window with 429 `ai_budget_exceeded`
//! BEFORE the provider call, so a holder near the limit cannot overrun
//! by a large prompt.
//!
//! # Design: character-based heuristic, not a tokenizer
//!
//! The issue proposed `tiktoken-rs` or a BPE approximation. This module
//! implements a CHARACTER-BASED heuristic instead — no new dependency,
//! no license review, no vendored BPE merge tables. The trade-off is
//! accuracy: the heuristic approximates ~4 characters per token for
//! English text (the widely-cited rule of thumb from the OpenAI
//! cookbook), with per-message structural overhead. The estimate is
//! CONSERVATIVE (it rounds UP and adds per-message overhead) so the
//! pre-check errs on the side of rejecting rather than undercounting —
//! the actual spend is still provider-reported ([`crate::ai::budget`]
//! records the provider's `usage.total_tokens` after the call).
//!
//! # What is estimated
//!
//! - Each message's text content (role + content parts).
//! - Each tool call's name + arguments (assistant messages).
//! - Each tool definition's name + description + JSON-Schema parameters
//!   (serialized to a compact JSON string for the character count).
//! - Per-message structural overhead (role markers, formatting): a
//!   fixed 4-token allowance per message.
//! - Image parts: a conservative fixed estimate (85 tokens per image,
//!   the OpenAI `detail: low` overhead — the gateway cannot decode the
//!   image to measure its tile count, so the low-detail cost is the
//!   honest floor).
//!
//! `max_tokens` (the requested output cap) is NOT included here; the
//! caller adds it to the prompt estimate for the total-request
//! pre-check (the budget window covers total tokens, not just the
//! prompt).
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only; this module reads
//! [`crate::ai::types::ChatRequest`] (same level). No new dependencies.

use crate::ai::types::{ChatRequest, ContentPart};
use serde_json::Value;

/// Characters per token (the English-text rule of thumb; conservative
/// for code-heavy or whitespace-heavy prompts, which tokenize denser).
const CHARS_PER_TOKEN: u64 = 4;

/// Per-message structural overhead (role marker, formatting): 4 tokens.
/// This matches the OpenAI cookbook's per-message overhead for the
/// `gpt-3.5/4` family; it is a fixed allowance, not a measured value.
const PER_MESSAGE_OVERHEAD_TOKENS: u64 = 4;

/// Conservative image-part estimate: 85 tokens per image (the OpenAI
/// `detail: low` tile cost). The gateway cannot decode the image to
/// count tiles, so the low-detail floor is the honest conservative
/// estimate. A `detail: high` image costs more (up to 1700 tokens),
/// but overestimating every image as 1700 would reject valid requests
/// near the limit; the low-detail floor is the documented balance.
const IMAGE_PART_TOKENS: u64 = 85;

/// A small fixed overhead for the tool-definitions block (the
/// `tools` array wrapper and the function-call protocol framing).
const TOOLS_BLOCK_OVERHEAD_TOKENS: u64 = 16;

/// Estimate the prompt token count for a canonical [`ChatRequest`]
/// (PERF-01). The estimate is CONSERVATIVE (rounds up, adds per-message
/// overhead) so the budget pre-check errs on the side of rejecting
/// rather than undercounting. The actual spend is still provider-
/// reported ([`crate::ai::budget`] records the provider's
/// `usage.total_tokens` after the call).
///
/// The estimate covers message content, tool calls, tool definitions,
/// and structural overhead. It does NOT include `max_tokens` (the
/// requested output cap); the caller adds that for the total-request
/// pre-check.
pub fn estimate_prompt_tokens(req: &ChatRequest) -> u64 {
    let mut chars: u64 = 0;

    for msg in &req.messages {
        chars += PER_MESSAGE_OVERHEAD_TOKENS * CHARS_PER_TOKEN;
        // Role name ("system", "user", "assistant", "tool").
        chars += msg.role.as_str().len() as u64;
        // Optional name field.
        if let Some(name) = &msg.name {
            chars += name.len() as u64;
        }
        // Content parts.
        for part in &msg.content {
            match part {
                ContentPart::Text { text } => chars += text.len() as u64,
                ContentPart::Image { .. } => {
                    // Images are counted as a fixed token estimate,
                    // not characters (the base64 payload is not text
                    // the provider tokenizes character-by-character).
                    chars += IMAGE_PART_TOKENS * CHARS_PER_TOKEN;
                }
            }
        }
        // Tool calls issued by an assistant message.
        for tc in &msg.tool_calls {
            chars += tc.id.len() as u64;
            chars += tc.name.len() as u64;
            chars += tc.arguments.len() as u64;
        }
        // Tool-call-id for Tool-role messages.
        if let Some(id) = &msg.tool_call_id {
            chars += id.len() as u64;
        }
    }

    // Tool definitions: serialize each tool's JSON-Schema parameters
    // to a compact string and count characters (the schema is the bulk
    // of a tool definition's token cost).
    if !req.tools.is_empty() {
        chars += TOOLS_BLOCK_OVERHEAD_TOKENS * CHARS_PER_TOKEN;
        for tool in &req.tools {
            chars += tool.name.len() as u64;
            if let Some(desc) = &tool.description {
                chars += desc.len() as u64;
            }
            if let Some(params) = &tool.parameters {
                chars += compact_json_len(params);
            }
        }
    }

    // Convert characters to tokens, rounding UP (conservative).
    chars.div_ceil(CHARS_PER_TOKEN)
}

/// Serialize a JSON value to a compact string and return its length.
/// Falls back to 0 if serialization fails (a non-serializable schema
/// is a config error, not a token-estimation concern).
fn compact_json_len(v: &Value) -> u64 {
    serde_json::to_string(v)
        .map(|s| s.len() as u64)
        .unwrap_or(0)
}
