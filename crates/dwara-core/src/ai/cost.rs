//! AI cost attribution (DW-079): pricing tables and per-call cost
//! computation.
//!
//! The pricing table is a COMPILED view of the `ai.pricing` config map:
//! provider model identifier -> per-1k-token micro-USD rates. It lives
//! on the dataplane behind an ArcSwap and is swapped on every config
//! reload (the same pattern as the AI budget engine), so a pricing
//! change takes effect on the NEXT request without a restart.
//!
//! # Cost computation
//!
//! `cost_micros` computes integer micro-USD for one call's usage:
//!
//! ```text
//! (input_tokens  - cached_tokens) * input_per_1k_micros  / 1000
//! + cached_tokens * cached_input_per_1k_micros           / 1000
//! + output_tokens * output_per_1k_micros                 / 1000
//! ```
//!
//! When `batch` is true, the batch rates (`batch_input_per_1k_micros`,
//! `batch_output_per_1k_micros`) replace the standard input/output
//! rates when declared; cached-token pricing is NOT combined with
//! batch rates (a batch request uses the batch rate for all input
//! tokens — the provider's batch API does not report a separate cached
//! tier). When optional fields are absent, the standard rates apply
//! (the fallback).
//!
//! Integer division truncates (the per-1k rate is the provider's
//! published unit; sub-micro-USD fractions are lost — the honest
//! rounding boundary, pinned by tests). Saturating adds guard against
//! overflow. An UNKNOWN model (no pricing entry) returns `None` — the
//! caller applies the `unknown_model_policy` (allow / fail_closed /
//! alert, DW-AI-03). The original fail-open behavior (cost 0) is
//! preserved by the `allow` policy at the call site.
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only (see `scripts/check_deps.py`); this
//! module reads `config::ai::AiConfig` and `ai::types::Usage`, both
//! same-level or lower. The spend RECORD DTO lives in `analytics` (a
//! plain struct, not importing `ai::types::Usage`) — the dataplane
//! converts at the call site, keeping the dependency direction
//! downward.

use crate::ai::types::Usage;
use crate::config::ai::AiConfig;
use std::collections::BTreeMap;

/// One model's per-1k-token rates (micro-USD). The optional cached and
/// batch fields extend the standard rates (DW-AI-03); when absent the
/// standard rates apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Price {
    input_per_1k_micros: u64,
    output_per_1k_micros: u64,
    /// Discounted rate for prompt-cached input tokens.
    cached_input_per_1k_micros: Option<u64>,
    /// Batch-API input rate.
    batch_input_per_1k_micros: Option<u64>,
    /// Batch-API output rate.
    batch_output_per_1k_micros: Option<u64>,
}

/// The compiled pricing table (DW-079): provider model -> rates. Built
/// at dataplane refresh from the published config; immutable once
/// built. Stored on the dataplane behind an ArcSwap and swapped on
/// reload, so a pricing change applies to the next request with no
/// restart.
#[derive(Debug, Clone, Default)]
pub struct PricingTable {
    prices: BTreeMap<String, Price>,
}

impl PricingTable {
    /// Compile from the `ai:` config block's pricing map. Absent or
    /// empty pricing yields an empty table (every model is unknown ->
    /// the caller applies the unknown-model policy).
    pub fn compile(cfg: Option<&AiConfig>) -> Self {
        let prices = cfg
            .map(|c| {
                c.pricing
                    .iter()
                    .map(|(model, p)| {
                        (
                            model.clone(),
                            Price {
                                input_per_1k_micros: p.input_per_1k_micros,
                                output_per_1k_micros: p.output_per_1k_micros,
                                cached_input_per_1k_micros: p.cached_input_per_1k_micros,
                                batch_input_per_1k_micros: p.batch_input_per_1k_micros,
                                batch_output_per_1k_micros: p.batch_output_per_1k_micros,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        PricingTable { prices }
    }

    /// Whether the table carries a pricing entry for `provider_model`.
    /// Cheap lookup used by the dataplane to apply the unknown-model
    /// policy (DW-AI-03) without computing the full cost.
    pub fn has_pricing(&self, provider_model: &str) -> bool {
        self.prices.contains_key(provider_model)
    }

    /// Micro-USD for one call's usage against this pricing table.
    /// Returns `None` when the model has no pricing entry (the caller
    /// applies the unknown-model policy); `Some(cost)` when it does.
    /// Integer micro-USD, saturating. When `batch` is true, batch rates
    /// replace the standard rates when declared. When
    /// `usage.cached_tokens` is present and a cached rate is declared,
    /// the cached portion of the prompt is priced at the cached rate
    /// (not combined with batch — a batch request uses the batch rate
    /// for all input tokens).
    pub fn cost_micros(&self, provider_model: &str, usage: Usage, batch: bool) -> Option<u64> {
        let price = self.prices.get(provider_model)?;
        let input = usage.prompt_tokens.unwrap_or(0);
        let output = usage.completion_tokens.unwrap_or(0);
        // Batch rates replace the standard rates when declared; cached
        // pricing is skipped under batch (the batch API does not report
        // a separate cached tier).
        if batch {
            let in_rate = price
                .batch_input_per_1k_micros
                .unwrap_or(price.input_per_1k_micros);
            let out_rate = price
                .batch_output_per_1k_micros
                .unwrap_or(price.output_per_1k_micros);
            let input_cost = input.saturating_mul(in_rate) / 1000;
            let output_cost = output.saturating_mul(out_rate) / 1000;
            return Some(input_cost.saturating_add(output_cost));
        }
        // Standard (non-batch) path: split the prompt into cached and
        // non-cached portions when both a cached rate and a cached
        // token count are present.
        let cached = usage.cached_tokens.unwrap_or(0);
        let (input_cost, cached_cost) = if let Some(cached_rate) = price.cached_input_per_1k_micros
        {
            let non_cached = input.saturating_sub(cached);
            let std_cost = non_cached.saturating_mul(price.input_per_1k_micros) / 1000;
            let cached_cost = cached.saturating_mul(cached_rate) / 1000;
            (std_cost, cached_cost)
        } else {
            let std_cost = input.saturating_mul(price.input_per_1k_micros) / 1000;
            (std_cost, 0)
        };
        let output_cost = output.saturating_mul(price.output_per_1k_micros) / 1000;
        Some(
            input_cost
                .saturating_add(cached_cost)
                .saturating_add(output_cost),
        )
    }

    /// Whether the table carries any pricing (cheap dataplane skip).
    pub fn is_empty(&self) -> bool {
        self.prices.is_empty()
    }
}
