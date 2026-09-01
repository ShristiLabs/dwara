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
//! input_tokens  * input_per_1k_micros  / 1000
//! + output_tokens * output_per_1k_micros / 1000
//! ```
//!
//! Integer division truncates (the per-1k rate is the provider's
//! published unit; sub-micro-USD fractions are lost — the honest
//! rounding boundary, pinned by tests). Saturating adds guard against
//! overflow. An UNKNOWN model (no pricing entry) yields 0: fail-open,
//! never a crash — a misconfigured price table must not 500 a request.
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

/// One model's per-1k-token rates (micro-USD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Price {
    input_per_1k_micros: u64,
    output_per_1k_micros: u64,
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
    /// cost 0, fail-open).
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
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        PricingTable { prices }
    }

    /// Micro-USD for one call's usage against this pricing table.
    /// Unknown model -> 0 (fail-open). Integer micro-USD, saturating.
    pub fn cost_micros(&self, provider_model: &str, usage: Usage) -> u64 {
        let Some(price) = self.prices.get(provider_model) else {
            return 0;
        };
        let input = usage.prompt_tokens.unwrap_or(0);
        let output = usage.completion_tokens.unwrap_or(0);
        let input_cost = input.saturating_mul(price.input_per_1k_micros) / 1000;
        let output_cost = output.saturating_mul(price.output_per_1k_micros) / 1000;
        input_cost.saturating_add(output_cost)
    }

    /// Whether the table carries any pricing (cheap dataplane skip).
    pub fn is_empty(&self) -> bool {
        self.prices.is_empty()
    }
}
