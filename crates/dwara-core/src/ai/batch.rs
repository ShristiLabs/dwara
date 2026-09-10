//! AI-04 (#194): Batch API support and half-price metering.
//!
//! OpenAI and Anthropic batch APIs are 50% cheaper than real-time
//! endpoints. The gateway proxies batch creation/status/cancel as a
//! passthrough (no translation), and when batch results are retrieved
//! the JSONL output file is parsed line-by-line. Each line's `usage`
//! object is metered at the batch rate (`batch_input_per_1k_micros` /
//! `batch_output_per_1k_micros`, falling back to standard rates when
//! batch-specific rates are not configured).
//!
//! The half-price cost computation already exists in
//! `ai::cost::PricingTable::cost_micros(batch=true)`; this module
//! provides the JSONL parsing and batch result metering.

use serde::Deserialize;
use serde_json::Value;

use crate::ai::cost::PricingTable;
use crate::ai::types::Usage;

/// One line of a batch result JSONL file. The OpenAI Batch API result
/// format has this shape per line:
/// ```json
/// {"custom_id":"request-1","response":{"id":"...","model":"gpt-4o-mini",
///  "choices":[...],"usage":{"prompt_tokens":10,"completion_tokens":5,
///  "total_tokens":15}},"error":null}
/// ```
#[derive(Debug, Deserialize)]
pub struct BatchResultLine {
    /// The client-provided custom_id for this request.
    pub custom_id: String,
    /// The response object (when successful).
    pub response: Option<BatchResponse>,
    /// The error object (when failed).
    pub error: Option<Value>,
}

/// The `response` field of a batch result line.
#[derive(Debug, Deserialize)]
pub struct BatchResponse {
    /// The model that served the request (provider model name).
    pub model: Option<String>,
    /// Token usage for this request.
    pub usage: Option<BatchUsage>,
}

/// The `usage` field of a batch response.
#[derive(Debug, Deserialize)]
pub struct BatchUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    /// OpenAI reports cached tokens here.
    pub prompt_tokens_details: Option<BatchPromptTokenDetails>,
    /// Anthropic reports cached tokens here.
    pub cache_read_input_tokens: Option<u64>,
}

/// The `prompt_tokens_details` sub-object.
#[derive(Debug, Deserialize)]
pub struct BatchPromptTokenDetails {
    pub cached_tokens: Option<u64>,
}

impl BatchUsage {
    /// Convert to the canonical `Usage` type.
    pub fn to_usage(&self) -> Usage {
        let cached = self
            .prompt_tokens_details
            .as_ref()
            .and_then(|d| d.cached_tokens)
            .or(self.cache_read_input_tokens);
        Usage {
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            total_tokens: self.total_tokens,
            cached_tokens: cached,
        }
    }
}

/// Summary of a batch result file's metering.
#[derive(Debug, Clone, Default)]
pub struct BatchMeteringSummary {
    /// Number of lines parsed.
    pub lines: u64,
    /// Number of lines with a successful response (has usage).
    pub successful: u64,
    /// Number of lines with an error.
    pub errors: u64,
    /// Total cost in micro-USD across all lines (batch rate).
    pub total_cost_micros: u64,
    /// Total prompt tokens across all lines.
    pub total_prompt_tokens: u64,
    /// Total completion tokens across all lines.
    pub total_completion_tokens: u64,
}

/// Parse a batch result JSONL file and compute the total cost at the
/// batch (50% discount) rate. Each line is parsed independently; a
/// malformed line is counted as an error and skipped.
///
/// `pricing` is the gateway's compiled pricing table. `default_model`
/// is used when a response line does not include a model field.
pub fn meter_batch_results(
    jsonl: &str,
    pricing: &PricingTable,
    default_model: &str,
) -> BatchMeteringSummary {
    let mut summary = BatchMeteringSummary::default();
    for line in jsonl.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        summary.lines += 1;
        let parsed: Result<BatchResultLine, _> = serde_json::from_str(line);
        match parsed {
            Ok(result) => {
                if result.error.is_some() {
                    summary.errors += 1;
                    continue;
                }
                if let Some(resp) = &result.response {
                    if let Some(usage) = &resp.usage {
                        let model = resp.model.as_deref().unwrap_or(default_model);
                        let canonical = usage.to_usage();
                        let cost = pricing.cost_micros(model, canonical, true).unwrap_or(0);
                        summary.total_cost_micros += cost;
                        summary.total_prompt_tokens += canonical.prompt_tokens.unwrap_or(0);
                        summary.total_completion_tokens += canonical.completion_tokens.unwrap_or(0);
                        summary.successful += 1;
                    } else {
                        // Response present but no usage — count as success
                        // but no metering.
                        summary.successful += 1;
                    }
                } else {
                    summary.errors += 1;
                }
            }
            Err(_) => {
                summary.errors += 1;
            }
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_batch_result_line() {
        let json = r#"{"custom_id":"req-1","response":{"id":"chatcmpl-x","model":"gpt-4o-mini","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}},"error":null}"#;
        let line: BatchResultLine = serde_json::from_str(json).unwrap();
        assert_eq!(line.custom_id, "req-1");
        assert!(line.error.is_none());
        let resp = line.response.unwrap();
        assert_eq!(resp.model.as_deref(), Some("gpt-4o-mini"));
        let usage = resp.usage.unwrap();
        assert_eq!(usage.prompt_tokens, Some(10));
        assert_eq!(usage.completion_tokens, Some(5));
    }

    #[test]
    fn parse_batch_result_with_cached_tokens() {
        let json = r#"{"custom_id":"req-2","response":{"model":"gpt-4o","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"prompt_tokens_details":{"cached_tokens":80}}},"error":null}"#;
        let line: BatchResultLine = serde_json::from_str(json).unwrap();
        let usage = line.response.unwrap().usage.unwrap();
        let canonical = usage.to_usage();
        assert_eq!(canonical.prompt_tokens, Some(100));
        assert_eq!(canonical.cached_tokens, Some(80));
    }

    #[test]
    fn parse_batch_result_error_line() {
        let json = r#"{"custom_id":"req-3","response":null,"error":{"message":"rate limited"}}"#;
        let line: BatchResultLine = serde_json::from_str(json).unwrap();
        assert!(line.response.is_none());
        assert!(line.error.is_some());
    }

    #[test]
    fn meter_batch_results_counts_lines() {
        let jsonl = "\
{\"custom_id\":\"req-1\",\"response\":{\"model\":\"gpt-4o-mini\",\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}},\"error\":null}\n\
{\"custom_id\":\"req-2\",\"response\":null,\"error\":{\"message\":\"failed\"}}\n\
{\"custom_id\":\"req-3\",\"response\":{\"model\":\"gpt-4o-mini\",\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":10,\"total_tokens\":30}},\"error\":null}";
        // Use an empty pricing table — cost will be 0 (unknown model),
        // but line counting should still work.
        let pricing = PricingTable::compile(None);
        let summary = meter_batch_results(jsonl, &pricing, "gpt-4o-mini");
        assert_eq!(summary.lines, 3);
        assert_eq!(summary.successful, 2);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.total_prompt_tokens, 30);
        assert_eq!(summary.total_completion_tokens, 15);
    }
}
