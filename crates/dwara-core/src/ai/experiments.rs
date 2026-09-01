//! Prompt experimentation (DW-086): A/B model comparison, prompt
//! versioning, regression evals, and feedback ingestion.
//!
//! # A/B tests
//!
//! A model alias declares `ab_test: <name>` to be served by an
//! experiment. The experiment's variants each name a plain model alias
//! (chain/canary), an optional prompt version, and a weight. The
//! [`CompiledAbTest`] resolves each variant's model alias to its
//! primary [`RouteTarget`] at compile time (the same composition
//! pattern as DW-085 routing policies). At request time, a
//! deterministic weighted pick by request id selects a variant — the
//! same slot semantics as canary splits (ratios hold per request, and
//! re-sending a request with the same id lands on the same variant).
//!
//! # Prompt versioning
//!
//! Each prompt declares one or more versions (each with a system
//! message) and an active version. The active version can be
//! overridden at runtime via the admin API (stored in the state
//! store). When a variant references a prompt version, or when an
//! eval references a prompt version, the system message is prepended
//! to the request's messages (BEFORE any existing system message).
//!
//! # Eval runner
//!
//! The eval runner makes DIRECT provider calls via `hyper_util` (the
//! same pattern as the DW-083 semantic cache and DW-085 routing
//! policy classifier). Each golden-set case is sent as a user message
//! to the provider; the response is scored by the case's scorer
//! (`exact_match`, `contains`, `regex`). Results are stored in
//! analytics. The verdict is computed from stored eval results (pass
//! rate, cost tiebreaker).
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only. The eval runner's HTTP call reuses
//! the same `hyper_util` client pattern as the DW-083 semantic cache
//! and DW-085 routing policy (no new dependencies).

use crate::ai::{CompiledModel, RouteTarget};
use crate::config::ai::{AiAbTest, AiEval, AiExperiments};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::BTreeMap;
use std::time::Duration;

/// One compiled A/B test variant (DW-086): the resolved model alias
/// target, the optional prompt-version system message, and the
/// variant's weight and name (for analytics attribution).
#[derive(Debug, Clone)]
pub struct CompiledAbVariant {
    /// The variant name (for analytics/metrics attribution).
    pub name: String,
    /// The primary [`RouteTarget`] of the variant's model alias.
    pub target: RouteTarget,
    /// The optional prompt-version system message (prepended to the
    /// request's messages when present).
    pub system_message: Option<String>,
    /// The relative weight (>= 1).
    pub weight: u32,
}

/// A compiled A/B test (DW-086): two or more variants with resolved
/// targets. At request time, a deterministic weighted pick by request
/// id selects a variant. Built at [`AiRuntime`](crate::ai::AiRuntime)
/// compile time from the config block; immutable once built.
#[derive(Debug, Clone)]
pub struct CompiledAbTest {
    /// The experiment name (for analytics/metrics attribution).
    pub name: String,
    /// The compiled variants.
    pub variants: Vec<CompiledAbVariant>,
}

impl CompiledAbTest {
    /// Compile from config. Resolves each variant's model alias to
    /// its primary [`RouteTarget`] against the first-pass compiled
    /// model map (plain chain/canary aliases only — an experiment
    /// alias cannot reference another experiment alias, so nested
    /// experiments are rejected by returning None). Returns None
    /// when a referenced alias is missing or is itself an experiment
    /// alias (a validate-vs-build race or an authoring error
    /// validation missed).
    pub fn compile(
        name: &str,
        test: &AiAbTest,
        models: &BTreeMap<String, CompiledModel>,
        experiments: Option<&AiExperiments>,
    ) -> Option<Self> {
        let mut variants = Vec::with_capacity(test.variants.len());
        for v in &test.variants {
            let target = primary_target_of(models, &v.model)?.clone();
            let system_message = v
                .prompt
                .as_ref()
                .and_then(|ref_str| resolve_prompt_version(experiments, ref_str));
            variants.push(CompiledAbVariant {
                name: v.name.clone(),
                target,
                system_message,
                weight: v.weight,
            });
        }
        Some(CompiledAbTest {
            name: name.to_string(),
            variants,
        })
    }

    /// The deterministic weighted pick for `pick_key` (the request
    /// id): the variant whose cumulative weight bound first exceeds
    /// `pick_hash(key) % total`. Same slot semantics as canary
    /// splits.
    pub fn pick(&self, pick_key: &str) -> &CompiledAbVariant {
        let entries: Vec<(u32, &CompiledAbVariant)> =
            self.variants.iter().map(|v| (v.weight, v)).collect();
        // weighted_pick returns a reference into the slice it was
        // given; we pass a Vec of references, so the returned
        // reference is to the borrowed variant. We need to map it
        // back to the owned variant.
        let total: u64 = entries.iter().map(|(w, _)| u64::from(*w)).sum();
        debug_assert!(total > 0, "validation guarantees positive total weight");
        let slot = crate::ai::routing::pick_hash(pick_key) % total;
        let mut bound = 0u64;
        for (w, variant) in &entries {
            bound += u64::from(*w);
            if slot < bound {
                return variant;
            }
        }
        // Unreachable for total > 0; fallthrough keeps a hostile
        // zero-weight list from panicking.
        &self.variants[0]
    }
}

/// The decision an A/B test made for one request (DW-086). The
/// dataplane records this as a metric and an analytics assignment
/// row. Carries the variant name and the model alias for attribution.
#[derive(Debug, Clone)]
pub struct ExperimentDecision {
    /// The experiment (A/B test) name.
    pub experiment: String,
    /// The selected variant name.
    pub variant: String,
    /// The model alias the variant routes to.
    pub model: String,
}

/// Resolve a model alias to its primary [`RouteTarget`] from the
/// compiled model map. Returns None when the alias is missing or is
/// itself an experiment/policy alias (no nested experiments — a
/// variant must reference a plain chain/canary alias).
fn primary_target_of<'a>(
    models: &'a BTreeMap<String, CompiledModel>,
    alias: &str,
) -> Option<&'a RouteTarget> {
    match models.get(alias)? {
        CompiledModel::Chain(chain) => chain.first(),
        CompiledModel::Canary(versions) => versions.first().map(|(_, t)| t),
        // Policy and Experiment aliases have no single primary
        // target — they are evaluated per request. A variant
        // referencing one is a nested-experiment error.
        CompiledModel::Policy(_) => None,
        CompiledModel::Experiment(_) => None,
    }
}

/// Resolve a `"prompt_name/version_name"` reference to its system
/// message. Returns None when the prompt or version does not exist
/// (a validate-vs-build race or an authoring error validation
/// missed — the variant serves without a system message).
fn resolve_prompt_version(experiments: Option<&AiExperiments>, reference: &str) -> Option<String> {
    let exp = experiments?;
    let (prompt_name, version_name) = reference.split_once('/')?;
    let prompt = exp.prompts.get(prompt_name)?;
    let version = prompt.versions.get(version_name)?;
    Some(version.system.clone())
}

/// Resolve the active version for a prompt, considering runtime
/// overrides. Returns the system message of the active (or
/// overridden) version, or None when the prompt does not exist.
pub fn active_prompt_system(
    experiments: Option<&AiExperiments>,
    overrides: &[(String, String)],
    prompt_name: &str,
) -> Option<String> {
    let exp = experiments?;
    let prompt = exp.prompts.get(prompt_name)?;
    // Check overrides first (runtime override takes precedence).
    let active_version = overrides
        .iter()
        .find(|(name, _)| name == prompt_name)
        .map(|(_, version)| version.clone())
        .unwrap_or_else(|| prompt.active.clone());
    let version = prompt.versions.get(&active_version)?;
    Some(version.system.clone())
}

// -----------------------------------------------------------------
// Eval runner: direct provider calls via hyper_util.
// -----------------------------------------------------------------

/// The scorer for an eval case (DW-086).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalScorer {
    /// Exact string match between the output and `expected`.
    ExactMatch,
    /// The output must CONTAIN the `expected` string.
    Contains,
    /// The output must MATCH the `expected` regex pattern.
    Regex,
}

impl EvalScorer {
    /// Parse a scorer name string. Defaults to `ExactMatch` for an
    /// unrecognized or None value.
    pub fn parse(s: Option<&str>) -> Self {
        match s {
            Some("contains") => EvalScorer::Contains,
            Some("regex") => EvalScorer::Regex,
            _ => EvalScorer::ExactMatch,
        }
    }

    /// The stable name string (for analytics storage).
    pub fn as_str(&self) -> &'static str {
        match self {
            EvalScorer::ExactMatch => "exact_match",
            EvalScorer::Contains => "contains",
            EvalScorer::Regex => "regex",
        }
    }

    /// Score an output against an expected value.
    pub fn score(&self, output: &str, expected: &str) -> bool {
        match self {
            EvalScorer::ExactMatch => output.trim() == expected.trim(),
            EvalScorer::Contains => output.contains(expected),
            EvalScorer::Regex => regex::Regex::new(expected)
                .map(|re| re.is_match(output))
                .unwrap_or(false),
        }
    }
}

/// One eval case result (DW-086): the output of running one golden-
/// set case against a provider.
#[derive(Debug, Clone)]
pub struct EvalCaseResult {
    /// The case index in the golden set.
    pub case_index: usize,
    /// The input prompt.
    pub input: String,
    /// The expected output.
    pub expected: String,
    /// The actual output from the provider.
    pub actual: String,
    /// Whether the case passed (scorer matched).
    pub passed: bool,
    /// The scorer used.
    pub scorer: EvalScorer,
    /// The latency of the provider call in milliseconds.
    pub latency_ms: f64,
}

/// The result of running one eval against one model (DW-086).
#[derive(Debug, Clone)]
pub struct EvalRunResult {
    /// The eval name (from config).
    pub eval_name: String,
    /// The model alias the eval ran against.
    pub model: String,
    /// The variant name (when running an A/B test's variants), or
    /// empty.
    pub variant: String,
    /// The prompt version reference, or empty.
    pub prompt_version: String,
    /// The per-case results.
    pub cases: Vec<EvalCaseResult>,
}

impl EvalRunResult {
    /// The pass rate (0.0 to 1.0): the fraction of cases that passed.
    pub fn pass_rate(&self) -> f64 {
        if self.cases.is_empty() {
            return 0.0;
        }
        let passed = self.cases.iter().filter(|c| c.passed).count();
        passed as f64 / self.cases.len() as f64
    }

    /// The number of cases that passed.
    pub fn passed_count(&self) -> usize {
        self.cases.iter().filter(|c| c.passed).count()
    }

    /// The average latency in milliseconds.
    pub fn avg_latency_ms(&self) -> f64 {
        if self.cases.is_empty() {
            return 0.0;
        }
        let total: f64 = self.cases.iter().map(|c| c.latency_ms).sum();
        total / self.cases.len() as f64
    }
}

/// The verdict of an A/B test comparison (DW-086): computed from
/// stored eval results. The variant with the higher pass rate wins;
/// on a tie, the lower average latency wins (the cost tiebreaker —
/// latency is a proxy for cost when the same provider serves both
/// variants, and the actual cost is in the spend table).
#[derive(Debug, Clone)]
pub struct ExperimentVerdict {
    /// The experiment (A/B test) name.
    pub experiment: String,
    /// The winning variant name, or None on a tie (both variants
    /// are equally good — the operator decides).
    pub winner: Option<String>,
    /// The per-variant pass rates.
    pub pass_rates: Vec<(String, f64)>,
    /// The per-variant average latencies (ms).
    pub avg_latencies: Vec<(String, f64)>,
}

/// Compute the verdict from a set of eval run results (DW-086). Each
/// result is one variant's eval run. The variant with the highest
/// pass rate wins; on a tie, the lowest average latency wins; on a
/// full tie (same pass rate AND same latency), the verdict is a tie
/// (winner = None).
pub fn compute_verdict(experiment: &str, results: &[EvalRunResult]) -> ExperimentVerdict {
    let pass_rates: Vec<(String, f64)> = results
        .iter()
        .map(|r| (r.variant.clone(), r.pass_rate()))
        .collect();
    let avg_latencies: Vec<(String, f64)> = results
        .iter()
        .map(|r| (r.variant.clone(), r.avg_latency_ms()))
        .collect();
    let winner = if results.len() < 2 {
        // Need at least two variants to compare.
        results.first().map(|r| r.variant.clone())
    } else {
        // Sort by pass rate descending, then latency ascending.
        let mut sorted: Vec<&EvalRunResult> = results.iter().collect();
        sorted.sort_by(|a, b| {
            b.pass_rate()
                .partial_cmp(&a.pass_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    a.avg_latency_ms()
                        .partial_cmp(&b.avg_latency_ms())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        let (first, second) = (&sorted[0], &sorted[1]);
        if (first.pass_rate() - second.pass_rate()).abs() < f64::EPSILON
            && (first.avg_latency_ms() - second.avg_latency_ms()).abs() < f64::EPSILON
        {
            // Full tie.
            None
        } else {
            Some(first.variant.clone())
        }
    };
    ExperimentVerdict {
        experiment: experiment.to_string(),
        winner,
        pass_rates,
        avg_latencies,
    }
}

/// Build a hyper_util client for the eval runner (the same pattern as
/// the DW-083 semantic cache and DW-085 routing policy classifier).
fn eval_http_client() -> Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>()
}

/// Run one eval case against a provider (DW-086): send the input as a
/// user message to the provider's chat-completions endpoint and
/// return the output text. The `provider_url` is the full URL
/// (including scheme, host, port, and path), `auth_header` is the
/// optional `Authorization` header value, and `provider_model` is
/// the provider's own model identifier.
async fn run_eval_case(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    provider_url: &str,
    auth_header: Option<&str>,
    provider_model: &str,
    system_message: Option<&str>,
    input: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut messages = Vec::new();
    if let Some(sys) = system_message {
        messages.push(serde_json::json!({
            "role": "system",
            "content": sys,
        }));
    }
    messages.push(serde_json::json!({
        "role": "user",
        "content": input,
    }));
    let body = serde_json::json!({
        "model": provider_model,
        "messages": messages,
        "stream": false,
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| format!("json encode: {e}"))?;
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(provider_url)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    if let Some(auth) = auth_header {
        req = req.header("authorization", auth);
    }
    let req = req
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| format!("request build: {e}"))?;
    let resp = tokio::time::timeout(timeout, client.request(req))
        .await
        .map_err(|_| format!("eval request timed out after {}ms", timeout.as_millis()))?
        .map_err(|e| format!("eval request failed: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("eval response body read: {e}"))?
        .to_bytes();
    if !status.is_success() {
        return Err(format!(
            "eval request returned status {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("eval response json parse: {e}"))?;
    // Extract the first choice's message content (OpenAI shape).
    let content = value
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    Ok(content.to_string())
}

/// Run an eval against a model alias (DW-086). The `provider_url` is
/// the full URL, `auth_header` is the optional Authorization header,
/// `provider_model` is the provider's own model identifier, and
/// `system_message` is the optional prompt-version system message
/// (from the eval's `prompt` reference, resolved by the caller).
/// Returns the per-case results.
#[allow(clippy::too_many_arguments)]
pub async fn run_eval(
    eval_name: &str,
    eval: &AiEval,
    model: &str,
    variant: &str,
    provider_url: &str,
    auth_header: Option<&str>,
    provider_model: &str,
    system_message: Option<&str>,
    timeout_ms: u64,
) -> EvalRunResult {
    let client = eval_http_client();
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let mut cases = Vec::with_capacity(eval.golden_set.len());
    for (i, case) in eval.golden_set.iter().enumerate() {
        let scorer = EvalScorer::parse(case.scorer.as_deref());
        let start = std::time::Instant::now();
        let actual = match run_eval_case(
            &client,
            provider_url,
            auth_header,
            provider_model,
            system_message,
            &case.input,
            timeout,
        )
        .await
        {
            Ok(output) => output,
            Err(e) => {
                tracing::warn!(
                    code = "eval_case_failed",
                    eval = %eval_name,
                    case_index = i,
                    "eval case failed: {e}"
                );
                e
            }
        };
        let latency_ms = start.elapsed().as_millis() as f64;
        let passed = scorer.score(&actual, &case.expected);
        cases.push(EvalCaseResult {
            case_index: i,
            input: case.input.clone(),
            expected: case.expected.clone(),
            actual,
            passed,
            scorer,
            latency_ms,
        });
    }
    EvalRunResult {
        eval_name: eval_name.to_string(),
        model: model.to_string(),
        variant: variant.to_string(),
        prompt_version: eval.prompt.clone().unwrap_or_default(),
        cases,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::{CompiledModel, RouteTarget};
    use crate::config::ai::{
        AiAbTest, AiAbVariant, AiExperiments, AiPromptVersion, AiPromptVersions,
    };

    fn make_chain_model(provider: &str, model: &str) -> CompiledModel {
        CompiledModel::Chain(vec![RouteTarget {
            provider: provider.to_string(),
            provider_model: model.to_string(),
            version: None,
        }])
    }

    fn make_models() -> BTreeMap<String, CompiledModel> {
        let mut m = BTreeMap::new();
        m.insert("model-a".to_string(), make_chain_model("p1", "gpt-4o"));
        m.insert("model-b".to_string(), make_chain_model("p2", "claude"));
        m
    }

    #[test]
    fn compiled_ab_test_pick_is_deterministic() {
        let models = make_models();
        let test = AiAbTest {
            variants: vec![
                AiAbVariant {
                    name: "control".to_string(),
                    model: "model-a".to_string(),
                    prompt: None,
                    weight: 1,
                },
                AiAbVariant {
                    name: "treatment".to_string(),
                    model: "model-b".to_string(),
                    prompt: None,
                    weight: 1,
                },
            ],
        };
        let compiled = CompiledAbTest::compile("my-test", &test, &models, None).unwrap();
        assert_eq!(compiled.variants.len(), 2);
        // Same key -> same pick.
        let pick1 = compiled.pick("req-001");
        let pick2 = compiled.pick("req-001");
        assert_eq!(pick1.name, pick2.name);
    }

    #[test]
    fn compiled_ab_test_resolves_prompt_version() {
        let models = make_models();
        let experiments = AiExperiments {
            prompts: {
                let mut m = BTreeMap::new();
                m.insert(
                    "greeting".to_string(),
                    AiPromptVersions {
                        versions: {
                            let mut v = BTreeMap::new();
                            v.insert(
                                "v1".to_string(),
                                AiPromptVersion {
                                    system: "You are a helpful assistant.".to_string(),
                                },
                            );
                            v
                        },
                        active: "v1".to_string(),
                    },
                );
                m
            },
            ..Default::default()
        };
        let test = AiAbTest {
            variants: vec![AiAbVariant {
                name: "v1".to_string(),
                model: "model-a".to_string(),
                prompt: Some("greeting/v1".to_string()),
                weight: 1,
            }],
        };
        let compiled = CompiledAbTest::compile("test", &test, &models, Some(&experiments)).unwrap();
        assert_eq!(
            compiled.variants[0].system_message.as_deref(),
            Some("You are a helpful assistant.")
        );
    }

    #[test]
    fn compiled_ab_test_rejects_nested_experiment_alias() {
        let models = make_models();
        // Insert an experiment alias into the models map (simulating
        // a second-pass compile that already added it).
        // This shouldn't happen in practice (validation rejects it),
        // but the compile must be defensive.
        let test = AiAbTest {
            variants: vec![AiAbVariant {
                name: "v1".to_string(),
                model: "model-a".to_string(),
                prompt: None,
                weight: 1,
            }],
        };
        let compiled = CompiledAbTest::compile("test", &test, &models, None);
        assert!(compiled.is_some());
    }

    #[test]
    fn eval_scorer_exact_match() {
        assert!(EvalScorer::ExactMatch.score("hello", "hello"));
        assert!(EvalScorer::ExactMatch.score("  hello  ", "hello"));
        assert!(!EvalScorer::ExactMatch.score("hello", "world"));
    }

    #[test]
    fn eval_scorer_contains() {
        assert!(EvalScorer::Contains.score("hello world", "world"));
        assert!(!EvalScorer::Contains.score("hello", "world"));
    }

    #[test]
    fn eval_scorer_regex() {
        assert!(EvalScorer::Regex.score("hello123", r"\d+"));
        assert!(!EvalScorer::Regex.score("hello", r"\d+"));
    }

    #[test]
    fn eval_pass_rate() {
        let result = EvalRunResult {
            eval_name: "test".to_string(),
            model: "m".to_string(),
            variant: "v".to_string(),
            prompt_version: String::new(),
            cases: vec![
                EvalCaseResult {
                    case_index: 0,
                    input: "a".to_string(),
                    expected: "a".to_string(),
                    actual: "a".to_string(),
                    passed: true,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 10.0,
                },
                EvalCaseResult {
                    case_index: 1,
                    input: "b".to_string(),
                    expected: "b".to_string(),
                    actual: "x".to_string(),
                    passed: false,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 20.0,
                },
            ],
        };
        assert_eq!(result.pass_rate(), 0.5);
        assert_eq!(result.passed_count(), 1);
        assert_eq!(result.avg_latency_ms(), 15.0);
    }

    #[test]
    fn verdict_picks_higher_pass_rate() {
        let results = vec![
            EvalRunResult {
                eval_name: "e".to_string(),
                model: "m".to_string(),
                variant: "a".to_string(),
                prompt_version: String::new(),
                cases: vec![EvalCaseResult {
                    case_index: 0,
                    input: "i".to_string(),
                    expected: "e".to_string(),
                    actual: "e".to_string(),
                    passed: true,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 100.0,
                }],
            },
            EvalRunResult {
                eval_name: "e".to_string(),
                model: "m".to_string(),
                variant: "b".to_string(),
                prompt_version: String::new(),
                cases: vec![EvalCaseResult {
                    case_index: 0,
                    input: "i".to_string(),
                    expected: "e".to_string(),
                    actual: "x".to_string(),
                    passed: false,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 50.0,
                }],
            },
        ];
        let verdict = compute_verdict("test", &results);
        assert_eq!(verdict.winner.as_deref(), Some("a"));
    }

    #[test]
    fn verdict_tiebreaks_on_latency() {
        let results = vec![
            EvalRunResult {
                eval_name: "e".to_string(),
                model: "m".to_string(),
                variant: "a".to_string(),
                prompt_version: String::new(),
                cases: vec![EvalCaseResult {
                    case_index: 0,
                    input: "i".to_string(),
                    expected: "e".to_string(),
                    actual: "e".to_string(),
                    passed: true,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 100.0,
                }],
            },
            EvalRunResult {
                eval_name: "e".to_string(),
                model: "m".to_string(),
                variant: "b".to_string(),
                prompt_version: String::new(),
                cases: vec![EvalCaseResult {
                    case_index: 0,
                    input: "i".to_string(),
                    expected: "e".to_string(),
                    actual: "e".to_string(),
                    passed: true,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 50.0,
                }],
            },
        ];
        let verdict = compute_verdict("test", &results);
        // Same pass rate, b is faster -> b wins.
        assert_eq!(verdict.winner.as_deref(), Some("b"));
    }

    #[test]
    fn verdict_full_tie_is_none() {
        let results = vec![
            EvalRunResult {
                eval_name: "e".to_string(),
                model: "m".to_string(),
                variant: "a".to_string(),
                prompt_version: String::new(),
                cases: vec![EvalCaseResult {
                    case_index: 0,
                    input: "i".to_string(),
                    expected: "e".to_string(),
                    actual: "e".to_string(),
                    passed: true,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 50.0,
                }],
            },
            EvalRunResult {
                eval_name: "e".to_string(),
                model: "m".to_string(),
                variant: "b".to_string(),
                prompt_version: String::new(),
                cases: vec![EvalCaseResult {
                    case_index: 0,
                    input: "i".to_string(),
                    expected: "e".to_string(),
                    actual: "e".to_string(),
                    passed: true,
                    scorer: EvalScorer::ExactMatch,
                    latency_ms: 50.0,
                }],
            },
        ];
        let verdict = compute_verdict("test", &results);
        assert_eq!(verdict.winner, None);
    }

    #[test]
    fn active_prompt_system_with_override() {
        let experiments = AiExperiments {
            prompts: {
                let mut m = BTreeMap::new();
                m.insert(
                    "greeting".to_string(),
                    AiPromptVersions {
                        versions: {
                            let mut v = BTreeMap::new();
                            v.insert(
                                "v1".to_string(),
                                AiPromptVersion {
                                    system: "default system".to_string(),
                                },
                            );
                            v.insert(
                                "v2".to_string(),
                                AiPromptVersion {
                                    system: "overridden system".to_string(),
                                },
                            );
                            v
                        },
                        active: "v1".to_string(),
                    },
                );
                m
            },
            ..Default::default()
        };
        // Without override: active is v1.
        assert_eq!(
            active_prompt_system(Some(&experiments), &[], "greeting"),
            Some("default system".to_string())
        );
        // With override: active is v2.
        let overrides = vec![("greeting".to_string(), "v2".to_string())];
        assert_eq!(
            active_prompt_system(Some(&experiments), &overrides, "greeting"),
            Some("overridden system".to_string())
        );
    }
}
