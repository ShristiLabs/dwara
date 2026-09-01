//! AI routing policies (DW-085): within-request escalation and
//! latency-vs-cost selection. Composed over DW-076 routing.
//!
//! Two policy kinds:
//! - **FallbackChain**: calls an external classifier service to
//!   estimate prompt complexity. Simple prompts (score < threshold)
//!   route to the cheap model; complex prompts (score >= threshold)
//!   escalate to the costlier model. On classifier error, fails open
//!   to the cheap model (the safe default).
//! - **LatencyCost**: static config-based selection. Candidates are
//!   sorted at compile time by the configured preference (cost,
//!   latency, or balanced); the policy returns the best candidate
//!   deterministically (no runtime metrics needed).
//!
//! A policy composes over DW-076 routing: the candidate aliases it
//! names (`cheap`, `escalate_to`, or `candidates[].model`) are
//! themselves plain chain/canary aliases. The policy resolves each
//! alias to its PRIMARY [`RouteTarget`] at compile time (the first
//! chain entry or the first canary version), so the runtime
//! evaluation returns a flat candidate list the dataplane walks with
//! the same failover loop as a plain chain.
//!
//! # Dependency direction
//!
//! `ai` depends on `config` only. The classifier HTTP call reuses
//! the same `hyper_util` client pattern as the DW-083 semantic cache
//! (no new dependencies).

use crate::ai::{CompiledModel, RouteTarget};
use crate::config::ai::{AiLatencyCostCandidate, AiLatencyPreference, AiRoutingPolicy};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::BTreeMap;
use std::time::Duration;

/// A compiled routing policy (DW-085). Built at AiRuntime compile
/// time from the config block; immutable once built. The
/// [`evaluate`](Self::evaluate) method returns the candidate list to
/// walk (the same shape as [`AiRuntime::route`](crate::ai::AiRuntime::route))
/// plus a [`PolicyDecision`] the dataplane records as a metric.
#[derive(Debug, Clone)]
pub enum CompiledRoutingPolicy {
    /// Cheap-first with complexity-signal escalation. The
    /// `evaluate` call POSTs the prompt to the external classifier
    /// service and picks the cheap or escalate-to target by the
    /// returned score.
    FallbackChain {
        /// The routing-policy name (for metrics attribution).
        name: String,
        /// The primary target of the `cheap` alias.
        cheap: Box<RouteTarget>,
        /// The primary target of the `escalate_to` alias.
        escalate_to: Box<RouteTarget>,
        /// The classifier service URL.
        classifier_url: String,
        /// The model name passed to the classifier service.
        classifier_model: String,
        /// The complexity score threshold (>= escalates).
        threshold: f64,
        /// The classifier HTTP timeout in milliseconds.
        timeout_ms: u64,
        /// Optional resolved API key for the classifier service.
        api_key: Option<String>,
    },
    /// Latency-vs-cost static selection. Candidates are pre-sorted at
    /// compile time by the configured preference; `evaluate` returns
    /// the best one (no I/O).
    LatencyCost {
        /// The routing-policy name (for metrics attribution).
        name: String,
        /// Candidates sorted best-first by the preference (the first
        /// is the pick).
        candidates: Vec<RouteTarget>,
    },
}

/// The decision a routing policy made for one request (DW-085). The
/// dataplane records this as a metric (the `ai` domain cannot import
/// `observability` — the dependency direction forbids it — so the
/// decision travels back to the caller, which records it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// FallbackChain: the prompt was simple (score < threshold) and
    /// routed to the cheap model.
    Cheap,
    /// FallbackChain: the prompt was complex (score >= threshold)
    /// and escalated to the costlier model.
    Escalate,
    /// FallbackChain: the classifier call failed and the policy
    /// failed open to the cheap model.
    ClassifierError,
    /// LatencyCost: the pre-sorted best candidate was selected.
    LatencyCost,
}

impl CompiledRoutingPolicy {
    /// Compile from config. Resolves each named alias to its primary
    /// [`RouteTarget`] against the first-pass compiled model map
    /// (plain chain/canary aliases only — a policy alias cannot
    /// reference another policy alias, so nested policies are
    /// rejected by returning None). Returns None when a referenced
    /// alias is missing or is itself a policy alias (a
    /// validate-vs-build race or an authoring error validation
    /// missed).
    pub fn compile(
        name: &str,
        policy: &AiRoutingPolicy,
        models: &BTreeMap<String, CompiledModel>,
    ) -> Option<Self> {
        match policy {
            AiRoutingPolicy::FallbackChain(p) => {
                let cheap = primary_target_of(models, &p.cheap)?.clone();
                let escalate_to = primary_target_of(models, &p.escalate_to)?.clone();
                Some(Self::FallbackChain {
                    name: name.to_string(),
                    cheap: Box::new(cheap),
                    escalate_to: Box::new(escalate_to),
                    classifier_url: p.classifier_url.clone(),
                    classifier_model: p.classifier_model.clone(),
                    threshold: p.threshold,
                    timeout_ms: p.timeout_ms,
                    api_key: p.api_key.clone(),
                })
            }
            AiRoutingPolicy::LatencyCost(p) => {
                let mut scored: Vec<(&AiLatencyCostCandidate, RouteTarget)> = Vec::new();
                for c in &p.candidates {
                    let target = primary_target_of(models, &c.model)?.clone();
                    scored.push((c, target));
                }
                match p.preference {
                    AiLatencyPreference::Cost => scored.sort_by_key(|(c, _)| c.cost),
                    AiLatencyPreference::Latency => scored.sort_by_key(|(c, _)| c.latency),
                    AiLatencyPreference::Balanced => {
                        scored.sort_by_key(|(c, _)| c.cost + c.latency)
                    }
                }
                Some(Self::LatencyCost {
                    name: name.to_string(),
                    candidates: scored.into_iter().map(|(_, t)| t).collect(),
                })
            }
        }
    }

    /// Evaluate the policy for one request. Returns the candidate
    /// list to walk (the same shape as
    /// [`AiRuntime::route`](crate::ai::AiRuntime::route)) plus a
    /// [`PolicyDecision`] the dataplane records as a metric. For
    /// FallbackChain, this calls the external classifier service
    /// (async). For LatencyCost, the candidates are pre-sorted at
    /// compile time, so this is effectively synchronous.
    pub async fn evaluate(&self, prompt_text: &str) -> (Vec<RouteTarget>, PolicyDecision) {
        match self {
            Self::FallbackChain {
                cheap,
                escalate_to,
                classifier_url,
                classifier_model,
                threshold,
                timeout_ms,
                api_key,
                ..
            } => {
                match call_classifier(
                    classifier_url,
                    classifier_model,
                    prompt_text,
                    *timeout_ms,
                    api_key.as_deref(),
                )
                .await
                {
                    Ok(score) => {
                        if score >= *threshold {
                            tracing::info!(
                                code = "ai_routing_policy_escalate",
                                score = score,
                                threshold = threshold,
                                "complexity signal triggered escalation to the costlier model"
                            );
                            (vec![(**escalate_to).clone()], PolicyDecision::Escalate)
                        } else {
                            tracing::info!(
                                code = "ai_routing_policy_cheap",
                                score = score,
                                threshold = threshold,
                                "complexity signal below threshold; using the cheap model"
                            );
                            (vec![(**cheap).clone()], PolicyDecision::Cheap)
                        }
                    }
                    Err(e) => {
                        // Fail open: on classifier error, use the
                        // cheap model (the safe default).
                        tracing::warn!(
                            code = "ai_routing_policy_classifier_error",
                            error = %e,
                            "classifier service call failed; defaulting to the cheap model"
                        );
                        (vec![(**cheap).clone()], PolicyDecision::ClassifierError)
                    }
                }
            }
            Self::LatencyCost { candidates, .. } => {
                // Pre-sorted at compile time; return the best
                // candidate. The list is non-empty (validation
                // rejects an empty candidates list).
                (vec![candidates[0].clone()], PolicyDecision::LatencyCost)
            }
        }
    }

    /// The routing-policy name (for metrics attribution).
    pub fn name(&self) -> &str {
        match self {
            Self::FallbackChain { name, .. } | Self::LatencyCost { name, .. } => name,
        }
    }
}

/// Resolve the primary [`RouteTarget`] of a named alias from the
/// compiled model map. Returns None when the alias is missing or is
/// itself a policy alias (nested policies are not allowed — a policy
/// composes over plain chain/canary aliases only).
fn primary_target_of<'a>(
    models: &'a BTreeMap<String, CompiledModel>,
    alias: &str,
) -> Option<&'a RouteTarget> {
    match models.get(alias)? {
        CompiledModel::Chain(chain) => chain.first(),
        CompiledModel::Canary(versions) => versions.first().map(|(_, t)| t),
        CompiledModel::Policy(_) => None,
    }
}

/// Call the external classifier service: POST
/// `{"model": ..., "input": text}` to `url`, parse
/// `{"data": [{"score": 0.0-1.0}]}`. Returns the complexity score on
/// success. Reuses the same `hyper_util` client pattern as the
/// DW-083 semantic cache embedding call.
async fn call_classifier(
    url: &str,
    model: &str,
    input: &str,
    timeout_ms: u64,
    api_key: Option<&str>,
) -> Result<f64, String> {
    let body = serde_json::json!({
        "model": model,
        "input": input,
    });
    let body_bytes =
        serde_json::to_vec(&body).map_err(|e| format!("encode classifier request body: {e}"))?;
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    // Optional API key (resolved at compile time; the value lives
    // only on the wire).
    if let Some(key) = api_key {
        let resolved = crate::config::credentials::resolve_configured_secret(key)
            .map_err(|e| format!("resolve classifier api key: {e}"))?;
        req = req.header("authorization", format!("Bearer {resolved}"));
    }
    let req = req
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| format!("build classifier request: {e}"))?;
    let client = Client::builder(TokioExecutor::new()).build_http();
    let timeout = Duration::from_millis(timeout_ms);
    let resp = tokio::time::timeout(timeout, client.request(req))
        .await
        .map_err(|_| format!("classifier service timed out after {timeout_ms} ms"))?
        .map_err(|e| format!("classifier service request failed: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read classifier response body: {e}"))?
        .to_bytes();
    if !status.is_success() {
        return Err(format!(
            "classifier service returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse classifier response JSON: {e}"))?;
    let score = v
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|d| d.get("score"))
        .and_then(|s| s.as_f64())
        .ok_or_else(|| "classifier response missing data[0].score".to_string())?;
    Ok(score)
}
