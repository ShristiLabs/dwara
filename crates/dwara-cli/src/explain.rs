//! `dwara explain` CLI logic (USA-09, #231): a human-readable decision
//! trace for a mock request against a config.
//!
//! Given a config file and a mock request (method, path, optional
//! headers and consumer identity), `dwara explain` compiles the config
//! into a snapshot, runs the pure [`decide`] function, and prints a
//! structured explanation of what the gateway WOULD do:
//!
//! - Which route matches (and why)
//! - Whether the request passes authorization
//! - Whether the request would be rate-limited
//! - Which transforms would apply
//! - Which upstream/endpoint would be selected
//! - Whether response caching is active for the route
//!
//! This is the offline, no-side-effects companion to `dwara replay`:
//! replay diffs two configs for recorded traffic; explain traces a
//! single request for an operator who wants to understand the
//! decision path.

use dwara_core::config::parse_gateway;
use dwara_core::dataplane::replay::{decide, ReplayRequest, SimulatedCounter};
use dwara_core::snapshot::{compile, Snapshot};

/// The mock request shape for `dwara explain`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ExplainRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub auth_identity: Option<String>,
    #[serde(default)]
    pub timestamp_ms: Option<i64>,
}

impl ExplainRequest {
    /// Build a `GET /` request with no headers (the simplest explain).
    pub fn get(path: &str) -> Self {
        ExplainRequest {
            method: "GET".to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            auth_identity: None,
            timestamp_ms: None,
        }
    }
}

/// The outcome of an explain run: the full decision trace rendered as
/// human-readable text.
#[derive(Debug, Clone)]
pub struct ExplainReport {
    pub text: String,
}

/// Run `dwara explain`: compile the config, run `decide`, and render
/// the decision trace.
pub fn run_explain(config_text: &str, request: &ExplainRequest) -> Result<ExplainReport, String> {
    let gateway = parse_gateway(config_text).map_err(|e| format!("parse failed: {e}"))?;
    let compiled = compile(&gateway).map_err(|e| format!("{e}"))?;
    let snapshot = Snapshot::from_compiled(compiled);

    let replay_req = ReplayRequest {
        method: request.method.clone(),
        path: request.path.clone(),
        headers: request.headers.clone(),
        auth_identity: request.auth_identity.clone(),
        timestamp_ms: request.timestamp_ms.unwrap_or(0),
    };

    let mut counter = SimulatedCounter::new();
    let decision = decide(&snapshot, &replay_req, &mut counter);

    let text = render_explanation(request, &decision, &snapshot);
    Ok(ExplainReport { text })
}

/// Render the decision trace as a human-readable explanation.
fn render_explanation(
    request: &ExplainRequest,
    decision: &dwara_core::dataplane::replay::ReplayDecision,
    snapshot: &Snapshot,
) -> String {
    let mut out = String::new();

    out.push_str("=== dwara explain ===\n\n");
    out.push_str(&format!("Request: {} {}\n", request.method, request.path));
    if !request.headers.is_empty() {
        out.push_str("Headers:\n");
        for (k, v) in &request.headers {
            out.push_str(&format!("  {k}: {v}\n"));
        }
    }
    if let Some(ref consumer) = request.auth_identity {
        out.push_str(&format!("Consumer: {consumer}\n"));
    }
    out.push('\n');

    // 1. Route matching
    out.push_str("--- Route Matching ---\n");
    match &decision.matched_route {
        Some(route_name) => {
            out.push_str(&format!("Matched route: {route_name}\n"));
            // Find the route in the gateway to show details.
            let gateway = snapshot.gateway();
            if let Some(route) = gateway.routes.iter().find(|r| &r.name == route_name) {
                out.push_str(&format!("  Service: {}\n", route.service));
                if let Some(ref host) = route.r#match.host {
                    out.push_str(&format!("  Host match: {host}\n"));
                }
                if !route.r#match.methods.is_empty() {
                    out.push_str(&format!(
                        "  Methods: {}\n",
                        route.r#match.methods.join(", ")
                    ));
                }
                // Show the action type.
                match &route.action {
                    dwara_core::config::RouteAction::Proxy { .. } => {
                        out.push_str("  Action: proxy\n");
                    }
                    dwara_core::config::RouteAction::Mock { .. } => {
                        out.push_str("  Action: mock\n");
                    }
                    dwara_core::config::RouteAction::Redirect { .. } => {
                        out.push_str("  Action: redirect\n");
                    }
                    dwara_core::config::RouteAction::Respond { .. } => {
                        out.push_str("  Action: respond\n");
                    }
                    _ => {
                        out.push_str("  Action: other\n");
                    }
                }
            }
        }
        None => {
            out.push_str("No route matched (the gateway would return 404)\n");
            out.push_str("\nNo further decisions are made without a matched route.\n");
            return out;
        }
    }
    out.push('\n');

    // 2. Authorization
    out.push_str("--- Authorization ---\n");
    match &decision.authz_result {
        Some(dwara_core::security::authz::Decision::Allow) => {
            out.push_str("Result: ALLOW\n");
            if request.auth_identity.is_none() {
                out.push_str("  (no auth identity provided — anonymous access allowed)\n");
            }
        }
        Some(dwara_core::security::authz::Decision::Deny { reason, .. }) => {
            out.push_str("Result: DENY\n");
            out.push_str(&format!("  Reason: {reason}\n"));
            if request.auth_identity.is_none() {
                out.push_str("  (no auth identity provided — anonymous access denied)\n");
            }
        }
        None => {
            out.push_str("Not evaluated (no route matched)\n");
        }
    }
    out.push('\n');

    // 3. Rate limiting
    out.push_str("--- Rate Limiting ---\n");
    match decision.rate_limit_result {
        Some(true) => out.push_str("Result: ALLOWED (within budget)\n"),
        Some(false) => out.push_str("Result: DENIED (over budget — 429)\n"),
        None => out.push_str("No rate-limit rules apply to this route\n"),
    }
    out.push('\n');

    // 4. Transforms
    out.push_str("--- Request/Response Transforms ---\n");
    match &decision.transform_result {
        Some(transforms) => {
            out.push_str(&format!(
                "  Request header ops: {}\n",
                transforms.request_header_ops
            ));
            out.push_str(&format!(
                "  Request query ops: {}\n",
                transforms.request_query_ops
            ));
            out.push_str(&format!(
                "  Request body transform: {}\n",
                if transforms.request_body_transform {
                    "yes"
                } else {
                    "no"
                }
            ));
            out.push_str(&format!(
                "  Response header ops: {}\n",
                transforms.response_header_ops
            ));
            out.push_str(&format!(
                "  Response body transform: {}\n",
                if transforms.response_body_transform {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        None => out.push_str("No transforms configured for this route\n"),
    }
    out.push('\n');

    // 5. Upstream selection
    out.push_str("--- Upstream Selection ---\n");
    match &decision.upstream_pick {
        Some(pick) => {
            out.push_str(&format!("  Upstream: {}\n", pick.upstream));
            out.push_str(&format!("  Endpoint: {}", pick.endpoint));
            out.push_str(&format!("  Load balancer: {}\n", pick.load_balancer));
            out.push_str(&format!("  Path rewrite: {}\n", pick.path_rewrite));
        }
        None => {
            out.push_str("No upstream selected (route may not be a proxy action)\n");
        }
    }
    out.push('\n');

    // 6. Caching (check if the route has a cache policy)
    out.push_str("--- Response Caching ---\n");
    if let Some(ref route_name) = decision.matched_route {
        let gateway = snapshot.gateway();
        if let Some(route) = gateway.routes.iter().find(|r| &r.name == route_name) {
            if route.cache.is_some() {
                out.push_str("  Caching: enabled\n");
                if let Some(ref cache) = route.cache {
                    out.push_str(&format!("  TTL: {}s\n", cache.ttl_secs));
                    if !cache.vary.is_empty() {
                        out.push_str(&format!("  Vary by: {}\n", cache.vary.join(", ")));
                    }
                }
            } else {
                out.push_str("  Caching: not configured for this route\n");
            }
        } else {
            out.push_str("  Caching: route not found\n");
        }
    } else {
        out.push_str("  Caching: no route matched\n");
    }

    out
}
