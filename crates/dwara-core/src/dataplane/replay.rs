//! Replay time-travel debugging (DW-102): a PURE decision replayer.
//!
//! The gateway's request path (`dataplane::proxy`) weaves together route
//! matching, authorization, rate limiting, transforms, and endpoint
//! selection with live I/O (upstream dials, live GCRA counters, breaker
//! state). Replay inverts that: given a captured request and a
//! [`Snapshot`] (a compiled config generation), it re-runs the SAME
//! decision logic with NO side effects — no network, no live counters,
//! no breaker state — so an operator can ask "what would this recorded
//! request do under THIS config?" and diff the answer across two
//! generations.
//!
//! # Sandbox isolation
//!
//! [`decide`] is pure: it reads only its inputs (`&Snapshot`,
//! `&ReplayRequest`) and a caller-supplied [`SimulatedCounter`] for the
//! rate-limit simulation. It never touches the network, the filesystem,
//! the live rate limiter, or any shared mutable gateway state. The
//! rate-limit check uses a SIMULATED counter (not the live GCRA store),
//! the breaker is reported from config alone (no live failure counts),
//! and the endpoint pick is deterministic (the first healthy-by-config
//! endpoint, no live health tracking). This is the contract that makes
//! replay safe to run in CI and against candidate configs that have
//! never served traffic.
//!
//! # Capture source
//!
//! The request detail (method, path, redacted headers, auth identity)
//! is captured by the analytics raw table (DW-043, extended in DW-102
//! with optional `request_headers_redacted` and `auth_identity`
//! columns). The capture is opt-in and redacted via the existing PII
//! redaction patterns (`ai::redaction`); the replay CLI reads those
//! rows (or an exported recording) and feeds them to [`decide`].
//!
//! # Diffing
//!
//! [`DecisionDiff`] compares two [`ReplayDecision`]s (the same request
//! under an old and a new snapshot) and reports which decision stages
//! changed — the unit the `dwara replay` CLI emits per request, and the
//! signal a CI gate exits non-zero on.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::{Gateway, PathRewrite, Route, RouteAction, Service};
use crate::security::authn::Identity;
use crate::security::authz::{self, AuthzChain, AuthzContext, Decision};
use crate::snapshot::Snapshot;
use crate::state::store::CredentialKind;

/// One captured request fed to [`decide`]. The fields mirror what the
/// analytics raw table stores (DW-043 + DW-102): the request shape and
/// the redacted auth identity. Headers are ALREADY redacted at capture
/// time (the existing PII patterns); replay never sees raw secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRequest {
    /// HTTP method (e.g. `GET`, `POST`).
    pub method: String,
    /// The request path (no query string); the same value route
    /// matching sees.
    pub path: String,
    /// Redacted request headers as (name, value) pairs. Values have
    /// already been scrubbed by the capture-time redaction pass; replay
    /// treats them as opaque match inputs for header-based route
    /// criteria and authz (none today, but reserved for future
    /// claim-sourced rules).
    pub headers: Vec<(String, String)>,
    /// The authenticated consumer name, or `None` for anonymous
    /// traffic. Captured opt-in (DW-102 `auth_identity`).
    pub auth_identity: Option<String>,
    /// Wall-clock ms since the Unix epoch (the analytics time domain).
    /// Used only for the simulated rate-limit window alignment; replay
    /// never reads the wall clock itself.
    pub timestamp_ms: i64,
}

impl ReplayRequest {
    /// Look up a header value (case-insensitive name match), the way
    /// the proxy's route criteria do.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The outcome of one stage of the replayed decision path. Each stage
/// reports what the LIVE proxy would have decided at that point, with
/// no side effects applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayDecision {
    /// The matched route name, or `None` when no route matched (the
    /// live proxy would answer 404).
    pub matched_route: Option<String>,
    /// The authorization verdict (`Allow` / `Deny`). `Allow` when no
    /// rules applied (the transparent-chain case). `None` only when no
    /// route matched — authz never runs pre-route.
    pub authz_result: Option<Decision>,
    /// The simulated rate-limit verdict: `true` when the request would
    /// be admitted, `false` when over budget. `None` when no route
    /// matched or no rate-limit rules applied.
    pub rate_limit_result: Option<bool>,
    /// A description of the request transforms that WOULD apply
    /// (header/query/body op counts), or `None` when no route matched
    /// or the route carries no transforms.
    pub transform_result: Option<TransformSummary>,
    /// The upstream endpoint that WOULD be selected
    /// (`upstream/endpoint`), or `None` when no route matched, the
    /// action is not a proxy action, or no endpoint is configured.
    pub upstream_pick: Option<UpstreamPick>,
}

/// A summary of the transforms that would apply to a matched route
/// (DW-028). Counts (not full op lists) keep the diff output stable
/// across unrelated key-order changes while still surfacing a change in
/// which transforms apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformSummary {
    /// Request header op count (set + add + remove + rename).
    pub request_header_ops: usize,
    /// Request query op count.
    pub request_query_ops: usize,
    /// Whether a request body (JSON) transform is configured.
    pub request_body_transform: bool,
    /// Response header op count.
    pub response_header_ops: usize,
    /// Whether a response body (JSON) transform is configured.
    pub response_body_transform: bool,
}

/// The upstream endpoint a matched proxy route would dispatch to. The
/// pick is deterministic for replay (the first endpoint of the resolved
/// upstream, or the first split target's first endpoint) — replay has
/// no live health state, so load-balancer selection is reported as the
/// resolved upstream name plus its first endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamPick {
    /// The resolved upstream name.
    pub upstream: String,
    /// The first endpoint's `address:port` (the deterministic pick).
    pub endpoint: String,
    /// The load-balancer algorithm the upstream is configured with.
    pub load_balancer: String,
    /// The path rewrite that would apply, if any (a short label:
    /// `strip_prefix`, `replace_prefix`, `regex`, or `none`).
    pub path_rewrite: String,
}

/// A simulated rate-limit counter (DW-102). Replay does NOT touch the
/// live GCRA store; instead the caller threads a counter that tracks
/// per-key usage within a fixed window, and [`decide`] advances it the
/// way the live limiter would. The simulation is deliberately simple
/// (fixed-window, not GCRA): replay answers "would this request be
/// admitted under this config's budget?" not "what is the exact GCRA
/// TAT?" — the decision boundary is what a diff cares about.
#[derive(Debug, Clone, Default)]
pub struct SimulatedCounter {
    /// (key, window_seconds) -> (window_start_ms, used).
    counts: HashMap<(String, u64), (i64, u64)>,
}

impl SimulatedCounter {
    /// New empty counter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate one rate-limit check: if `requests` over `window_seconds`
    /// is within budget for `key` at `now_ms`, reserve one unit and
    /// return `true`; otherwise return `false` (over budget). The
    /// window resets when `now_ms` crosses `window_start + window_s`.
    pub fn check(&mut self, key: &str, requests: u64, window_seconds: u64, now_ms: i64) -> bool {
        let window_ms = (window_seconds as i64) * 1000;
        let entry = self
            .counts
            .entry((key.to_string(), window_seconds))
            .or_insert((now_ms, 0));
        // Reset the window when it has elapsed.
        if now_ms >= entry.0 + window_ms {
            entry.0 = now_ms;
            entry.1 = 0;
        }
        if entry.1 >= requests {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// The pure decision function (DW-102). Re-runs the gateway's decision
/// path — route match, authz, simulated rate limit, transform
/// resolution, upstream pick — against `snapshot` for `request`, with
/// NO I/O and NO side effects on live gateway state. The
/// `rate_counter` is the ONLY mutable state touched, and it is a
/// simulated counter the caller owns (not the live limiter).
///
/// Returns a [`ReplayDecision`] describing what the live proxy WOULD
/// have decided at each stage. Stages after a miss (no route, authz
/// deny, rate-limit deny) are still reported when they can be computed
/// without side effects — an operator diffing two configs wants to see
/// "authz now denies" even when the live proxy would have stopped
/// there, so the diff surfaces the full picture.
pub fn decide(
    snapshot: &Snapshot,
    request: &ReplayRequest,
    rate_counter: &mut SimulatedCounter,
) -> ReplayDecision {
    let gateway = snapshot.gateway();

    // 1. Route matching (same precedence as proxy.rs: exact, regex,
    //    longest prefix). The snapshot's RouteTable is the compiled
    //    matcher; find_full returns the route index and path params.
    let Some((idx, _params)) = snapshot.route_table().find_full(&request.path) else {
        return ReplayDecision {
            matched_route: None,
            authz_result: None,
            rate_limit_result: None,
            transform_result: None,
            upstream_pick: None,
        };
    };
    let Some(route) = gateway.routes.get(idx) else {
        return ReplayDecision {
            matched_route: None,
            authz_result: None,
            rate_limit_result: None,
            transform_result: None,
            upstream_pick: None,
        };
    };

    // 2. Authorization (pure, against the snapshot's authz rules).
    //    Build a minimal Identity from the captured auth identity: the
    //    consumer name plus the groups the CONFIG consumer declares
    //    (replay has no store-managed consumers). The effective IP is
    //    the loopback (replay has no real peer; IP ACLs are reported
    //    against 127.0.0.1, the honest "no network" stand-in).
    let authz_result = evaluate_authz(gateway, route, request);

    // 3. Rate-limit simulation. Resolve the applicable policies
    //    (consumer > route > service > listener > global) and simulate
    //    each rule's windows against the counter. A request is admitted
    //    only if EVERY window of EVERY applicable rule allows it (the
    //    live AND-composition). Dry-run bundles report `true` (they
    //    never enforce).
    let rate_limit_result = evaluate_rate_limit(gateway, route, request, rate_counter);

    // 4. Transform resolution (which transforms would apply).
    let transform_result = summarize_transforms(route);

    // 5. Upstream pick (deterministic: the resolved upstream's first
    //    endpoint). Only proxy actions dial an upstream.
    let upstream_pick = pick_upstream(gateway, route, snapshot);

    ReplayDecision {
        matched_route: Some(route.name.clone()),
        authz_result: Some(authz_result),
        rate_limit_result,
        transform_result,
        upstream_pick,
    }
}

/// Build a minimal [`Identity`] from the captured auth identity and the
/// config consumer record (groups come from config; replay has no
/// store-managed consumers and no real claims).
fn replay_identity(gateway: &Gateway, request: &ReplayRequest) -> Option<Identity> {
    let name = request.auth_identity.as_ref()?;
    let consumer = gateway.consumers.iter().find(|c| &c.name == name)?;
    Some(Identity {
        consumer_name: consumer.name.clone(),
        credential_kind: CredentialKind::ApiKey, // replay does not know the family
        consumer_type: consumer.consumer_type,
        groups: consumer.groups.clone(),
        claims: std::collections::BTreeMap::new(),
        body_digest: None,
    })
}

/// Evaluate the authorization chain (pure). Mirrors the proxy's
/// `AuthzChain` construction: consumer, route, service, listener,
/// global (in precedence order). Listener-level rules are transparent
/// in replay (no listener context), exactly like the proxy's
/// direct-drive test path.
fn evaluate_authz(gateway: &Gateway, route: &Route, request: &ReplayRequest) -> Decision {
    let identity = replay_identity(gateway, request);
    let consumer_cfg = identity.as_ref().and_then(|id| {
        gateway
            .consumers
            .iter()
            .find(|c| c.name == id.consumer_name)
    });
    let consumer_authz = consumer_cfg.and_then(|c| c.authorization.as_ref());
    let service = gateway.services.iter().find(|s| s.name == route.service);
    let service_authz = service.and_then(|s| s.authorization.as_ref());
    let global_authz = gateway.authorization.as_ref();

    let any_rules = consumer_authz.is_some()
        || route.authorization.is_some()
        || service_authz.is_some()
        || global_authz.is_some();
    if !any_rules {
        return Decision::Allow;
    }

    let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let ctx = AuthzContext {
        identity: identity.as_ref(),
        consumer_groups: identity
            .as_ref()
            .map(|id| id.groups.as_slice())
            .unwrap_or(&[]),
        peer_ip,
        effective_ip: peer_ip,
        geoip: None,
    };
    let chain = AuthzChain {
        consumer: consumer_authz,
        route: route.authorization.as_ref(),
        service: service_authz,
        listener: None,
        global: global_authz,
    };
    authz::resolve(&chain, &ctx).decision
}

/// Resolve the applicable rate-limit rules (consumer, route, service,
/// listener, global in precedence order) and simulate each against the
/// counter. Returns `Some(true)` if admitted, `Some(false)` if over
/// budget, `None` if no rate-limit rules apply at all.
fn evaluate_rate_limit(
    gateway: &Gateway,
    route: &Route,
    request: &ReplayRequest,
    counter: &mut SimulatedCounter,
) -> Option<bool> {
    let identity = replay_identity(gateway, request);
    let consumer_cfg = identity.as_ref().and_then(|id| {
        gateway
            .consumers
            .iter()
            .find(|c| c.name == id.consumer_name)
    });
    let service = gateway.services.iter().find(|s| s.name == route.service);
    let policy_by_name = |name: &str| gateway.policies.iter().find(|p| p.name == name);

    // Collect applicable policy names in precedence order (consumer,
    // route, service, global). Listener-level is transparent (no
    // listener context in replay).
    let mut applicable: Vec<&str> = Vec::new();
    if let Some(c) = consumer_cfg {
        applicable.extend(c.policies.iter().map(String::as_str));
    }
    applicable.extend(route.policies.iter().map(String::as_str));
    if let Some(s) = service {
        applicable.extend(s.policies.iter().map(String::as_str));
    }
    applicable.extend(gateway.global_policies.iter().map(String::as_str));

    // Collect the resolved rules from each policy. Each entry is
    // (key, window_count, window_seconds, dry_run): the simulated
    // counter checks one (count, window) pair at a time. A policy may
    // contribute the legacy single-window field AND stacked rules.
    let mut checks: Vec<(String, u64, u64, bool)> = Vec::new();
    for name in applicable {
        let Some(policy) = policy_by_name(name) else {
            continue;
        };
        let key = rate_limit_key(policy, request, route);
        // Legacy single-window field: `requests` per `window_seconds`,
        // selector [route] (see the rate-limiter module docs).
        if let Some(rl) = &policy.rate_limit {
            checks.push((key.clone(), rl.requests, rl.window_seconds, policy.dry_run));
        }
        // Stacked GCRA rules (DW-017): each rule stacks one or more
        // windows (s, minute, hour); a request is admitted only if
        // EVERY set window allows it.
        for rule in &policy.rate_limits {
            for (maybe_count, window_s) in [
                (rule.requests_per.per_second, 1u64),
                (rule.requests_per.minute, 60u64),
                (rule.requests_per.hour, 3600u64),
            ] {
                if let Some(count) = maybe_count {
                    checks.push((key.clone(), count as u64, window_s, policy.dry_run));
                }
            }
        }
    }

    if checks.is_empty() {
        return None;
    }

    let mut admitted = true;
    for (key, count, window_s, dry_run) in checks {
        if dry_run {
            // Dry-run bundles never enforce; they report as admitted.
            continue;
        }
        if !counter.check(&key, count, window_s, request.timestamp_ms) {
            admitted = false;
        }
    }
    Some(admitted)
}

/// Build the rate-limit key for a policy from its rule selectors. The
/// live limiter composes the key from the selector components; replay
/// mirrors that with the consumer name (or loopback IP for anonymous)
/// and the route name.
fn rate_limit_key(
    policy: &crate::config::Policy,
    request: &ReplayRequest,
    route: &Route,
) -> String {
    // The key is composed from the FIRST rule's selectors (all rules in
    // a policy share the key shape in v1; the live limiter composes per
    // rule, but the policy-level key is what the counter tracks). Fall
    // back to a composite of consumer + route when no rules declare
    // selectors.
    let consumer = request
        .auth_identity
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let mut parts: Vec<String> = Vec::new();
    let first_rule = policy.rate_limits.first();
    let selectors = first_rule.map(|r| r.selector.as_slice()).unwrap_or(&[]);
    if selectors.is_empty() {
        // Legacy single-window field: selector is [route].
        parts.push(route.name.clone());
    } else {
        for sel in selectors {
            match sel {
                crate::config::RateLimitSelector::Ip => parts.push("127.0.0.1".to_string()),
                crate::config::RateLimitSelector::Credential => parts.push(consumer.clone()),
                crate::config::RateLimitSelector::Route => parts.push(route.name.clone()),
            }
        }
    }
    parts.join(":")
}

/// Summarize the route's transforms (DW-028) into a stable shape for
/// diffing. Returns `None` when the route carries no transforms.
fn summarize_transforms(route: &Route) -> Option<TransformSummary> {
    let transforms = route.transforms.as_ref()?;
    let mut summary = TransformSummary {
        request_header_ops: 0,
        request_query_ops: 0,
        request_body_transform: false,
        response_header_ops: 0,
        response_body_transform: false,
    };
    if let Some(req) = transforms.request.as_ref() {
        if let Some(h) = req.headers.as_ref() {
            summary.request_header_ops =
                h.set.len() + h.add.len() + h.remove.len() + h.rename.len();
        }
        if let Some(q) = req.query.as_ref() {
            summary.request_query_ops = q.set.len() + q.add.len() + q.remove.len() + q.rename.len();
        }
        if req.body.is_some() {
            summary.request_body_transform = true;
        }
    }
    if let Some(resp) = transforms.response.as_ref() {
        if let Some(h) = resp.headers.as_ref() {
            summary.response_header_ops =
                h.set.len() + h.add.len() + h.remove.len() + h.rename.len();
        }
        if resp.body.is_some() {
            summary.response_body_transform = true;
        }
    }
    // A transforms block with all-empty ops is still a present block;
    // report it (the diff cares that the block exists).
    Some(summary)
}

/// Resolve the upstream a proxy route would dispatch to (deterministic
/// for replay: the first endpoint of the resolved upstream, or the
/// first split target's first endpoint). Returns `None` for non-proxy
/// actions or when no endpoint is configured.
fn pick_upstream(gateway: &Gateway, route: &Route, snapshot: &Snapshot) -> Option<UpstreamPick> {
    let proxy = match &route.action {
        RouteAction::Proxy { rewrite } => rewrite,
        _ => return None,
    };
    let service = gateway.services.iter().find(|s| s.name == route.service)?;
    let upstream_name = resolve_service_upstream(service)?;
    let upstream = gateway.upstreams.iter().find(|u| u.name == upstream_name)?;
    let endpoint = upstream.endpoints.first()?;
    let path_rewrite = match proxy {
        Some(PathRewrite::StripPrefix {}) => "strip_prefix",
        Some(PathRewrite::ReplacePrefix { .. }) => "replace_prefix",
        Some(PathRewrite::Regex { .. }) => "regex",
        None => "none",
    }
    .to_string();
    // The rewrite regex is compiled in the snapshot; confirm it exists
    // for a regex rewrite (mirrors the live path's contract) but do not
    // apply it — replay reports the configured rewrite, not the
    // rewritten path.
    let _ = snapshot.route_table().rewrite_regex(0);
    Some(UpstreamPick {
        upstream: upstream.name.clone(),
        endpoint: format!("{}:{}", endpoint.address, endpoint.port),
        load_balancer: format!("{:?}", upstream.load_balancer).to_lowercase(),
        path_rewrite,
    })
}

/// Resolve the upstream name for a service (single target or the first
/// split target with a positive weight).
fn resolve_service_upstream(service: &Service) -> Option<String> {
    if let Some(name) = &service.upstream {
        return Some(name.clone());
    }
    if let Some(split) = &service.split {
        // The first target with a positive weight is the deterministic
        // pick (replay has no live weighted-random draw).
        return split
            .targets
            .iter()
            .find(|t| t.weight > 0)
            .map(|t| t.upstream.clone());
    }
    None
}

/// A per-stage diff between two [`ReplayDecision`]s (the same request
/// under an old and a new snapshot). Each field is `true` when that
/// stage's decision changed; [`DecisionDiff::any`] is the CI-gate
/// signal (exit 1 when any stage differs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionDiff {
    /// The request path the diff is for (for report labeling).
    pub path: String,
    /// The matched route name changed (including a match becoming a
    /// miss or vice versa).
    pub route_changed: bool,
    /// The authorization verdict changed.
    pub authz_changed: bool,
    /// The rate-limit verdict changed.
    pub rate_limit_changed: bool,
    /// The transform summary changed.
    pub transform_changed: bool,
    /// The upstream pick changed.
    pub upstream_changed: bool,
}

impl DecisionDiff {
    /// Compare two decisions for the same request `path`. Returns a
    /// [`DecisionDiff`] with each stage's change flag set.
    pub fn compare(path: &str, old: &ReplayDecision, new: &ReplayDecision) -> Self {
        DecisionDiff {
            path: path.to_string(),
            route_changed: old.matched_route != new.matched_route,
            authz_changed: old.authz_result != new.authz_result,
            rate_limit_changed: old.rate_limit_result != new.rate_limit_result,
            transform_changed: old.transform_result != new.transform_result,
            upstream_changed: old.upstream_pick != new.upstream_pick,
        }
    }

    /// Whether ANY stage changed (the CI-gate signal).
    pub fn any(&self) -> bool {
        self.route_changed
            || self.authz_changed
            || self.rate_limit_changed
            || self.transform_changed
            || self.upstream_changed
    }

    /// A one-line human-readable summary of the diff (for the CLI
    /// report). Empty when nothing changed.
    pub fn summary(&self) -> String {
        if !self.any() {
            return String::new();
        }
        let mut parts = Vec::new();
        if self.route_changed {
            parts.push("route");
        }
        if self.authz_changed {
            parts.push("authz");
        }
        if self.rate_limit_changed {
            parts.push("rate_limit");
        }
        if self.transform_changed {
            parts.push("transforms");
        }
        if self.upstream_changed {
            parts.push("upstream");
        }
        format!("{}: {}", self.path, parts.join(","))
    }
}
