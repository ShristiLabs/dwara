//! Request-path plugin dispatch (DW-157, epic #274).
//!
//! This module is the wiring between the config's `plugins`/route
//! `plugins` lists and the live request path. For every routed request
//! whose route references plugins, it:
//!
//! 1. builds the per-request [`RequestPlugins`] — a fail-closed health
//!    gate over the generation's [`PluginLifecycle`] state, one
//!    per-request WASM instantiation through the lifecycle's runner
//!    (`wasm::runner::PluginRunner`), and the unified [`PluginChain`]
//!    (native filters + WASM entries in config order, dispatched
//!    through one [`WasmChainAdapter`]);
//! 2. drives the chain at the four documented phase points
//!    (`request_headers` after route resolution before authn;
//!    `request_body` after authz/rate-limit before the action;
//!    `response_headers` after the response arrives before masking;
//!    `response_body` after masking before the operator transforms and
//!    compression);
//! 3. runs `on_done` cleanup on EVERY exit path via `Drop`.
//!
//! ## Fast path discipline
//!
//! A route with an empty `plugins` list builds nothing:
//! [`RequestPlugins::build`] returns `Ok(None)` before any allocation,
//! and `handle_routed` skips every phase call — the no-plugin request
//! path is byte-identical to the pre-DW-157 path.
//!
//! ## Body policy
//!
//! Header phases always run. Body phases require a buffered body: a
//! route whose chain declares `request_body` (or `response_body`) has
//! that body buffered up to the route's body cap
//! ([`plugin_body_cap`] — `routes[].limits.max_body_bytes`, default
//! [`PLUGIN_BODY_CAP_DEFAULT`]); an over-cap body answers 500
//! `plugin_body_too_large` (fail-closed: a plugin that declared a body
//! phase must see the body or the request does not proceed). Bodies on
//! routes without body-phase plugins stay streamed — zero buffering,
//! zero cost. The response side rides the same buffering masking
//! already establishes when masking ran; otherwise it buffers the same
//! way. One documented exception: a STREAMING response body
//! (`text/event-stream`, or a body with no declared length — chunked
//! or open-ended) or a CONTENT-ENCODED response body skips the
//! `response_body` phase (logged once, `plugin_response_body_skipped`):
//! buffering an endless stream would stall the route, an encoded body
//! is opaque bytes to the plugin, and the gateway never decompresses on
//! this path (its own compression runs later, after the phase).
//!
//! ## Failure semantics
//!
//! Everything fails closed, on the AFFECTED route only:
//!
//! - a Crashed/Disabled/not-loaded plugin, a native name missing from
//!   the registry, a native factory that errors while the chain is
//!   built, or a failed per-request instantiation answers 500
//!   `plugin_unavailable`;
//! - a WASM trap (fuel/epoch/memory) or native filter error answers
//!   500 `plugin_failed`;
//! - an over-cap body answers 500 `plugin_body_too_large`;
//! - a plugin's `send_http_response` is honored verbatim (status,
//!   headers, body) and the upstream is never dialed.
//!
//! Every failure increments `dwara_plugin_failures_total{name,reason}`
//! and logs one server-side event naming the plugin; a plugin answering
//! the request (short-circuit OR failure) sets the access log's
//! `plugin_short_circuit` flag.
//!
//! ## Header conventions
//!
//! The proxy-wasm convention exposes HTTP framing as pseudo-headers.
//! Matching the host/runner tests (tests/wasm_host.rs), the request
//! header map carries `:method` and `:path` (path INCLUDING the query
//! string) ahead of the real headers (`host` included verbatim); the
//! response map carries `:status`. The write-back of ORDINARY headers
//! applies ONLY the names the chain changed (`apply_header_changes`):
//! headers no plugin touched keep their original bytes, non-UTF-8
//! (obs-text) values included. Pseudo-headers never enter the ordinary
//! map — the three target pseudo-headers a chain may rewrite are
//! captured separately ([`pseudo_header_rewrite`]) and applied when
//! the forwarded request is built:
//!
//! - `:path` — the FINAL upstream target, origin-form (`/...`),
//!   query string included (a written path without a query forwards
//!   without one). It composes with the route's own rewrite: the
//!   route rewrite applies first, the plugin's `:path` is the final
//!   say, and routes are never re-matched. Only the upstream sees the
//!   rewritten target — route matching, authn/authz, the cache key,
//!   anomaly scoring, and the access log all evaluated the ORIGINAL
//!   target and keep it.
//! - `:method` — a valid method token; replaces the forwarded method.
//! - `:authority` — overrides the forwarded `Host` header only (see
//!   [`PluginForwardHost`]); the dialed endpoint stays the balancer's
//!   pick.
//!
//! Only CHANGED values apply: writing back the value the map carried
//! has zero effect, and REMOVING a pseudo-header is ignored (the
//! request keeps its real method/path). An invalid changed value
//! (empty, non-`/`-prefixed, or unparseable `:path`; a non-token
//! `:method`; an unparseable `:authority`) fails closed: 500
//! `plugin_failed`, metric reason `invalid_rewrite`, upstream never
//! dialed.
//!
//! `:status` writes on the response map stay IGNORED (pipeline-owned)
//! — a deliberate asymmetry with the request side, documented on
//! [`RequestPlugins::response_headers_phase`].

use std::collections::HashMap;

use bytes::Bytes;
use http::uri::PathAndQuery;
use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};

use crate::config::{Gateway, PluginConfig, PluginPhase, Route};
use crate::dataplane::proxy::ProxyBody;
use crate::observability::Observability;
use crate::plugins::{ChainOutcome, LocalResponse, NativeRegistry, PluginChain};
use crate::wasm::adapter::WasmChainAdapter;
use crate::wasm::lifecycle::{PluginHealth, PluginLifecycle};

/// The default body cap for plugin body phases on routes without an
/// explicit `limits.max_body_bytes` (DW-157): 1 MiB, the same bound the
/// nano-service body cap uses. Buffering must be opt-in (the plugin
/// declaring the phase) and size-capped (always) — this is the cap when
/// the route configures none.
pub const PLUGIN_BODY_CAP_DEFAULT: u64 = 1024 * 1024;

/// The cap for plugin body phases (DW-157): the route's
/// `limits.max_body_bytes` when configured, else
/// [`PLUGIN_BODY_CAP_DEFAULT`]. The same bound governs the request and
/// response sides (it is the only per-route body cap in the config
/// surface). It applies even when the limits block is `dry_run` — it is
/// a buffering bound for the plugin phase, not the 413 policy.
pub fn plugin_body_cap(route: &Route) -> u64 {
    route
        .limits
        .as_ref()
        .and_then(|l| l.max_body_bytes)
        .unwrap_or(PLUGIN_BODY_CAP_DEFAULT)
}

/// The fail-closed exit a plugin phase hands its caller: the response
/// the proxy returns immediately (a plugin's local response or one of
/// the 500 envelopes). Boxed — `Response<ProxyBody>` is large and the
/// clippy `result_large_err` gate holds the hot-path `Result`s small.
pub type PluginExit = Box<Response<ProxyBody>>;

/// A chain's rewrite of the forwarded request target, captured at the
/// `request_headers` phase ([`pseudo_header_rewrite`]) and applied
/// when the upstream request is built: the phase runs early (before
/// authn) but the rewrite shapes the UPSTREAM request only, so it
/// rides the request extensions from the phase to the forward build
/// (`proxy::proxy_request` removes it there — after the route's own
/// rewrite and the query transforms, with no route re-match; see the
/// module's "Header conventions" section). `Default` is the no-rewrite
/// case (no pseudo-header changed); `is_noop` lets the caller skip
/// the extension entirely on that fast path.
#[derive(Clone, Debug, Default)]
pub struct PluginTargetRewrite {
    /// The validated `:path` write: origin-form, the WHOLE upstream
    /// target including any query string.
    pub path: Option<PathAndQuery>,
    /// The validated `:method` write (a method token).
    pub method: Option<hyper::Method>,
    /// The validated `:authority` write, as the `Host` header value
    /// the forwarded request will carry (see [`PluginForwardHost`]).
    pub authority: Option<HeaderValue>,
}

impl PluginTargetRewrite {
    /// Whether every field is unset — no pseudo-header was changed
    /// (the common case; the caller skips the extension ride).
    pub fn is_noop(&self) -> bool {
        self.path.is_none() && self.method.is_none() && self.authority.is_none()
    }
}

/// The `Host` override a plugin's `:authority` write produced. Rides
/// the request extensions from the forward build to the upstream
/// dispatch (`upstream::UpstreamHandle` owns the forwarded `Host`):
/// the header the plugin named replaces the picked endpoint's
/// authority there, and ONLY there — the dial target and the URI
/// authority stay the balancer's pick (a plugin shapes the `Host`
/// header, never which origin the gateway dials).
#[derive(Clone, Debug)]
pub struct PluginForwardHost(pub HeaderValue);

/// The per-request plugin execution state (DW-157): the unified chain
/// plus the fail-closed helpers that drive it. Constructed by
/// [`RequestPlugins::build`] only on routes that reference plugins;
/// `Drop` runs the `on_done` cleanup callback on every exit path
/// (early short-circuits, failures, and the natural tail alike).
pub struct RequestPlugins {
    chain: PluginChain<WasmChainAdapter>,
    /// The first plugin on the route declaring `request_headers` —
    /// the deterministic attribution for a fail-closed invalid target
    /// rewrite (the merged header map has no per-plugin author; the
    /// same first-declarer rule the body phases attribute by).
    request_headers_plugin: Option<String>,
    /// The first plugin on the route declaring `request_body` — the
    /// deterministic attribution for a request body the gateway could
    /// not buffer for the phase (over-cap).
    request_body_plugin: Option<String>,
    /// The first plugin on the route declaring `response_body` — the
    /// attribution for the response side of the same rule.
    response_body_plugin: Option<String>,
}

impl Drop for RequestPlugins {
    fn drop(&mut self) {
        self.chain.on_done();
    }
}

impl RequestPlugins {
    /// Build the per-request chain for `route`. `Ok(None)` — with zero
    /// allocations — when the route references no plugins (the fast
    /// path). `Err(response)` is the fail-closed 500 a caller returns
    /// immediately: a referenced plugin is Crashed/Disabled/not loaded,
    /// a native name is missing from the registry, a native factory
    /// errors while the chain is built, or per-request WASM
    /// instantiation failed or did not cover every WASM plugin.
    pub fn build(
        lifecycle: &PluginLifecycle,
        configs: &HashMap<String, PluginConfig>,
        registry: &NativeRegistry,
        route: &Route,
        obs: &Observability,
        rid: &str,
    ) -> Result<Option<Self>, PluginExit> {
        if route.plugins.is_empty() {
            return Ok(None);
        }
        let mut request_headers_plugin = None;
        let mut request_body_plugin = None;
        let mut response_body_plugin = None;
        // Health gate: every referenced plugin must be usable BEFORE the
        // request proceeds (fail-closed). Validation already rejected
        // names absent from the top-level list; a miss here is a
        // generation tear, and it still fails closed rather than
        // silently skipping the plugin.
        for name in &route.plugins {
            let Some(config) = configs.get(name) else {
                return Err(Box::new(unavailable(obs, name, "not_loaded", route, rid)));
            };
            if config.phases.contains(&PluginPhase::RequestHeaders)
                && request_headers_plugin.is_none()
            {
                request_headers_plugin = Some(name.clone());
            }
            if config.phases.contains(&PluginPhase::RequestBody) && request_body_plugin.is_none() {
                request_body_plugin = Some(name.clone());
            }
            if config.phases.contains(&PluginPhase::ResponseBody) && response_body_plugin.is_none()
            {
                response_body_plugin = Some(name.clone());
            }
            if let Some(native) = &config.native {
                if !registry.contains(native) {
                    return Err(Box::new(unavailable(
                        obs,
                        name,
                        "not_registered",
                        route,
                        rid,
                    )));
                }
                continue;
            }
            // A WASM plugin (`wasm:` or the registry `source:` variant,
            // resolved to a verified local artifact at publish — DW-165).
            // It must have entered the lifecycle this generation: a miss
            // is a generation tear and fails closed rather than skipping.
            let Some(loaded) = lifecycle.get_plugin(name) else {
                return Err(Box::new(unavailable(obs, name, "not_loaded", route, rid)));
            };
            match &loaded.health {
                PluginHealth::Healthy => {}
                PluginHealth::Crashed { error, .. } => {
                    tracing::warn!(
                        code = "plugin_unavailable",
                        request_id = %rid,
                        route = %route.name,
                        plugin = %name,
                        reason = %error,
                        "route references a crashed plugin; failing closed"
                    );
                    obs.record_plugin_failure(name, "crashed");
                    return Err(Box::new(unavailable_response(rid)));
                }
                PluginHealth::Disabled { reason } => {
                    tracing::warn!(
                        code = "plugin_unavailable",
                        request_id = %rid,
                        route = %route.name,
                        plugin = %name,
                        reason = %reason,
                        "route references a disabled plugin; failing closed"
                    );
                    obs.record_plugin_failure(name, "disabled");
                    return Err(Box::new(unavailable_response(rid)));
                }
            }
        }
        // Per-request instantiation through the compiled modules. All
        // WASM plugins on the route share ONE adapter (the chain
        // dispatches per name; see WasmChainAdapter). A native-only
        // chain gets the EMPTY instance set (every per-name dispatch
        // passes through — native filters dispatch through the chain's
        // own entries). The runner can be absent only before the first
        // successful load — every plugin then reads as not loaded
        // above; reaching here without one is a generation tear and
        // fails closed the same way.
        let has_wasm = route.plugins.iter().any(|n| {
            configs
                .get(n)
                .is_some_and(|c| c.wasm.is_some() || c.source.is_some())
        });
        let instances = if has_wasm {
            let Some(runner) = lifecycle.runner() else {
                return Err(Box::new(unavailable(
                    obs,
                    &route.plugins[0],
                    "not_loaded",
                    route,
                    rid,
                )));
            };
            match runner.instantiate(&route.plugins) {
                Some(instances) => instances,
                None => {
                    return Err(Box::new(unavailable(
                        obs,
                        &route.plugins[0],
                        "instantiate_failed",
                        route,
                        rid,
                    )));
                }
            }
        } else {
            crate::wasm::runner::PluginInstances::empty()
        };
        // Coverage: every WASM plugin on the route must hold a
        // per-request instance (a missing instance would silently skip
        // a configured plugin). Native-only names never enter the
        // runner and are exempt.
        for name in &route.plugins {
            let is_wasm = configs
                .get(name)
                .is_some_and(|c| (c.wasm.is_some() || c.source.is_some()) && c.native.is_none());
            if is_wasm && !instances.contains(name) {
                tracing::warn!(
                    code = "plugin_unavailable",
                    request_id = %rid,
                    route = %route.name,
                    plugin = %name,
                    reason = "per-request instantiation failed",
                    "route references a plugin that could not be instantiated"
                );
                obs.record_plugin_failure(name, "instantiate_failed");
                return Err(Box::new(unavailable_response(rid)));
            }
        }
        let (chain, create_failures) = PluginChain::new(
            &route.plugins,
            configs,
            registry,
            WasmChainAdapter::new(instances),
        );
        // Fail-closed native construction (DW-157): the health gate
        // admitted the entry (the name IS registered), but its factory
        // errored — the configured filter never runs, so the request
        // must not proceed. Never skip a create failure the gate
        // admitted.
        if let Some(failure) = create_failures.first() {
            tracing::warn!(
                code = "plugin_unavailable",
                request_id = %rid,
                route = %route.name,
                plugin = %failure.plugin,
                reason = %failure.message,
                "native filter construction failed; failing closed"
            );
            obs.record_plugin_failure(&failure.plugin, "instantiate_failed");
            return Err(Box::new(unavailable_response(rid)));
        }
        Ok(Some(Self {
            chain,
            request_headers_plugin,
            request_body_plugin,
            response_body_plugin,
        }))
    }

    /// Whether the chain has any plugin declaring `request_body`
    /// (buffers the request body when true — see the module docs).
    pub fn needs_request_body(&self) -> bool {
        self.chain.has_phase(PluginPhase::RequestBody)
    }

    /// Whether the chain has any plugin declaring `response_body`
    /// (buffers the response body when true — see the module docs).
    pub fn needs_response_body(&self) -> bool {
        self.chain.has_phase(PluginPhase::ResponseBody)
    }

    /// Run the `request_headers` phase: after route resolution, before
    /// authn (the documented contract — authn sees plugin-modified
    /// headers). `path_and_query` is the full request target (path
    /// including any query string). On `Ok` the (possibly rewritten)
    /// header map is in place and the returned [`PluginTargetRewrite`]
    /// carries the chain's validated `:path`/`:method`/`:authority`
    /// writes (see the module's "Header conventions" section) for the
    /// caller to apply at the forward build; on `Err` the caller
    /// returns the response immediately.
    pub fn request_headers_phase(
        &mut self,
        method: &hyper::Method,
        path_and_query: &str,
        headers: &mut HeaderMap,
        obs: &Observability,
        rid: &str,
        route: &str,
    ) -> Result<PluginTargetRewrite, PluginExit> {
        let mut map = Vec::with_capacity(headers.len() + 2);
        map.push((":method".to_string(), method.as_str().to_string()));
        map.push((":path".to_string(), path_and_query.to_string()));
        for (k, v) in headers.iter() {
            map.push((k.as_str().to_string(), v.to_str().unwrap_or("").to_string()));
        }
        // The write-back diffs against this snapshot of the input (the
        // chain consumes `map`); see `apply_header_changes`.
        let input = map.clone();
        match self.chain.on_request_headers(map) {
            (ChainOutcome::Continue, out) => {
                apply_header_changes(headers, &input, &out);
                let rewrite = pseudo_header_rewrite(
                    &input,
                    &out,
                    obs,
                    rid,
                    route,
                    self.request_headers_plugin.as_deref(),
                )?;
                Ok(rewrite)
            }
            (ChainOutcome::LocalResponse(resp), _) => {
                plugin_decision(rid, route);
                Err(Box::new(local_response(resp, rid)))
            }
            (ChainOutcome::Error { plugin, message }, _) => {
                Err(Box::new(plugin_error(obs, rid, route, &plugin, &message)))
            }
        }
    }

    /// Run the `request_body` phase: buffer the request body (capped —
    /// over-cap answers 500 `plugin_body_too_large`, fail-closed), let
    /// the chain rewrite it, and hand the action a fully-buffered
    /// `Full<Bytes>` body with a rewritten `Content-Length`. Runs after
    /// authz/rate-limit, before the route action (and before request
    /// validation, which then sees the post-plugin bytes).
    pub async fn request_body_phase<B>(
        &mut self,
        req: Request<B>,
        cap: u64,
        obs: &Observability,
        rid: &str,
        route: &str,
    ) -> Result<Request<Full<Bytes>>, PluginExit>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (mut parts, body) = req.into_parts();
        let bytes = match Limited::new(body, cap as usize).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                if err.downcast_ref::<LengthLimitError>().is_some() {
                    return Err(Box::new(body_too_large(
                        obs,
                        rid,
                        route,
                        cap,
                        self.request_body_plugin.as_deref(),
                    )));
                }
                tracing::warn!(
                    code = "plugin_body_read_failed",
                    request_id = %rid,
                    route = %route,
                    error = %err,
                    "request body could not be buffered for the plugin phase"
                );
                return Err(Box::new(simple(
                    StatusCode::BAD_REQUEST,
                    "plugin_body_read_failed",
                    "request body could not be read",
                    rid,
                )));
            }
        };
        match self.chain.on_request_body(bytes.to_vec()) {
            (ChainOutcome::Continue, out) => {
                let bytes = Bytes::from(out);
                set_content_length(&mut parts.headers, bytes.len());
                Ok(Request::from_parts(parts, Full::new(bytes)))
            }
            (ChainOutcome::LocalResponse(resp), _) => {
                plugin_decision(rid, route);
                Err(Box::new(local_response(resp, rid)))
            }
            (ChainOutcome::Error { plugin, message }, _) => {
                Err(Box::new(plugin_error(obs, rid, route, &plugin, &message)))
            }
        }
    }

    /// Run the `response_headers` phase: after the response arrives
    /// (any action: proxy, mock, respond, redirect alike — plugins are
    /// route-level), before masking. `:status` rides the map for
    /// visibility; plugin writes to it are IGNORED — a deliberate
    /// asymmetry with the request-side target rewrite: by the time
    /// this phase runs the status is bound to the response's framing
    /// (204/304/101 carry no body, and `Content-Length` already
    /// matches the upstream bytes a later phase may rewrite), so a
    /// mid-pipeline flip would desynchronize both. A plugin that
    /// wants to DECIDE the answer has `send_http_response` at the
    /// request phases.
    pub fn response_headers_phase(
        &mut self,
        status: StatusCode,
        headers: &mut HeaderMap,
        obs: &Observability,
        rid: &str,
        route: &str,
    ) -> Result<(), PluginExit> {
        let mut map = Vec::with_capacity(headers.len() + 1);
        map.push((":status".to_string(), status.as_u16().to_string()));
        for (k, v) in headers.iter() {
            map.push((k.as_str().to_string(), v.to_str().unwrap_or("").to_string()));
        }
        // The write-back diffs against this snapshot of the input (the
        // chain consumes `map`); see `apply_header_changes`.
        let input = map.clone();
        match self.chain.on_response_headers(map) {
            (ChainOutcome::Continue, out) => {
                apply_header_changes(headers, &input, &out);
                Ok(())
            }
            (ChainOutcome::LocalResponse(resp), _) => {
                plugin_decision(rid, route);
                Err(Box::new(local_response(resp, rid)))
            }
            (ChainOutcome::Error { plugin, message }, _) => {
                Err(Box::new(plugin_error(obs, rid, route, &plugin, &message)))
            }
        }
    }

    /// Run the `response_body` phase: after masking, before the
    /// operator transforms and compression. Bodiless statuses
    /// (informational, 101, 204, 304) have nothing to inspect and pass
    /// through untouched, exactly like masking; STREAMING bodies
    /// (`text/event-stream`, or a body of unknown length — chunked or
    /// otherwise un-framed) and CONTENT-ENCODED bodies are skipped,
    /// documented and logged once per response: buffering an endless
    /// SSE stream would stall the route, and an encoded body is opaque
    /// bytes to the plugin (dwara never decompresses on this path —
    /// compression is applied downstream, after this phase). Every
    /// other response on a chain with a `response_body` plugin is
    /// buffered up to `cap` (over-cap answers 500
    /// `plugin_body_too_large`, fail-closed), the chain may rewrite the
    /// bytes, and the response is rebuilt with a `Full` body and a
    /// rewritten `Content-Length`. When masking already buffered the
    /// body (its fail-closed path) this rides the same buffered bytes.
    pub async fn response_body_phase(
        &mut self,
        resp: Response<ProxyBody>,
        cap: u64,
        obs: &Observability,
        rid: &str,
        route: &str,
    ) -> Result<Response<ProxyBody>, PluginExit> {
        let status = resp.status();
        if status.is_informational()
            || status == StatusCode::SWITCHING_PROTOCOLS
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
        {
            return Ok(resp);
        }
        if let Some(reason) = plugin_body_skip_reason(&resp) {
            tracing::debug!(
                code = "plugin_response_body_skipped",
                request_id = %rid,
                route = %route,
                reason = reason,
                "streaming or content-encoded response; the response_body plugin phase is skipped"
            );
            return Ok(resp);
        }
        let (mut parts, body) = resp.into_parts();
        let bytes = match Limited::new(body, cap as usize).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                if err.downcast_ref::<LengthLimitError>().is_some() {
                    return Err(Box::new(body_too_large(
                        obs,
                        rid,
                        route,
                        cap,
                        self.response_body_plugin.as_deref(),
                    )));
                }
                // The response stream died mid-body before the phase
                // could run: attribute to the first response-body
                // plugin (the plugin itself never executed — the
                // distinct `response_stream_ended` reason keeps that
                // clear in the metric), fail closed.
                let name = self.response_body_plugin.as_deref().unwrap_or(route);
                tracing::warn!(
                    code = "plugin_failed",
                    request_id = %rid,
                    route = %route,
                    plugin = name,
                    error = %err,
                    "response body could not be buffered for the plugin phase"
                );
                obs.record_plugin_failure(name, "response_stream_ended");
                return Err(Box::new(plugin_failed_response(rid)));
            }
        };
        match self.chain.on_response_body(bytes.to_vec()) {
            (ChainOutcome::Continue, out) => {
                let bytes = Bytes::from(out);
                set_content_length(&mut parts.headers, bytes.len());
                Ok(Response::from_parts(
                    parts,
                    ProxyBody::Full(Full::new(bytes)),
                ))
            }
            (ChainOutcome::LocalResponse(resp), _) => {
                plugin_decision(rid, route);
                Err(Box::new(local_response(resp, rid)))
            }
            (ChainOutcome::Error { plugin, message }, _) => {
                Err(Box::new(plugin_error(obs, rid, route, &plugin, &message)))
            }
        }
    }
}

// --- Plugin status surface (DW-158) ---------------------------------------

/// A plugin's observable lifecycle state for the status surface (`GET
/// /plugins`, `dwara-cli status`, `dwara_plugin_total{state}`). The
/// three lifecycle states come from [`PluginHealth`]; the two extra
/// states cover plugins that are declared in the config but unusable
/// BEFORE the lifecycle can judge them (the same conditions the
/// request-path gate fails closed on, so the status surface never
/// shows a plugin as serving when its routes answer 500).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginStatusState {
    /// Loaded and serving: a healthy WASM plugin or a registered
    /// native filter.
    Healthy,
    /// The .wasm could not be read or compiled (lifecycle judgment);
    /// routes referencing it fail closed.
    Crashed { error: String, crash_count: u32 },
    /// Disabled (manually or by a circuit breaker); routes referencing
    /// it fail closed.
    Disabled { reason: String },
    /// Declared but not present in the running plugin runtime: a
    /// registry `source:` artifact that has not been through a
    /// resolution+load cycle yet, or a generation tear after a failed
    /// engine rebuild.
    NotLoaded,
    /// A native filter whose registered name has no factory in the
    /// registry; routes referencing it fail closed.
    NotRegistered,
}

impl PluginStatusState {
    /// The closed label vocabulary shared by `GET /plugins`, the CLI
    /// status section, and `dwara_plugin_total{state}` — one mapping,
    /// three surfaces, no drift.
    pub fn label(&self) -> &'static str {
        match self {
            PluginStatusState::Healthy => "healthy",
            PluginStatusState::Crashed { .. } => "crashed",
            PluginStatusState::Disabled { .. } => "disabled",
            PluginStatusState::NotLoaded => "not_loaded",
            PluginStatusState::NotRegistered => "not_registered",
        }
    }
}

/// One plugin's status entry (DW-158): what the admin endpoint, the
/// CLI, and the per-state gauge are all built from.
#[derive(Clone, Debug)]
pub struct PluginStatusEntry {
    /// The config-declared plugin name.
    pub name: String,
    /// `"wasm"` (local `.wasm` path), `"registry"` (remote source), or
    /// `"native"` (compiled-in filter).
    pub kind: &'static str,
    /// Where the plugin comes from: the `.wasm` path, the registry
    /// URL, or the registered native filter name.
    pub source: String,
    /// SHA-256 digest of the loaded `.wasm` artifact (hot-swap
    /// change-detection key). Empty when there is no digest to report:
    /// native plugins (no artifact), registry plugins before their
    /// artifact is resolved, or a `.wasm` that could not be read.
    pub sha256: String,
    /// The plugin's lifecycle state.
    pub state: PluginStatusState,
    /// Effective resource limits — configured value or the documented
    /// default — as `(fuel, memory_mb, timeout_ms)`. `None` for native
    /// plugins (in-process; the config schema documents `limits` as
    /// wasm-only).
    pub limits: Option<(u64, usize, u64)>,
    /// The phases the plugin declared (config order).
    pub phases: Vec<PluginPhase>,
    /// Route names whose `plugins` list references this plugin (config
    /// order) — the blast radius of a state change.
    pub referenced_by: Vec<String>,
}

/// Enumerate the generation's declared plugins as status entries
/// (DW-158), in config order. Health and digest come from the live
/// [`PluginLifecycle`] (WASM local and registry-resolved alike,
/// DW-165) or the [`NativeRegistry`] (native names). The dataplane
/// serves this through `DataPlane::plugin_statuses` (the admin `GET
/// /plugins` handler) and folds it into `dwara_plugin_total{state}`
/// at publish time — the same enumeration, so the endpoint, the CLI,
/// and the metric can never disagree.
pub fn plugin_statuses(
    lifecycle: &PluginLifecycle,
    registry: &NativeRegistry,
    gateway: &Gateway,
) -> Vec<PluginStatusEntry> {
    gateway
        .plugins
        .iter()
        .map(|config| {
            let referenced_by: Vec<String> = gateway
                .routes
                .iter()
                .filter(|r| r.plugins.iter().any(|n| n == &config.name))
                .map(|r| r.name.clone())
                .collect();
            let (kind, source, sha256, state, limits) = if let Some(native) = &config.native {
                // DW-119: a compiled-in filter. The registry lookup IS
                // its health: an unregistered name fails closed at
                // request time exactly like a crashed plugin.
                let state = if registry.contains(native) {
                    PluginStatusState::Healthy
                } else {
                    PluginStatusState::NotRegistered
                };
                ("native", native.clone(), String::new(), state, None)
            } else {
                // A WASM plugin from either local origin: a `wasm:`
                // path or a registry `source:` (SCALE-12/DW-165)
                // resolved to a verified local artifact. Health and
                // digest come from the lifecycle, which loads/compiles
                // with every generation (checksum-keyed); a `source:`
                // that failed resolution reads Crashed with the
                // step-named error, its routes fail-closed.
                let (kind, source) = if let Some(src) = &config.source {
                    ("registry", src.url.clone())
                } else {
                    ("wasm", config.wasm.clone().unwrap_or_default())
                };
                let loaded = lifecycle.get_plugin(&config.name);
                let (sha256, state) = match &loaded {
                    None => (String::new(), PluginStatusState::NotLoaded),
                    Some(lp) => {
                        let state = match &lp.health {
                            PluginHealth::Healthy => PluginStatusState::Healthy,
                            PluginHealth::Crashed { error, crash_count } => {
                                PluginStatusState::Crashed {
                                    error: error.clone(),
                                    crash_count: *crash_count,
                                }
                            }
                            PluginHealth::Disabled { reason } => PluginStatusState::Disabled {
                                reason: reason.clone(),
                            },
                        };
                        (lp.checksum.clone(), state)
                    }
                };
                (kind, source, sha256, state, Some(effective_limits(config)))
            };
            PluginStatusEntry {
                name: config.name.clone(),
                kind,
                source,
                sha256,
                state,
                limits,
                phases: config.phases.clone(),
                referenced_by,
            }
        })
        .collect()
}

/// A plugin's effective limits: the configured value where set, else
/// the documented defaults (the same defaults the runner instantiates
/// with, single-sourced from [`crate::wasm::PluginLimits::default`]).
fn effective_limits(config: &PluginConfig) -> (u64, usize, u64) {
    let defaults = crate::wasm::PluginLimits::default();
    let limits = config.limits.as_ref();
    (
        limits.and_then(|l| l.fuel).unwrap_or(defaults.fuel),
        limits
            .and_then(|l| l.memory_mb)
            .unwrap_or(defaults.memory_mb),
        limits
            .and_then(|l| l.timeout_ms)
            .unwrap_or(defaults.timeout_ms),
    )
}

/// Group a header list by name (first-seen order), preserving each
/// name's value sequence so multiplicity is compared exactly.
/// Pseudo-headers (leading `:`) are excluded — the ordinary header map
/// never carries them; the request-side target pseudo-headers are
/// captured separately by [`pseudo_header_rewrite`].
fn group_header_list(list: &[(String, String)]) -> Vec<(String, Vec<&str>)> {
    let mut grouped: Vec<(String, Vec<&str>)> = Vec::new();
    for (name, value) in list {
        if name.starts_with(':') {
            continue;
        }
        match grouped.iter_mut().find(|(n, _)| n == name) {
            Some((_, values)) => values.push(value.as_str()),
            None => grouped.push((name.clone(), vec![value.as_str()])),
        }
    }
    grouped
}

/// The pseudo-headers whose CHANGED values rewrite the forwarded
/// request (see the module docs): `:path` (the whole upstream target,
/// query string included), `:method`, and `:authority` (the forwarded
/// `Host`). Any other pseudo-header name stays ignored.
const TARGET_PSEUDO_HEADERS: [&str; 3] = [":path", ":method", ":authority"];

/// The LAST value a header list carries for `name` (case-insensitive
/// — the host's replace/add hostcalls both land the newest write at or
/// after the previous one), or `None` when the name is absent.
fn last_header_value<'a>(list: &'a [(String, String)], name: &str) -> Option<&'a str> {
    list.iter()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Extract the chain's pseudo-header target rewrite from the
/// `request_headers` output and validate it (see the module's "Header
/// conventions" section). Only names whose value the chain CHANGED
/// participate — writing back the value the map carried is the
/// documented no-op, and a REMOVED pseudo-header is ignored (the
/// request keeps its real method/path). An invalid changed value fails
/// closed (500 `plugin_failed`, metric reason `invalid_rewrite`),
/// attributed to the first plugin declaring the phase (`plugin`; the
/// merged chain output has no per-plugin author — the same
/// deterministic first-declarer attribution the body phases use).
/// The invalid value itself is never logged: a `:path` carries the
/// query string, which logs must not see.
fn pseudo_header_rewrite(
    input: &[(String, String)],
    output: &[(String, String)],
    obs: &Observability,
    rid: &str,
    route: &str,
    plugin: Option<&str>,
) -> Result<PluginTargetRewrite, PluginExit> {
    let mut rewrite = PluginTargetRewrite::default();
    for name in TARGET_PSEUDO_HEADERS {
        // Absent from the output (never written, or removed): no
        // rewrite from this name.
        let Some(new) = last_header_value(output, name) else {
            continue;
        };
        // Identical to the input value: zero effect.
        if last_header_value(input, name) == Some(new) {
            continue;
        }
        match name {
            // Origin-form only: non-empty, leading '/', parseable as a
            // path-and-query (rejects bad characters and fragments).
            // An absolute-form target would move the dial target — the
            // upstream pick is the balancer's, never the plugin's.
            ":path" => match if new.is_empty() || !new.starts_with('/') {
                None
            } else {
                new.parse::<PathAndQuery>().ok()
            } {
                Some(target) => rewrite.path = Some(target),
                None => {
                    return Err(Box::new(invalid_rewrite(obs, rid, route, plugin, name)));
                }
            },
            ":method" => match new.parse::<hyper::Method>() {
                Ok(method) => rewrite.method = Some(method),
                Err(_) => {
                    return Err(Box::new(invalid_rewrite(obs, rid, route, plugin, name)));
                }
            },
            // The authority grammar, converted to the header value the
            // forward will carry: either parse failing (empty,
            // userinfo, bad bytes) is an unusable Host — fail closed.
            ":authority" => match new
                .parse::<http::uri::Authority>()
                .ok()
                .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
            {
                Some(host) => rewrite.authority = Some(host),
                None => {
                    return Err(Box::new(invalid_rewrite(obs, rid, route, plugin, name)));
                }
            },
            _ => unreachable!("TARGET_PSEUDO_HEADERS enumerates every match arm"),
        }
    }
    Ok(rewrite)
}

/// The fail-closed 500 for a plugin's invalid target rewrite (empty,
/// non-`/`-prefixed, or unparseable `:path`; a non-token `:method`;
/// an unparseable `:authority`): one failure metric (`invalid_rewrite`
/// — attributed to the first `request_headers` plugin, falling back to
/// the route name exactly like the body-cap attribution), one
/// server-side log naming the pseudo-header but never the value, and
/// the generic envelope. The request does not proceed to the upstream.
fn invalid_rewrite(
    obs: &Observability,
    rid: &str,
    route: &str,
    plugin: Option<&str>,
    name: &str,
) -> Response<ProxyBody> {
    let attribution = plugin.unwrap_or(route);
    tracing::warn!(
        code = "plugin_failed",
        request_id = %rid,
        route = %route,
        plugin = %attribution,
        pseudo_header = name,
        "plugin wrote an invalid target rewrite; failing closed"
    );
    obs.record_plugin_failure(attribution, "invalid_rewrite");
    plugin_failed_response(rid)
}

/// Why a response's `response_body` plugin phase is skipped (DW-157):
/// the body is streaming (SSE or un-framed — buffering it would stall
/// the route) or content-encoded (opaque bytes to the plugin; dwara
/// never decompresses on this path). `None` = bufferable.
fn plugin_body_skip_reason(resp: &Response<ProxyBody>) -> Option<&'static str> {
    let headers = resp.headers();
    if headers.contains_key(hyper::header::CONTENT_ENCODING) {
        return Some("content_encoded");
    }
    let sse = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        });
    if sse {
        return Some("streaming");
    }
    if !headers.contains_key(hyper::header::CONTENT_LENGTH) {
        // No declared length: chunked or an open-ended stream. The
        // phase needs the WHOLE body up front, which is exactly what
        // these bodies never promise.
        return Some("streaming");
    }
    None
}

/// A plugin DECIDED the request's answer (`send_http_response` or a
/// native LocalResponse): not a failure — log at info for the audit
/// trail; the access-log `plugin_short_circuit` flag is set by the
/// caller (the proxy).
fn plugin_decision(rid: &str, route: &str) {
    tracing::info!(
        code = "plugin_short_circuit",
        request_id = %rid,
        route = %route,
        "plugin answered the request locally; the upstream was not dialed"
    );
}

/// A plugin failed (WASM trap or native filter error): fail-closed 500
/// `plugin_failed`, one failure metric, one server-side log naming the
/// plugin. The trap detail never reaches the client.
fn plugin_error(
    obs: &Observability,
    rid: &str,
    route: &str,
    plugin: &str,
    message: &str,
) -> Response<ProxyBody> {
    tracing::warn!(
        code = "plugin_failed",
        request_id = %rid,
        route = %route,
        plugin = %plugin,
        reason = %message,
        "plugin trapped or errored; failing closed"
    );
    obs.record_plugin_failure(plugin, "trap");
    plugin_failed_response(rid)
}

fn plugin_failed_response(rid: &str) -> Response<ProxyBody> {
    simple(
        StatusCode::INTERNAL_SERVER_ERROR,
        "plugin_failed",
        "a plugin on this route failed",
        rid,
    )
}

fn unavailable_response(rid: &str) -> Response<ProxyBody> {
    simple(
        StatusCode::INTERNAL_SERVER_ERROR,
        "plugin_unavailable",
        "a plugin on this route is unavailable",
        rid,
    )
}

/// The fail-closed 500 for an unusable plugin (missing, crashed,
/// disabled, unregistered native, failed instantiation): metric +
/// server-side log (the specific reason) + the generic envelope.
fn unavailable(
    obs: &Observability,
    name: &str,
    reason: &'static str,
    route: &Route,
    rid: &str,
) -> Response<ProxyBody> {
    tracing::warn!(
        code = "plugin_unavailable",
        request_id = %rid,
        route = %route.name,
        plugin = %name,
        reason = reason,
        "route references an unusable plugin; failing closed"
    );
    obs.record_plugin_failure(name, reason);
    unavailable_response(rid)
}

/// The fail-closed 500 for a body over the plugin buffering cap.
/// `plugin` is the first plugin declaring the phase (deterministic
/// attribution; falls back to the route name — the phase, not one
/// plugin, is what could not be satisfied — keeping the metric's label
/// space config-bounded either way).
fn body_too_large(
    obs: &Observability,
    rid: &str,
    route: &str,
    cap: u64,
    plugin: Option<&str>,
) -> Response<ProxyBody> {
    let name = plugin.unwrap_or(route);
    tracing::warn!(
        code = "plugin_body_too_large",
        request_id = %rid,
        route = %route,
        plugin = name,
        cap_bytes = cap,
        "body exceeds the plugin buffering cap; failing closed"
    );
    obs.record_plugin_failure(name, "body_too_large");
    simple(
        StatusCode::INTERNAL_SERVER_ERROR,
        "plugin_body_too_large",
        &format!("body exceeds the plugin buffering cap of {cap} bytes"),
        rid,
    )
}

/// Build the response for a plugin's local response
/// (`proxy_send_http_response` / native LocalResponse): the plugin's
/// status, headers, and body verbatim; a `content-type` default of
/// `application/json` when it set none (mirroring the nano-service
/// response builder).
fn local_response(resp: LocalResponse, rid: &str) -> Response<ProxyBody> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    let has_content_type = resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    if !has_content_type && !resp.body.is_empty() {
        builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
    }
    for (name, value) in &resp.headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(n, v);
        }
    }
    match builder.body(ProxyBody::Full(Full::new(Bytes::from(resp.body)))) {
        Ok(resp) => resp,
        Err(_) => plugin_failed_response(rid),
    }
}

/// Write a plugin phase's header output back into the live
/// [`HeaderMap`], applying ONLY what the chain actually changed
/// (DW-157). The `(String, String)` list the sandbox sees cannot
/// represent non-UTF-8 header values (legal obs-text), so a
/// clear-and-rebuild would blank them. Instead:
///
/// - when the chain returned its input unchanged (the common case — no
///   plugin in the phase, or pure pass-through) the map is not touched
///   at all;
/// - otherwise the lists are diffed per name: only names whose VALUE
///   LIST the chain changed (added, removed, reordered, or rewritten)
///   are rewritten in the map; every other header keeps its original
///   bytes, non-UTF-8 values included.
///
/// Pseudo-headers (leading `:`) are excluded from both sides — the
/// ordinary header map never carries them (the request-side target
/// pseudo-headers are applied separately; see
/// [`pseudo_header_rewrite`]). Unparseable names/values a changed name
/// produced are skipped (the sandbox cannot crash the gateway with a
/// bad header).
fn apply_header_changes(
    headers: &mut HeaderMap,
    input: &[(String, String)],
    output: &[(String, String)],
) {
    if input == output {
        return;
    }
    let before = group_header_list(input);
    let after = group_header_list(output);
    for (name, new_values) in &after {
        let unchanged = before
            .iter()
            .find(|(n, _)| n == name)
            .is_some_and(|(_, old_values)| old_values == new_values);
        if unchanged {
            continue;
        }
        // The chain changed this name's value list: rewrite it in the
        // map. `remove` drops every value of the name; the plugin's
        // list is the new truth for it.
        headers.remove(name.as_str());
        for value in new_values {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(n, v);
            }
        }
    }
    // Names the chain REMOVED (present before, absent after).
    for (name, _) in &before {
        if !after.iter().any(|(n, _)| n == name) {
            headers.remove(name.as_str());
        }
    }
}

/// Set `Content-Length` to the (rewritten) body length after a body
/// phase replaces the body with buffered bytes. Framing is exact: the
/// buffered bytes ARE the body now.
fn set_content_length(headers: &mut HeaderMap, len: usize) {
    headers.remove(hyper::header::TRANSFER_ENCODING);
    if let Ok(v) = HeaderValue::from_str(&len.to_string()) {
        headers.insert(hyper::header::CONTENT_LENGTH, v);
    }
}

/// The uniform gateway error envelope (a local copy of the proxy's
/// `simple` responder: this module builds its own responses and the
/// proxy's helper is private to that module).
fn simple(status: StatusCode, code: &str, msg: &str, rid: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(ProxyBody::Full(Full::new(
            crate::observability::envelope_body(code, msg, rid),
        )))
        .expect("static error body is valid")
}
