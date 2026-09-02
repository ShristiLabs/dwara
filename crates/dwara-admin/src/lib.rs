//! Admin API (DW-022, feature analysis 4.18; decision 6: mTLS-only).
//!
//! A small, separate hyper server surface for operators:
//!
//! - `GET /config` — the CURRENT published gateway config as normalized
//!   YAML, with `x-dwara-config-generation` / `x-dwara-config-hash`
//!   headers identifying the generation. SECRET REDACTION (DW-045): the
//!   returned document is the TYPED-redacted copy
//!   ([`Gateway::redacted`](dwara_core::config::Gateway::redacted)) —
//!   inline `api_key` values become unresolvable
//!   `${redacted:sha256:<prefix>}` placeholders (a short sha256 prefix so
//!   operators can still compare which key a generation carries), and
//!   `${...}` references echo as references (an env-var name or file
//!   path is not secret bytes; the config file already carries it). No
//!   secret VALUE is ever returned, by construction. Consequence, by
//!   design: a GET-then-edit-then-PATCH round trip that carries a
//!   placeholder back is REJECTED by validation (400 naming the field)
//!   instead of silently installing placeholder bytes as a live key —
//!   re-enter the secret or switch the field to a reference.
//! - `PATCH /config` — FULL-document YAML replacement (v1 has no partial
//!   merge: silent-merge of unknown subtrees is a footgun, so a PATCH
//!   body must be the complete config). The body is parsed, validated,
//!   and compiled as a dry run FIRST; on any issue the response is 400
//!   carrying EVERY problem (the same error envelope style as the
//!   dataplane). On success the new config is written ATOMICALLY to the
//!   config file (temp file + rename, so the file watcher and restarts
//!   observe exactly what was published) and then published to the
//!   running dataplane. Documented consequence: the gateway's config
//!   watcher also observes the rename; because the content is identical
//!   to what was just published, the watcher's reload is a no-op (the
//!   generation does not advance again).
//! - `GET /health` — gateway readiness, config generation, and
//!   per-upstream per-endpoint health labels.
//! - `GET /stats` — cheap live state only: state-store schema version
//!   (when a store is attached), per-upstream breaker states, the
//!   active-requests gauge, the config generation, and the response
//!   cache's live-entry estimate and purge count (DW-037).
//! - `POST /cache/purge` — response-cache invalidation (DW-037): body
//!   `{"route": "<name>"}` or `{"all": true}`; the response names what
//!   was invalidated. Purge is an O(1) cache-epoch advance, never a
//!   store enumeration — sub-100 ms at any store size by construction.
//! - `GET /mcp/sessions` — list active MCP sessions (DW-087).
//! - `DELETE /mcp/sessions/:id` — teardown an MCP session (DW-087).
//! - `GET /mcp/tools` — list configured MCP tools (DW-087).
//! - `GET /mcp/calls` — query MCP tool call analytics (DW-087).
//!
//! AUTHENTICATION IS THE TLS LAYER (decision 6): the admin listener
//! REQUIRES a client certificate chaining to the configured CA; there is
//! deliberately no token layer in v1 — possession of a valid client
//! certificate IS the authorization. The one escape hatch is
//! [`ListenMode::dev`] (loopback-only plaintext, gated by the binary on
//! `DWARA_ADMIN_DEV=1`), which must never be enabled outside a
//! developer machine.
//!
//! The admin listener has its own accept loop and graceful shutdown;
//! its bind set is fixed at startup (config changes to `admin.bind`
//! take effect on restart). The accept loop runs under the same
//! bounded panic-respawn supervision as the gateway listeners (#130,
//! via dwara-core's shared supervisor from #120): a panicked accept
//! incarnation is respawned on the same socket up to a fixed budget,
//! after which the admin listener is given up on with a loud ERROR log
//! instead of dying silently for the rest of the process lifetime.
//!
//! Hardening posture (DW-023): the admin listener shares the
//! dataplane's parser/amplification bounds and its pre-parse smuggling
//! guard (the same `dwara_core::hardening::HttpHardening` is applied to
//! its connection builder), with ONE deliberate asymmetry: request
//! bodies are NOT wrapped in the slow-body gap wrapper
//! (`hardening::InboundBody`). The admin surface is mTLS-only (decision
//! 6 — every client holds a CA-chained certificate), and its bodies are
//! small JSON/YAML documents already capped DURING streaming by
//! `MAX_PATCH_BODY`'s `Limited` wrapper, so the per-connection
//! body-inactivity defense of the data plane would add nothing the TLS
//! requirement and the mid-stream cap do not already pin; body-stall
//! protection remains a data-plane concern.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::{gateway_to_yaml, parse_gateway, AdminConfig, Gateway};
use dwara_core::observability::{envelope_body, resolve_request_id};
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::{compile, ConfigState};
use dwara_core::tls;
use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};

/// Response body type of the admin API (always complete in memory).
type AdminBody = Full<Bytes>;

/// Hard cap on a PATCH body: the config is a small YAML document; a
/// multi-megabyte body is a mistake or abuse. The cap is enforced
/// DURING streaming (`http_body_util::Limited` wraps the request body
/// before collection), so an oversized body is rejected while it is
/// still arriving and is never fully buffered in memory.
const MAX_PATCH_BODY: usize = 4 * 1024 * 1024;

/// Hard cap on a purge body (DW-037): `{"route": "<name>"}` or
/// `{"all": true}` — a few hundred bytes of JSON at most.
const MAX_PURGE_BODY: usize = 4096;

/// Everything the admin handlers need: the published-config state, the
/// dataplane (for refresh/health/stats), the config file path (for
/// atomic writes), the write lock serializing PATCHes, and the process
/// start instant (for `/runtime_info` uptime, DW-072).
pub struct AdminContext {
    state: Arc<ConfigState>,
    dp: Arc<DataPlane>,
    config_path: PathBuf,
    patch_lock: Arc<Mutex<()>>,
    started: std::time::Instant,
}

impl AdminContext {
    pub fn new(state: Arc<ConfigState>, dp: Arc<DataPlane>, config_path: PathBuf) -> Self {
        AdminContext {
            state,
            dp,
            config_path,
            patch_lock: Arc::new(Mutex::new(())),
            started: std::time::Instant::now(),
        }
    }
}

/// How the admin listener accepts connections.
#[derive(Clone)]
pub enum ListenMode {
    /// mTLS: rustls `ServerConfig` requiring client certificates that
    /// chain to the configured CA (the production shape; decision 6).
    Mtls(Box<rustls::ServerConfig>),
    /// DEV ONLY: plaintext loopback. Gated by the binary on
    /// `DWARA_ADMIN_DEV=1` and refused for non-loopback binds.
    DevPlaintext,
}

/// Error building the admin listener.
#[derive(Debug)]
pub enum AdminBuildError {
    Tls(dwara_core::tls::TlsError),
    /// Dev mode was requested for a bind that is not loopback.
    NotLoopback(String),
}

impl std::fmt::Display for AdminBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminBuildError::Tls(e) => write!(f, "admin tls setup failed: {e}"),
            AdminBuildError::NotLoopback(bind) => write!(
                f,
                "DWARA_ADMIN_DEV=1 permits plaintext admin on LOOPBACK only; \
                 '{bind}' is not loopback"
            ),
        }
    }
}

impl std::error::Error for AdminBuildError {}

impl ListenMode {
    /// The production shape: mTLS with mandatory client certificates.
    pub fn mtls(cfg: &AdminConfig) -> Result<Self, AdminBuildError> {
        Ok(ListenMode::Mtls(Box::new(
            tls::admin_mtls_server_config(&cfg.tls).map_err(AdminBuildError::Tls)?,
        )))
    }

    /// The dev shape: plaintext, refused unless the bind is loopback.
    /// The CALLER (dwara-bin) is responsible for gating this on
    /// `DWARA_ADMIN_DEV=1`; this method enforces the loopback half of
    /// the contract so a non-loopback plaintext admin can never start.
    pub fn dev(cfg: &AdminConfig) -> Result<Self, AdminBuildError> {
        match cfg.bind.parse::<std::net::SocketAddr>() {
            Ok(addr) if addr.ip().is_loopback() => Ok(ListenMode::DevPlaintext),
            _ => Err(AdminBuildError::NotLoopback(cfg.bind.clone())),
        }
    }
}

/// Wall-clock milliseconds since the Unix epoch (the health module's
/// clock domain).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Write `contents` to `path` atomically: a named temp file in the same
/// directory (same filesystem, so rename is atomic), fsync, rename over
/// the destination. A crash mid-write leaves either the old or the new
/// document, never a torn one.
fn write_atomic(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(contents.as_bytes())?;
    tmp.flush()?;
    tmp.reopen()?.sync_all()?;
    tmp.persist(path)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

fn envelope(status: u16, code: &str, message: &str, request_id: &str) -> Response<AdminBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(envelope_body(code, message, request_id)))
        .expect("static response parts")
}

fn json_response(status: u16, body: serde_json::Value) -> Response<AdminBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static response parts")
}

fn generation_headers(
    mut resp: Response<AdminBody>,
    generation: u64,
    content_hash: u64,
) -> Response<AdminBody> {
    resp.headers_mut().insert(
        "x-dwara-config-generation",
        generation
            .to_string()
            .parse()
            .expect("u64 header value is valid ASCII"),
    );
    resp.headers_mut().insert(
        "x-dwara-config-hash",
        format!("{content_hash:#x}")
            .parse()
            .expect("hex header value is valid ASCII"),
    );
    resp
}

/// GET /health: readiness (at least one published generation), the
/// current generation, and per-endpoint health labels from the live
/// upstream registry (the same balancer state the dataplane picks
/// through).
fn health_body(ctx: &AdminContext) -> serde_json::Value {
    let snapshot = ctx.state.snapshot();
    let registry = ctx.dp.registry();
    let now = now_ms();
    let mut upstreams = serde_json::Map::new();
    for name in registry.names() {
        let Some(handle) = registry.get(name) else {
            continue;
        };
        let mut endpoints = serde_json::Map::new();
        for (addr, port, health) in handle.lb().health_targets() {
            let label = health
                .as_ref()
                .map(|h| h.state_label(now))
                .unwrap_or("healthy");
            endpoints.insert(format!("{addr}:{port}"), serde_json::json!(label));
        }
        upstreams.insert(
            name.to_string(),
            serde_json::json!({ "endpoints": endpoints }),
        );
    }
    serde_json::json!({
        "ready": ctx.dp.ready(),
        "config_generation": snapshot.generation(),
        "upstreams": upstreams,
    })
}

/// GET /stats: cheap live state only. `schema_version` is the SQLite
/// store's current schema (null when no state store is attached);
/// `breakers` maps each upstream to `closed`/`open`/`half_open`, or
/// `disabled` when the upstream configures no breaker; the
/// active-requests gauge and config generation round it out. Anything
/// more expensive belongs in the metrics endpoint (DW-021), not here.
fn stats_body(ctx: &AdminContext) -> serde_json::Value {
    let snapshot = ctx.state.snapshot();
    let registry = ctx.dp.registry();
    let mut breakers = serde_json::Map::new();
    for name in registry.names() {
        let Some(handle) = registry.get(name) else {
            continue;
        };
        let label = if handle.breaker_params().is_none() {
            "disabled"
        } else {
            match handle.breaker().state() {
                dwara_core::breaker::BreakerState::Closed { .. } => "closed",
                dwara_core::breaker::BreakerState::Open { .. } => "open",
                dwara_core::breaker::BreakerState::HalfOpen { .. } => "half_open",
            }
        };
        breakers.insert(name.to_string(), serde_json::json!(label));
    }
    let schema_version = ctx
        .dp
        .state_store()
        .and_then(|s| s.schema_info().ok())
        .map(|info| info.current);
    serde_json::json!({
        "schema_version": schema_version,
        "breakers": breakers,
        "active_requests": ctx.dp.observability().active_requests().get(),
        "config_generation": snapshot.generation(),
        "cache": {
            "entries": ctx.dp.response_cache().live_entries(),
            "purges": ctx.dp.response_cache().purge_count(),
        },
    })
}

/// GET /stats?format=prometheus (DW-072): the full Prometheus text-format
/// dump — every metric family in the registry, text-encoded. The default
/// (no `format` param) returns the existing JSON shape (`stats_body`).
fn stats_prometheus(ctx: &AdminContext) -> Response<AdminBody> {
    let text = ctx.dp.observability().render();
    Response::builder()
        .status(200)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(text)))
        .expect("static response parts")
}

/// GET /clusters (DW-072): Envoy-style cluster dump. Per upstream: the
/// load-balancer algorithm, scheme (http/https), connection/request
/// counters, breaker state, and per-endpoint health + inflight counts.
/// Everything here is live state from the registry — no config echo.
fn clusters_body(ctx: &AdminContext) -> serde_json::Value {
    let registry = ctx.dp.registry();
    let now = now_ms();
    let mut upstreams = serde_json::Map::new();
    for name in registry.names() {
        let Some(handle) = registry.get(name) else {
            continue;
        };
        let lb = handle.lb();
        let algo = match lb.algorithm() {
            dwara_core::config::LoadBalancer::RoundRobin => "round_robin",
            dwara_core::config::LoadBalancer::LeastRequests => "least_requests",
            dwara_core::config::LoadBalancer::Random => "random",
            dwara_core::config::LoadBalancer::IpHash => "ip_hash",
            dwara_core::config::LoadBalancer::PeakEwma => "peak_ewma",
        };
        let breaker_state = if handle.breaker_params().is_none() {
            serde_json::json!("disabled")
        } else {
            match handle.breaker().state() {
                dwara_core::breaker::BreakerState::Closed { consecutive } => {
                    serde_json::json!({
                        "state": "closed",
                        "consecutive_failures": consecutive,
                    })
                }
                dwara_core::breaker::BreakerState::Open { until_ms } => {
                    serde_json::json!({
                        "state": "open",
                        "until_ms": until_ms,
                    })
                }
                dwara_core::breaker::BreakerState::HalfOpen { probes_left } => {
                    serde_json::json!({
                        "state": "half_open",
                        "probes_left": probes_left,
                    })
                }
            }
        };
        let mut endpoints = Vec::new();
        for (i, (addr, port, health)) in lb.health_targets().iter().enumerate() {
            let label = health
                .as_ref()
                .map(|h| h.state_label(now))
                .unwrap_or("healthy");
            endpoints.push(serde_json::json!({
                "address": addr,
                "port": port,
                "health": label,
                "inflight": lb.inflight(i),
            }));
        }
        upstreams.insert(
            name.to_string(),
            serde_json::json!({
                "algorithm": algo,
                "scheme": handle.scheme(),
                "connections_opened": handle.connections_opened(),
                "requests_sent": handle.requests_sent(),
                "connection_cap": handle.cap(),
                "max_pending": handle.max_pending(),
                "breaker": breaker_state,
                "endpoints": endpoints,
            }),
        );
    }
    serde_json::json!({
        "upstreams": upstreams,
    })
}

/// GET /config_dump (DW-072): the full published gateway config as JSON
/// (redacted — inline secrets become `${redacted:...}` placeholders),
/// with generation and content-hash headers. The existing GET /config
/// returns YAML; this endpoint returns JSON for tooling that consumes
/// structured config dumps (Envoy's `/config_dump` is JSON).
fn config_dump_body(ctx: &AdminContext) -> serde_json::Value {
    let snapshot = ctx.state.snapshot();
    let gateway = snapshot.gateway().redacted();
    serde_json::to_value(&gateway).unwrap_or_else(|_| {
        serde_json::json!({
            "error": "config serialization failed",
            "generation": snapshot.generation(),
        })
    })
}

/// GET /runtime_info (DW-072): process-level runtime information —
/// version, uptime, config generation, and dataplane readiness.
fn runtime_info_body(ctx: &AdminContext) -> serde_json::Value {
    let snapshot = ctx.state.snapshot();
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": ctx.started.elapsed().as_secs(),
        "ready": ctx.dp.ready(),
        "config_generation": snapshot.generation(),
        "config_hash": format!("{:#x}", snapshot.content_hash()),
    })
}

/// POST /cache/purge (DW-037): invalidate cached responses. Body is
/// `{"route": "<name>"}` (one route; 404 when the name is not in the
/// CURRENT config) or `{"all": true}` (every current route). Purge is
/// an O(1) cache-epoch advance — the response names exactly what was
/// invalidated and the epoch it now sits at; the store is never
/// enumerated, which is why the operation stays well under the 100 ms
/// bar at any store size.
async fn purge_cache(ctx: &AdminContext, body: Bytes, request_id: &str) -> Response<AdminBody> {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return envelope(
                400,
                "cache_purge_invalid",
                &format!("body is not valid JSON: {err}"),
                request_id,
            )
        }
    };
    let snapshot = ctx.state.snapshot();
    if parsed.get("all").and_then(|v| v.as_bool()) == Some(true) {
        let names: Vec<String> = snapshot
            .gateway()
            .routes
            .iter()
            .map(|r| r.name.clone())
            .collect();
        let bumped = ctx.dp.response_cache().purge_all(names.iter().cloned());
        ctx.dp.observability().record_cache_purge("all");
        tracing::info!(
            code = "cache_purged",
            scope = "all",
            routes = bumped,
            "cache purged for every current route (epoch advance)"
        );
        return json_response(
            200,
            serde_json::json!({
                "all": true,
                "routes": names,
                "routes_invalidated": bumped,
            }),
        );
    }
    let Some(route) = parsed.get("route").and_then(|v| v.as_str()) else {
        return envelope(
            400,
            "cache_purge_invalid",
            "body must be {\"route\": \"<name>\"} or {\"all\": true}",
            request_id,
        );
    };
    if !snapshot.gateway().routes.iter().any(|r| r.name == route) {
        return envelope(
            404,
            "cache_purge_unknown_route",
            &format!("no route named '{route}' in the current config"),
            request_id,
        );
    }
    let epoch = ctx.dp.response_cache().bump_route(route);
    ctx.dp.observability().record_cache_purge("route");
    tracing::info!(
        code = "cache_purged",
        scope = "route",
        route = route,
        epoch = epoch,
        "cache purged for route (epoch advance)"
    );
    json_response(200, serde_json::json!({ "route": route, "epoch": epoch }))
}

/// Percent-decode one query-string component (`%XX` and `+`-as-space;
/// a stray `%` without two hex digits decodes as itself — the admin
/// surface is mTLS-gated, lenient decode beats rejecting).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if let (Some(h), Some(l)) = (
                    bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16)),
                    bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16)),
                ) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a request URI's query string into decoded (key, value) pairs.
fn query_params(uri: &hyper::Uri) -> Vec<(String, String)> {
    let Some(q) = uri.query() else {
        return Vec::new();
    };
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// Look one parameter up (first occurrence wins).
fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The not-configured answer shared by all three analytics endpoints.
fn analytics_absent(request_id: &str) -> Response<AdminBody> {
    envelope(
        404,
        "analytics_not_configured",
        "the gateway is running without an analytics store (configure gateway.analytics \
         and restart)",
        request_id,
    )
}

/// GET /analytics/dashboard (DW-043).
async fn analytics_dashboard(
    ctx: Arc<AdminContext>,
    req: &Request<Incoming>,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let params = query_params(req.uri());
    let (Some(from_ms), Some(to_ms)) = (
        param(&params, "from_ms").and_then(|v| v.parse::<i64>().ok()),
        param(&params, "to_ms").and_then(|v| v.parse::<i64>().ok()),
    ) else {
        return envelope(
            400,
            "analytics_bad_range",
            "from_ms and to_ms are required epoch-millisecond bounds",
            request_id,
        );
    };
    if from_ms >= to_ms {
        return envelope(
            400,
            "analytics_bad_range",
            "from_ms must be < to_ms",
            request_id,
        );
    }
    let gran = param(&params, "gran")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if gran > 3 {
        return envelope(400, "analytics_bad_gran", "gran must be 0..=3", request_id);
    }
    let group_by = param(&params, "group_by");
    if let Some(g) = group_by {
        if !dwara_core::analytics::query::DIM_COLUMNS.contains(&g) {
            return envelope(
                400,
                "analytics_bad_group_by",
                &format!(
                    "group_by must be one of: {}",
                    dwara_core::analytics::query::DIM_COLUMNS.join(", ")
                ),
                request_id,
            );
        }
    }
    let filters = dwara_core::analytics::query::Filters {
        listener: param(&params, "listener").map(str::to_string),
        route: param(&params, "route").map(str::to_string),
        upstream: param(&params, "upstream").map(str::to_string),
        consumer: param(&params, "consumer").map(str::to_string),
        method: param(&params, "method").map(str::to_string),
        status_class: param(&params, "status_class").map(str::to_string),
    };
    match store.query(|c| {
        dwara_core::analytics::query::dashboard(c, from_ms, to_ms, gran, group_by, &filters)
    }) {
        Ok(points) => json_response(
            200,
            serde_json::json!({
                "from_ms": from_ms,
                "to_ms": to_ms,
                "gran": gran,
                "points": points,
            }),
        ),
        Err(e) => envelope(500, "analytics_query_failed", &e.to_string(), request_id),
    }
}

/// GET /analytics/top (DW-043).
async fn analytics_top(
    ctx: Arc<AdminContext>,
    req: &Request<Incoming>,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let params = query_params(req.uri());
    let Some(kind_s) = param(&params, "kind") else {
        return envelope(
            400,
            "analytics_bad_kind",
            "kind is required: consumers|routes|slowest|error_prone|rate_limited",
            request_id,
        );
    };
    let Some(kind) = dwara_core::analytics::query::TopKind::parse(kind_s) else {
        return envelope(
            400,
            "analytics_bad_kind",
            "kind must be one of: consumers|routes|slowest|error_prone|rate_limited",
            request_id,
        );
    };
    let (Some(from_ms), Some(to_ms)) = (
        param(&params, "from_ms").and_then(|v| v.parse::<i64>().ok()),
        param(&params, "to_ms").and_then(|v| v.parse::<i64>().ok()),
    ) else {
        return envelope(
            400,
            "analytics_bad_range",
            "from_ms and to_ms are required epoch-millisecond bounds",
            request_id,
        );
    };
    let n = param(&params, "n")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10)
        .clamp(1, 100);
    match store.query(|c| dwara_core::analytics::query::top(c, kind, from_ms, to_ms, n)) {
        Ok(entries) => json_response(
            200,
            serde_json::json!({
                "kind": kind_s,
                "from_ms": from_ms,
                "to_ms": to_ms,
                "n": n,
                "entries": entries,
            }),
        ),
        Err(e) => envelope(500, "analytics_query_failed", &e.to_string(), request_id),
    }
}

/// POST /analytics/query (DW-043): the structured query endpoint.
async fn analytics_query(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let q: dwara_core::analytics::query::StructuredQuery = match serde_json::from_slice(&body) {
        Ok(q) => q,
        Err(err) => {
            return envelope(
                400,
                "analytics_query_invalid",
                &format!("body is not a valid structured query: {err}"),
                request_id,
            )
        }
    };
    if let Err(err) = q.validate() {
        return envelope(400, "analytics_query_invalid", &err.to_string(), request_id);
    }
    match store.query(|c| dwara_core::analytics::query::structured(c, &q)) {
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "query": { "from_ms": q.from_ms, "to_ms": q.to_ms, "gran": q.gran,
                           "group_by": q.group_by },
                "rows": rows,
            }),
        ),
        Err(e) => envelope(500, "analytics_query_failed", &e.to_string(), request_id),
    }
}

/// POST /analytics/spend (DW-079): the spend query endpoint — a
/// closed JSON grammar over the `ai_spend` table, aggregated per
/// consumer/team/model for billing reconciliation. Never SQL text.
async fn analytics_spend(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let q: dwara_core::analytics::query::SpendQuery = match serde_json::from_slice(&body) {
        Ok(q) => q,
        Err(err) => {
            return envelope(
                400,
                "analytics_spend_invalid",
                &format!("body is not a valid spend query: {err}"),
                request_id,
            )
        }
    };
    if let Err(err) = q.validate() {
        return envelope(400, "analytics_spend_invalid", &err.to_string(), request_id);
    }
    match store.query(|c| dwara_core::analytics::query::spend_summary(c, &q)) {
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "query": { "from_ms": q.from_ms, "to_ms": q.to_ms,
                           "group_by": q.group_by },
                "rows": rows,
            }),
        ),
        Err(e) => envelope(500, "analytics_spend_failed", &e.to_string(), request_id),
    }
}

/// POST /analytics/dimensions (DW-093): the custom-dimension query
/// endpoint — a closed JSON grammar over the `rollup_dim` table,
/// aggregated per (window, dimension name, value). Never SQL text.
async fn analytics_dimensions(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let q: dwara_core::analytics::query::DimensionQuery = match serde_json::from_slice(&body) {
        Ok(q) => q,
        Err(err) => {
            return envelope(
                400,
                "analytics_dimensions_invalid",
                &format!("body is not a valid dimension query: {err}"),
                request_id,
            )
        }
    };
    if let Err(err) = q.validate() {
        return envelope(
            400,
            "analytics_dimensions_invalid",
            &err.to_string(),
            request_id,
        );
    }
    match store.query(|c| dwara_core::analytics::query::dimension_query(c, &q)) {
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "query": { "from_ms": q.from_ms, "to_ms": q.to_ms, "gran": q.gran,
                           "dim": q.dim, "value": q.value },
                "rows": rows,
            }),
        ),
        Err(e) => envelope(
            500,
            "analytics_dimensions_failed",
            &e.to_string(),
            request_id,
        ),
    }
}

/// GET /analytics/journey (DW-093): the journey/funnel query endpoint
/// — returns all raw records matching a correlation id, ordered by
/// time ascending. Query params: correlation_id (required), from_ms,
/// to_ms (optional time range filter).
async fn analytics_journey(
    ctx: Arc<AdminContext>,
    req: &Request<Incoming>,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let params = query_params(req.uri());
    let Some(correlation_id) = param(&params, "correlation_id") else {
        return envelope(
            400,
            "analytics_journey_missing_correlation_id",
            "correlation_id is required",
            request_id,
        );
    };
    if correlation_id.is_empty() {
        return envelope(
            400,
            "analytics_journey_missing_correlation_id",
            "correlation_id must be non-empty",
            request_id,
        );
    }
    let from_ms = param(&params, "from_ms").and_then(|v| v.parse::<i64>().ok());
    let to_ms = param(&params, "to_ms").and_then(|v| v.parse::<i64>().ok());
    match store
        .query(|c| dwara_core::analytics::query::journey_query(c, correlation_id, from_ms, to_ms))
    {
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "correlation_id": correlation_id,
                "from_ms": from_ms,
                "to_ms": to_ms,
                "rows": rows,
            }),
        ),
        Err(e) => envelope(500, "analytics_journey_failed", &e.to_string(), request_id),
    }
}

/// POST /analytics/governance-audit (DW-084): the governance audit
/// endpoint — a time window over the `ai_governance_events` table,
/// returning the raw allow/deny events for shadow review (which
/// consumer/team called which model and whether the governance layer
/// allowed or denied it). Never SQL text.
async fn analytics_governance_audit(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let q: dwara_core::analytics::query::GovernanceAuditQuery = match serde_json::from_slice(&body)
    {
        Ok(q) => q,
        Err(err) => {
            return envelope(
                400,
                "analytics_governance_audit_invalid",
                &format!("body is not a valid governance audit query: {err}"),
                request_id,
            )
        }
    };
    if let Err(err) = q.validate() {
        return envelope(
            400,
            "analytics_governance_audit_invalid",
            &err.to_string(),
            request_id,
        );
    }
    match store.query(|c| dwara_core::analytics::query::governance_audit(c, &q)) {
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "query": { "from_ms": q.from_ms, "to_ms": q.to_ms },
                "rows": rows,
            }),
        ),
        Err(e) => envelope(
            500,
            "analytics_governance_audit_failed",
            &e.to_string(),
            request_id,
        ),
    }
}

/// POST /analytics/prompt-logs (DW-081): the prompt log endpoint — a
/// time window over the `ai_prompt_logs` table, returning the
/// REDACTED prompt and response for each captured AI request.
/// Optionally filtered by consumer. Never SQL text.
async fn analytics_prompt_logs(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let q: dwara_core::analytics::query::PromptLogQuery = match serde_json::from_slice(&body) {
        Ok(q) => q,
        Err(err) => {
            return envelope(
                400,
                "analytics_prompt_logs_invalid",
                &format!("body is not a valid prompt logs query: {err}"),
                request_id,
            )
        }
    };
    if let Err(err) = q.validate() {
        return envelope(
            400,
            "analytics_prompt_logs_invalid",
            &err.to_string(),
            request_id,
        );
    }
    match store.query(|c| dwara_core::analytics::query::prompt_logs(c, &q)) {
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "query": {
                    "from_ms": q.from_ms,
                    "to_ms": q.to_ms,
                    "consumer": q.consumer,
                },
                "rows": rows,
            }),
        ),
        Err(e) => envelope(
            500,
            "analytics_prompt_logs_failed",
            &e.to_string(),
            request_id,
        ),
    }
}

/// GET /analytics/exports (DW-120): the export run ledger, newest
/// first — every scheduled or manual usage-statement export attempt
/// per window (status, partial flag, formats, consumer/request
/// counts). Query param: `limit` (default 25, 1..=100).
async fn analytics_exports_list(
    ctx: Arc<AdminContext>,
    req: &Request<Incoming>,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let params = query_params(req.uri());
    let limit = param(&params, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(25)
        .clamp(1, 100);
    match dwara_core::analytics::exports::list_runs(&store, limit) {
        Ok(runs) => json_response(
            200,
            serde_json::json!({
                "runs": runs,
            }),
        ),
        Err(e) => envelope(500, "analytics_query_failed", &e.to_string(), request_id),
    }
}

/// POST /analytics/exports/run (DW-120): manually trigger one export
/// (the scheduled worker's twin — same engine, same reconciliation
/// contract). Optional JSON body: `{"window": "hourly|daily|monthly",
/// "window_start_ms": <aligned, closed>}`; absent fields default to
/// the configured window kind and its most recent CLOSED window.
/// Requires `analytics.exports` in the config (the directory is where
/// outputs land; an ad hoc directory from a request body would be a
/// write-anywhere footgun).
async fn analytics_exports_run(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    use dwara_core::analytics::exports;
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let Some(exports_cfg) = ctx
        .state
        .snapshot()
        .gateway()
        .analytics
        .as_ref()
        .and_then(|a| a.exports.clone())
    else {
        return envelope(
            400,
            "analytics_exports_not_configured",
            "the gateway config carries no analytics.exports block (set \
             analytics.exports.directory to enable exports)",
            request_id,
        );
    };
    let manual: exports::ManualRunBody = if body.is_empty() {
        exports::ManualRunBody::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(m) => m,
            Err(err) => {
                return envelope(
                    400,
                    "analytics_export_run_invalid",
                    &format!("body is not a valid export run request: {err}"),
                    request_id,
                )
            }
        }
    };
    let window = match manual.window.as_deref() {
        None => exports::effective_window(&exports_cfg),
        Some(s) => match exports::WindowKind::parse(s) {
            Some(w) => w,
            None => {
                return envelope(
                    400,
                    "analytics_export_run_invalid",
                    "window must be one of: hourly|daily|monthly",
                    request_id,
                )
            }
        },
    };
    let now = now_ms() as i64;
    let start = match manual.window_start_ms {
        None => exports::last_closed_window(window, now),
        Some(s) => {
            let (aligned, end) = window.window_of(s);
            if aligned != s {
                return envelope(
                    400,
                    "analytics_export_run_invalid",
                    &format!(
                        "window_start_ms {s} is not aligned to the {} window boundary {aligned}",
                        window.as_str()
                    ),
                    request_id,
                );
            }
            if end > now {
                return envelope(
                    400,
                    "analytics_export_run_invalid",
                    &format!("window starting at {s} is not closed yet (ends {end}; now {now})",),
                    request_id,
                );
            }
            s
        }
    };
    let formats = exports::effective_formats(&exports_cfg);
    let run = exports::run_export(
        &store,
        &exports_cfg.directory,
        window,
        start,
        &formats,
        &|ps, pe| ctx.dp.quota_figures_at(ps, pe),
        now,
    );
    if run.status == "ok" {
        match serde_json::to_value(&run) {
            Ok(v) => json_response(200, v),
            Err(e) => envelope(500, "analytics_export_failed", &e.to_string(), request_id),
        }
    } else {
        envelope(500, "analytics_export_failed", &run.error, request_id)
    }
}

/// GET /quotas/usage (DW-033): the metering read — for every
/// quota-configured consumer (or the one named by the optional
/// `consumer` param), each budget's current-window used/limit and the
/// window bounds (`reset_epoch_s` is the same instant a budget 429's
/// `X-RateLimit-Reset` advertises). Requires the state store
/// (`DWARA_STATE_DB`): without it there are no counters to read (and,
/// as the request path has warned, no enforcement either). A consumer
/// whose store row is missing reports `synced: false` with no budgets
/// — no counters exist for it, and zero-usage would be a lie.
async fn quotas_usage(
    ctx: Arc<AdminContext>,
    req: &Request<Incoming>,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return envelope(
            404,
            "state_store_not_configured",
            "the gateway is running without a state store (set DWARA_STATE_DB and \
             restart); quota usage is not queryable",
            request_id,
        );
    };
    let snapshot = ctx.state.snapshot();
    let gateway = snapshot.gateway();
    let params = query_params(req.uri());
    let filter = param(&params, "consumer");
    if let Some(name) = &filter {
        let quotaed = gateway
            .consumers
            .iter()
            .any(|c| &c.name == name && c.quotas.is_some());
        if !quotaed {
            return envelope(
                400,
                "quota_bad_consumer",
                "consumer must name a consumer that declares a quotas block",
                request_id,
            );
        }
    }
    let now_epoch_s = (now_ms() / 1000) as i64;
    let mut consumers = Vec::new();
    for c in &gateway.consumers {
        let Some(quotas) = &c.quotas else {
            continue;
        };
        if let Some(f) = &filter {
            if f != &c.name {
                continue;
            }
        }
        let record = store.lookup_consumer(&c.name).ok().flatten();
        let budgets = match &record {
            Some(rec) => {
                dwara_core::state::quotas::current_usage(&store, rec.id, quotas, now_epoch_s)
                    .iter()
                    .map(|u| {
                        serde_json::json!({
                            "budget": u.budget.as_str(),
                            "limit": u.limit,
                            "used": u.used,
                            "remaining": u.remaining,
                            "window_start_epoch_s": u.window_start_epoch_s,
                            "reset_epoch_s": u.reset_epoch_s,
                        })
                    })
                    .collect::<Vec<_>>()
            }
            None => Vec::new(),
        };
        consumers.push(serde_json::json!({
            "consumer": c.name,
            "synced": record.is_some(),
            "budgets": budgets,
        }));
    }
    json_response(
        200,
        serde_json::json!({
            "now_epoch_s": now_epoch_s,
            "consumers": consumers,
        }),
    )
}

// -----------------------------------------------------------------
// DW-086: Prompt experimentation admin endpoints.
// -----------------------------------------------------------------

/// GET /experiments/prompt-overrides (DW-086): list all runtime
/// prompt-version overrides (prompt_name, version).
async fn experiments_prompt_overrides_list(
    ctx: Arc<AdminContext>,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return envelope(
            503,
            "state_store_not_configured",
            "a state store is required for prompt overrides",
            request_id,
        );
    };
    match store.list_prompt_overrides() {
        Ok(overrides) => json_response(
            200,
            serde_json::json!({
                "overrides": overrides.iter().map(|(name, version)| {
                    serde_json::json!({
                        "prompt_name": name,
                        "version": version,
                    })
                }).collect::<Vec<_>>(),
            }),
        ),
        Err(e) => envelope(
            500,
            "prompt_overrides_list_failed",
            &e.to_string(),
            request_id,
        ),
    }
}

/// PUT /experiments/prompt-overrides (DW-086): set or replace a
/// prompt-version override. Body: `{"prompt_name": "...", "version":
/// "..."}`. The caller validates that the prompt name and version
/// exist in the current config before calling.
async fn experiments_prompt_overrides_set(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return envelope(
            503,
            "state_store_not_configured",
            "a state store is required for prompt overrides",
            request_id,
        );
    };
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return envelope(
                400,
                "prompt_override_invalid",
                &format!("body is not valid JSON: {e}"),
                request_id,
            )
        }
    };
    let prompt_name = match req.get("prompt_name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => {
            return envelope(
                400,
                "prompt_override_invalid",
                "missing required field 'prompt_name'",
                request_id,
            )
        }
    };
    let version = match req.get("version").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => {
            return envelope(
                400,
                "prompt_override_invalid",
                "missing required field 'version'",
                request_id,
            )
        }
    };
    // Validate against the current config.
    let snapshot = ctx.state.snapshot();
    let gateway = snapshot.gateway();
    if let Some(ai) = &gateway.ai {
        if let Some(experiments) = &ai.experiments {
            if let Some(prompt) = experiments.prompts.get(&prompt_name) {
                if !prompt.versions.contains_key(&version) {
                    return envelope(
                        400,
                        "prompt_override_invalid",
                        &format!(
                            "version '{}' does not exist for prompt '{}'",
                            version, prompt_name
                        ),
                        request_id,
                    );
                }
            } else {
                return envelope(
                    400,
                    "prompt_override_invalid",
                    &format!("prompt '{}' does not exist in config", prompt_name),
                    request_id,
                );
            }
        } else {
            return envelope(
                400,
                "prompt_override_invalid",
                "ai.experiments is not configured",
                request_id,
            );
        }
    } else {
        return envelope(
            400,
            "prompt_override_invalid",
            "ai block is not configured",
            request_id,
        );
    }
    match store.set_prompt_override(&prompt_name, &version) {
        Ok(()) => json_response(
            200,
            serde_json::json!({
                "prompt_name": prompt_name,
                "version": version,
                "status": "set",
            }),
        ),
        Err(e) => envelope(
            500,
            "prompt_override_set_failed",
            &e.to_string(),
            request_id,
        ),
    }
}

/// DELETE /experiments/prompt-overrides (DW-086): clear a
/// prompt-version override (revert to config-declared active
/// version). Body: `{"prompt_name": "..."}`.
async fn experiments_prompt_overrides_clear(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return envelope(
            503,
            "state_store_not_configured",
            "a state store is required for prompt overrides",
            request_id,
        );
    };
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return envelope(
                400,
                "prompt_override_invalid",
                &format!("body is not valid JSON: {e}"),
                request_id,
            )
        }
    };
    let prompt_name = match req.get("prompt_name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => {
            return envelope(
                400,
                "prompt_override_invalid",
                "missing required field 'prompt_name'",
                request_id,
            )
        }
    };
    match store.clear_prompt_override(&prompt_name) {
        Ok(()) => json_response(
            200,
            serde_json::json!({
                "prompt_name": prompt_name,
                "status": "cleared",
            }),
        ),
        Err(e) => envelope(
            500,
            "prompt_override_clear_failed",
            &e.to_string(),
            request_id,
        ),
    }
}

/// POST /experiments/feedback (DW-086): ingest one feedback record.
/// Body: `{"request_id": "...", "label": "...", "comment": "...",
/// "consumer": "...", "model": "..."}`.
async fn experiments_feedback_ingest(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(analytics) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return envelope(
                400,
                "feedback_invalid",
                &format!("body is not valid JSON: {e}"),
                request_id,
            )
        }
    };
    let rec = dwara_core::analytics::AiFeedbackRecord {
        ts_ms: now_ms() as i64,
        request_id: req
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        label: req
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        comment: req
            .get("comment")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        consumer: req
            .get("consumer")
            .and_then(|v| v.as_str())
            .unwrap_or("anonymous")
            .to_string(),
        model: req
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    };
    if rec.request_id.is_empty() || rec.label.is_empty() {
        return envelope(
            400,
            "feedback_invalid",
            "fields 'request_id' and 'label' are required and must be non-empty",
            request_id,
        );
    }
    analytics.offer_ai_feedback(rec);
    json_response(200, serde_json::json!({"status": "accepted"}))
}

/// POST /experiments/verdict (DW-086): compute the verdict for an
/// A/B test from stored eval results. Body: `{"experiment": "..."}`.
/// Reads eval results from the analytics store and computes the
/// winner (highest pass rate, lowest latency tiebreaker).
async fn experiments_verdict(
    ctx: Arc<AdminContext>,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(analytics) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return envelope(
                400,
                "verdict_invalid",
                &format!("body is not valid JSON: {e}"),
                request_id,
            )
        }
    };
    let experiment_name = match req.get("experiment").and_then(|v| v.as_str()) {
        Some(e) => e.to_string(),
        None => {
            return envelope(
                400,
                "verdict_invalid",
                "missing required field 'experiment'",
                request_id,
            )
        }
    };
    // Read eval results from the analytics store for this experiment.
    let results = match analytics.query(|c| {
        let mut stmt = c.prepare(
            "SELECT variant, case_index, input, expected, actual, \
             passed, scorer, latency_ms \
             FROM ai_eval_results WHERE eval_name = ?1 ORDER BY variant, case_index",
        )?;
        // Collect raw rows first.
        struct RawRow {
            variant: String,
            case_index: usize,
            input: String,
            expected: String,
            actual: String,
            passed: bool,
            scorer: String,
            latency_ms: f64,
        }
        let rows = stmt.query_map([&experiment_name], |r| {
            Ok(RawRow {
                variant: r.get::<_, String>(0)?,
                case_index: r.get::<_, i64>(1)? as usize,
                input: r.get::<_, String>(2)?,
                expected: r.get::<_, String>(3)?,
                actual: r.get::<_, String>(4)?,
                passed: r.get::<_, i64>(5)? != 0,
                scorer: r.get::<_, String>(6)?,
                latency_ms: r.get::<_, f64>(7)?,
            })
        })?;
        // Group cases by variant.
        let mut by_variant: std::collections::BTreeMap<
            String,
            Vec<dwara_core::ai::experiments::EvalCaseResult>,
        > = std::collections::BTreeMap::new();
        for row in rows {
            let r = row?;
            by_variant.entry(r.variant.clone()).or_default().push(
                dwara_core::ai::experiments::EvalCaseResult {
                    case_index: r.case_index,
                    input: r.input,
                    expected: r.expected,
                    actual: r.actual,
                    passed: r.passed,
                    scorer: dwara_core::ai::experiments::EvalScorer::parse(Some(r.scorer.as_str())),
                    latency_ms: r.latency_ms,
                },
            );
        }
        let results: Vec<dwara_core::ai::experiments::EvalRunResult> = by_variant
            .into_iter()
            .map(
                |(variant, cases)| dwara_core::ai::experiments::EvalRunResult {
                    eval_name: experiment_name.clone(),
                    model: String::new(),
                    variant,
                    prompt_version: String::new(),
                    cases,
                },
            )
            .collect();
        Ok(results)
    }) {
        Ok(results) => results,
        Err(e) => return envelope(500, "verdict_query_failed", &e.to_string(), request_id),
    };
    if results.is_empty() {
        return envelope(
            404,
            "verdict_no_results",
            &format!("no eval results found for experiment '{}'", experiment_name),
            request_id,
        );
    }
    let verdict = dwara_core::ai::experiments::compute_verdict(&experiment_name, &results);
    json_response(
        200,
        serde_json::json!({
            "experiment": verdict.experiment,
            "winner": verdict.winner,
            "pass_rates": verdict.pass_rates.iter().map(|(v, r)| {
                serde_json::json!({"variant": v, "pass_rate": r})
            }).collect::<Vec<_>>(),
            "avg_latencies": verdict.avg_latencies.iter().map(|(v, l)| {
                serde_json::json!({"variant": v, "avg_latency_ms": l})
            }).collect::<Vec<_>>(),
        }),
    )
}

/// Validate + compile a candidate gateway as a dry run; Err carries a
/// message listing EVERY problem (validation reports all issues at
/// once, never fail-fast).
fn dry_run(gateway: &Gateway) -> Result<(), String> {
    compile(gateway).map(|_| ()).map_err(|e| e.to_string())
}

/// PATCH /config: full-YAML replacement. Dry-run first (400 with all
/// issues on failure), then atomic file write, then publish + dataplane
/// refresh. Serialized by the context's patch lock so two concurrent
/// PATCHes cannot interleave file writes. Known v1 behavior: SIGHUP
/// reloads are NOT serialized with this lock — a SIGHUP racing a PATCH
/// can transiently flip the published generation, but the file watcher's
/// rename event re-publishes the PATCHed document and the gateway
/// self-heals to the patched generation.
async fn patch_config(ctx: &AdminContext, body: Bytes, request_id: &str) -> Response<AdminBody> {
    if body.len() > MAX_PATCH_BODY {
        return envelope(
            413,
            "config_too_large",
            &format!("config body exceeds {} bytes", MAX_PATCH_BODY),
            request_id,
        );
    }
    let text = match std::str::from_utf8(&body) {
        Ok(t) => t,
        Err(_) => {
            return envelope(
                400,
                "config_invalid",
                "config body is not valid UTF-8",
                request_id,
            )
        }
    };
    let gateway = match parse_gateway(text) {
        Ok(g) => g,
        Err(err) => {
            return envelope(
                400,
                "config_invalid",
                &format!("parse failed: {err}"),
                request_id,
            )
        }
    };
    if let Err(message) = dry_run(&gateway) {
        return envelope(400, "config_invalid", &message, request_id);
    }
    let normalized = match gateway_to_yaml(&gateway) {
        Ok(y) => y,
        Err(err) => return envelope(500, "config_serialize_failed", &err.to_string(), request_id),
    };

    let _guard = ctx.patch_lock.lock().await;
    if let Err(err) = write_atomic(&ctx.config_path, &normalized) {
        return envelope(
            500,
            "config_write_failed",
            &format!("failed to write {}: {err}", ctx.config_path.display()),
            request_id,
        );
    }
    match ctx.state.compile_and_publish(&gateway) {
        Ok(info) => {
            ctx.dp.refresh();
            tracing::info!(
                code = "admin_config_published",
                generation = info.generation,
                routes = info.route_count,
                "admin PATCH published config generation {}",
                info.generation
            );
            generation_headers(
                json_response(
                    200,
                    serde_json::json!({
                        "generation": info.generation,
                        "content_hash": format!("{:#x}", info.content_hash),
                        "routes": info.route_count,
                    }),
                ),
                info.generation,
                info.content_hash,
            )
        }
        Err(err) => envelope(
            500,
            "config_publish_failed",
            &format!("validated config failed to publish: {err}"),
            request_id,
        ),
    }
}

/// Dispatch one admin request. Errors use the dataplane's error
/// envelope style (code/message/request_id) so operators can grep one
/// shape across both surfaces.
async fn handle(ctx: Arc<AdminContext>, req: Request<Incoming>) -> Response<AdminBody> {
    let request_id = resolve_request_id(req.headers());
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Same framing-ambiguity rejection as the dataplane (DW-023): a
    // request carrying both Content-Length and Transfer-Encoding is the
    // smuggling primitive; the admin surface applies the identical policy.
    // UNREACHABLE BY DESIGN — belt-and-suspenders insurance (same
    // reasoning as the dataplane's in-handler check): the pre-parse
    // sniff in `serve_conn` below rejects the pair on the connection's
    // first head, hyper's parser refuses it on later keep-alive heads,
    // and TE-preference normalization strips the Content-Length before
    // this handler runs. Kept so a future parser change fails CLOSED
    // here instead of re-admitting the smuggling primitive.
    if req.headers().contains_key(hyper::header::CONTENT_LENGTH)
        && req.headers().contains_key(hyper::header::TRANSFER_ENCODING)
    {
        return envelope(
            400,
            "ambiguous_framing",
            "request declares both Content-Length and Transfer-Encoding",
            &request_id,
        );
    }
    match (method.as_str(), path.as_str()) {
        // GET /config (the config-dump surface, DW-045): the TYPED-redacted
        // copy of the published gateway — inline api-key values become
        // unresolvable ${redacted:...} placeholders, references echo as
        // references. Redaction is structural (a schema transform, not a
        // string scrub), so it cannot miss a field the schema knows about.
        ("GET", "/config") => {
            let snapshot = ctx.state.snapshot();
            let body = gateway_to_yaml(&snapshot.gateway().redacted()).unwrap_or_default();
            generation_headers(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/yaml")
                    .body(Full::new(Bytes::from(body)))
                    .expect("static response parts"),
                snapshot.generation(),
                snapshot.content_hash(),
            )
        }
        ("PATCH", "/config") => {
            // The size cap is enforced DURING collection, not after: a
            // cert-holding client streaming an unbounded body is cut off
            // at MAX_PATCH_BODY and never buffered whole in memory.
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "config_too_large",
                            &format!("config body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            patch_config(&ctx, body, &request_id).await
        }
        ("GET", "/health") => json_response(200, health_body(&ctx)),
        // GET /stats (DW-021): default JSON shape. The `format=prometheus`
        // query param (DW-072) returns the full Prometheus text-format
        // dump instead — the same output as the /metrics endpoint but
        // reachable through the admin surface for Envoy-style tooling.
        ("GET", "/stats") => {
            let format = req
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("format=")))
                .unwrap_or("");
            if format == "prometheus" {
                stats_prometheus(&ctx)
            } else {
                json_response(200, stats_body(&ctx))
            }
        }
        // GET /clusters (DW-072): Envoy-style cluster dump — per upstream:
        // algorithm, scheme, connection/request counters, breaker state,
        // and per-endpoint health + inflight counts.
        ("GET", "/clusters") => json_response(200, clusters_body(&ctx)),
        // GET /config_dump (DW-072): the full published gateway config as
        // redacted JSON with generation/hash headers (Envoy-style
        // structured dump; the existing GET /config returns YAML).
        ("GET", "/config_dump") => {
            let snapshot = ctx.state.snapshot();
            generation_headers(
                json_response(200, config_dump_body(&ctx)),
                snapshot.generation(),
                snapshot.content_hash(),
            )
        }
        // GET /runtime_info (DW-072): process-level runtime information —
        // version, uptime, config generation, and readiness.
        ("GET", "/runtime_info") => json_response(200, runtime_info_body(&ctx)),
        // POST /cache/purge (DW-037): O(1) epoch-advance invalidation;
        // see `purge_cache` for the body shape and the response that
        // names what was purged.
        ("POST", "/cache/purge") => {
            let limited = Limited::new(req.into_body(), MAX_PURGE_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "cache_purge_too_large",
                            &format!("purge body exceeds {} bytes", MAX_PURGE_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            purge_cache(&ctx, body, &request_id).await
        }
        // GET /analytics/dashboard (DW-043): per-window series (requests,
        // error rate, latency percentiles) with optional drill-down
        // (`group_by`) and filters. Query params: from_ms, to_ms, gran
        // (0..=3), group_by, and any of listener/route/upstream/
        // consumer/method/status_class as equality filters.
        ("GET", "/analytics/dashboard") => analytics_dashboard(ctx, &req, &request_id).await,
        // GET /analytics/top (DW-043): Top-N reports. Query params: kind
        // (consumers|routes|slowest|error_prone|rate_limited), from_ms,
        // to_ms, n.
        ("GET", "/analytics/top") => analytics_top(ctx, &req, &request_id).await,
        // GET /quotas/usage (DW-033): per-consumer request-budget
        // metering — current-window used/limit per budget. Query params:
        // optional consumer (name filter).
        ("GET", "/quotas/usage") => quotas_usage(ctx, &req, &request_id).await,
        // Credential lifecycle (DW-046 key rotation): list a consumer's
        // credential rows (ids and lifecycle stamps only — never
        // selector/hash material), issue a NEW api key alongside the
        // existing ones (the dual-validity window opens here), and
        // schedule-or-execute a credential's retirement.
        (m, p) if p.starts_with("/consumers/") && p.ends_with("/credentials") => {
            let name = percent_decode(
                p.trim_start_matches("/consumers/")
                    .strip_suffix("/credentials")
                    .unwrap_or(""),
            );
            match m {
                "GET" => credentials_list(ctx, &name, &request_id).await,
                "POST" => {
                    let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
                    let body = match limited.collect().await {
                        Ok(c) => c.to_bytes(),
                        Err(err) => {
                            return envelope(400, "body_read_failed", &err.to_string(), &request_id)
                        }
                    };
                    credentials_issue(ctx, &name, body, &request_id).await
                }
                _ => envelope(405, "method_not_allowed", "GET or POST here", &request_id),
            }
        }
        (m, p) if m == "POST" && p.starts_with("/credentials/") && p.ends_with("/retire") => {
            let id = p
                .trim_start_matches("/credentials/")
                .strip_suffix("/retire")
                .unwrap_or("")
                .parse::<i64>()
                .ok();
            match id {
                None => envelope(
                    400,
                    "bad_credential_id",
                    "credential id must be an integer",
                    &request_id,
                ),
                Some(id) => {
                    let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
                    let body = match limited.collect().await {
                        Ok(c) => c.to_bytes(),
                        Err(err) => {
                            return envelope(400, "body_read_failed", &err.to_string(), &request_id)
                        }
                    };
                    credentials_retire(ctx, id, body, &request_id).await
                }
            }
        }
        // POST /analytics/query (DW-043): the structured query — a
        // closed JSON grammar translated to SQL (never SQL text).
        ("POST", "/analytics/query") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "query_too_large",
                            &format!("query body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            analytics_query(ctx, body, &request_id).await
        }
        // POST /analytics/spend (DW-079): the spend query — a closed
        // JSON grammar over the ai_spend table, aggregated per
        // consumer/team/model for billing reconciliation.
        ("POST", "/analytics/spend") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "query_too_large",
                            &format!("query body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            analytics_spend(ctx, body, &request_id).await
        }
        // POST /analytics/dimensions (DW-093): the custom-dimension
        // query — a closed JSON grammar over the rollup_dim table,
        // aggregated per (window, dimension name, value).
        ("POST", "/analytics/dimensions") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "query_too_large",
                            &format!("query body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            analytics_dimensions(ctx, body, &request_id).await
        }
        // GET /analytics/journey (DW-093): the journey/funnel query —
        // returns all raw records matching a correlation id, ordered
        // by time ascending. Query params: correlation_id (required),
        // from_ms, to_ms (optional).
        ("GET", "/analytics/journey") => analytics_journey(ctx, &req, &request_id).await,
        // POST /analytics/governance-audit (DW-084): the governance
        // audit query — a time window over the ai_governance_events
        // table, returning raw allow/deny events for shadow review.
        ("POST", "/analytics/governance-audit") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "query_too_large",
                            &format!("query body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            analytics_governance_audit(ctx, body, &request_id).await
        }
        // POST /analytics/prompt-logs (DW-081): the prompt log query
        // — a time window over the ai_prompt_logs table, returning
        // the REDACTED prompt and response for each captured AI
        // request. Optionally filtered by consumer.
        ("POST", "/analytics/prompt-logs") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "query_too_large",
                            &format!("query body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            analytics_prompt_logs(ctx, body, &request_id).await
        }
        // GET /analytics/exports (DW-120): the export run ledger,
        // newest first. Query param: limit (default 25, 1..=100).
        ("GET", "/analytics/exports") => analytics_exports_list(ctx, &req, &request_id).await,
        // POST /analytics/exports/run (DW-120): manual trigger of one
        // window's export (scheduled worker's twin). Optional JSON
        // body: {window?, window_start_ms?}.
        ("POST", "/analytics/exports/run") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "query_too_large",
                            &format!("body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            analytics_exports_run(ctx, body, &request_id).await
        }
        // DW-086: Prompt experimentation endpoints.
        // GET /experiments/prompt-overrides — list all runtime
        // prompt-version overrides.
        ("GET", "/experiments/prompt-overrides") => {
            experiments_prompt_overrides_list(ctx, &request_id).await
        }
        // PUT /experiments/prompt-overrides — set or replace a
        // prompt-version override.
        ("PUT", "/experiments/prompt-overrides") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "body_too_large",
                            &format!("body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            experiments_prompt_overrides_set(ctx, body, &request_id).await
        }
        // DELETE /experiments/prompt-overrides — clear a
        // prompt-version override.
        ("DELETE", "/experiments/prompt-overrides") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "body_too_large",
                            &format!("body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            experiments_prompt_overrides_clear(ctx, body, &request_id).await
        }
        // POST /experiments/feedback — ingest one feedback record.
        ("POST", "/experiments/feedback") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "body_too_large",
                            &format!("body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            experiments_feedback_ingest(ctx, body, &request_id).await
        }
        // POST /experiments/verdict — compute the verdict for an
        // A/B test from stored eval results.
        ("POST", "/experiments/verdict") => {
            let limited = Limited::new(req.into_body(), MAX_PATCH_BODY);
            let body = match limited.collect().await {
                Ok(c) => c.to_bytes(),
                Err(err) => {
                    if err.downcast_ref::<LengthLimitError>().is_some() {
                        return envelope(
                            413,
                            "body_too_large",
                            &format!("body exceeds {} bytes", MAX_PATCH_BODY),
                            &request_id,
                        );
                    }
                    return envelope(400, "body_read_failed", &err.to_string(), &request_id);
                }
            };
            experiments_verdict(ctx, body, &request_id).await
        }
        // DW-087: MCP gateway admin endpoints.
        // GET /mcp/sessions -- list active MCP sessions from the state
        // store.
        ("GET", "/mcp/sessions") => mcp_sessions_list(ctx, &request_id).await,
        // DELETE /mcp/sessions/:id -- teardown an MCP session.
        (m, p) if m == "DELETE" && p.starts_with("/mcp/sessions/") => {
            let id = percent_decode(p.trim_start_matches("/mcp/sessions/"));
            mcp_session_delete(ctx, &id, &request_id).await
        }
        // GET /mcp/tools -- list configured MCP tools from the current
        // snapshot's AiRuntime.
        ("GET", "/mcp/tools") => mcp_tools_list(ctx, &request_id).await,
        // GET /mcp/calls -- query MCP tool call analytics. Query params:
        // from_ms, to_ms, session_id, consumer, tool_name, limit.
        ("GET", "/mcp/calls") => mcp_calls_query(ctx, &req, &request_id).await,
        // A known resource path with the wrong method.
        (
            _,
            "/config"
            | "/health"
            | "/stats"
            | "/clusters"
            | "/config_dump"
            | "/runtime_info"
            | "/cache/purge"
            | "/analytics/dashboard"
            | "/analytics/top"
            | "/analytics/query"
            | "/analytics/spend"
            | "/analytics/dimensions"
            | "/analytics/journey"
            | "/analytics/governance-audit"
            | "/analytics/exports"
            | "/analytics/exports/run"
            | "/experiments/prompt-overrides"
            | "/experiments/feedback"
            | "/experiments/verdict"
            | "/mcp/sessions"
            | "/mcp/tools"
            | "/mcp/calls"
            | "/quotas/usage",
        ) => envelope(
            405,
            "method_not_allowed",
            &format!("{method} not allowed here"),
            &request_id,
        ),
        _ => envelope(
            404,
            "not_found",
            &format!("unknown admin path '{path}'"),
            &request_id,
        ),
    }
}

/// #130 panic policy for the admin accept loop, mirroring the gateway
/// listeners' #120 budget: how many times a panicked accept incarnation
/// is respawned before the admin listener is given up on. Total for the
/// process lifetime (a simple bounded budget; a crash-looping accept
/// loop stops after this many respawns instead of spinning forever).
const MAX_ADMIN_RESPAWNS: u32 = 8;

/// Serve the admin API on an already-bound listener until `shutdown`
/// fires, then drain gracefully (in-flight requests complete; anything
/// still draining when the process exits is closed by process exit).
///
/// The accept loop runs under panic supervision (#130) with the same
/// semantics as the gateway listeners (#120): a panicked incarnation is
/// respawned on the SAME bound socket up to MAX_ADMIN_RESPAWNS times,
/// then the admin listener is given up on with a loud ERROR log
/// (the gateway's data plane keeps serving; the process stays up).
pub async fn serve(
    ctx: Arc<AdminContext>,
    listener: TcpListener,
    mode: ListenMode,
    shutdown: watch::Receiver<()>,
) -> std::io::Result<()> {
    let label = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "admin".to_string());
    let listener = Arc::new(listener);
    supervise_admin_accept(&label, move || {
        tokio::spawn(accept_incarnation(
            Arc::clone(&ctx),
            Arc::clone(&listener),
            mode.clone(),
            shutdown.clone(),
        ))
    })
    .await;
    Ok(())
}

/// Bind the supervision of the admin accept task (#130): every respawn
/// reuses the same bound socket (shared `Arc`) and clones of the serve
/// plumbing, so a panicked accept loop cannot kill the admin listener
/// silently for the rest of the process lifetime. The supervisor is
/// dwara-core's shared [`dwara_core::supervision::supervise_panics`];
/// only the admin budget and wiring live here.
///
/// Pin: never poll a `shutdown` receiver held OUTSIDE the spawn
/// closure (changed()/borrow_and_update) — each clone inside the
/// closure inherits its seen version, and only the never-updated
/// initial version makes a respawned incarnation's changed() fire
/// immediately for an already-sent shutdown (the same pin as the
/// listener supervisor in dwara-bin).
async fn supervise_admin_accept<F>(label: &str, spawn: F)
where
    F: FnMut() -> tokio::task::JoinHandle<()>,
{
    dwara_core::supervision::supervise_panics("admin", label, MAX_ADMIN_RESPAWNS, spawn).await;
}

/// One incarnation of the admin accept loop: serve until `shutdown`
/// fires, then drain gracefully. Panicking here (a bug in the loop
/// body) hands control back to the supervisor, which respawns on the
/// same socket.
async fn accept_incarnation(
    ctx: Arc<AdminContext>,
    listener: Arc<TcpListener>,
    mode: ListenMode,
    mut shutdown: watch::Receiver<()>,
) {
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    // Same protocol-hardening posture as the data plane (DW-023): the
    // admin surface parses the same untrusted wire bytes, so the parser
    // bounds and slowloris timeout apply here too. Read once per
    // incarnation (a respawned incarnation picks up fresh bounds).
    let hardening = std::sync::Arc::new(dwara_core::hardening::HttpHardening::from_env());
    let tls_config: Option<Arc<rustls::ServerConfig>> = match mode {
        ListenMode::Mtls(config) => Some(Arc::new(*config)),
        ListenMode::DevPlaintext => None,
    };
    loop {
        let (stream, _peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(code = "admin_accept_error", "admin accept error: {err}");
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        let watcher = graceful.watcher();
        let ctx = Arc::clone(&ctx);
        let hardening = Arc::clone(&hardening);
        match &tls_config {
            Some(config) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(config));
                tokio::spawn(async move {
                    // A failed handshake here is the mTLS gate doing its
                    // job (no client cert, or a cert from the wrong CA).
                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                        serve_conn(watcher, ctx, tls_stream, Arc::clone(&hardening)).await;
                    }
                });
            }
            None => {
                tokio::spawn(serve_conn(watcher, ctx, stream, hardening));
            }
        }
    }
    // Drain: in-flight admin requests complete; anything still open when
    // the process exits is closed by process exit (the binary's overall
    // shutdown budget governs). The socket itself closes when the last
    // Arc reference drops — the supervisor's, immediately after this
    // clean return ends supervision.
    let drain = graceful.shutdown();
    drain.await;
    tracing::info!(code = "admin_drained", "admin listener drained");
}

async fn serve_conn<S>(
    watcher: hyper_util::server::graceful::Watcher,
    ctx: Arc<AdminContext>,
    stream: S,
    hardening: std::sync::Arc<dwara_core::hardening::HttpHardening>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut auto =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    hardening.apply(&mut auto);
    // Pre-parse smuggling guard (DW-023), same policy as the dataplane: a
    // first request head with both Content-Length and Transfer-Encoding
    // is answered 400 and closed before the parser ever sees it.
    let Some(stream) = hardening.guard_connection(stream).await else {
        return;
    };
    let conn = watcher.watch(auto.serve_connection(
        hyper_util::rt::TokioIo::new(stream),
        hyper::service::service_fn(move |req| {
            let ctx = Arc::clone(&ctx);
            async move { Ok::<_, std::convert::Infallible>(handle(ctx, req).await) }
        }),
    ));
    if let Err(err) = conn.await {
        tracing::warn!(code = "admin_conn_error", "admin connection error: {err}");
    }
}

// --- Credential lifecycle: key rotation (DW-046) --------------------------

/// Epoch seconds (the credential lifecycle stamps' time domain).
fn now_secs() -> i64 {
    now_ms() as i64 / 1000
}

/// The store-absent answer shared by the credential endpoints.
fn store_absent(request_id: &str) -> Response<AdminBody> {
    envelope(
        404,
        "state_store_not_configured",
        "credential management requires a DWARA_STATE_DB deployment (config-only \
         credentials rotate by editing the config and reloading)",
        request_id,
    )
}

/// GET /consumers/{name}/credentials: the rotation runbook's view —
/// one row per credential with id, kind, and lifecycle stamps. The
/// selector (a key id) and hash are credential material and never
/// leave the store module.
async fn credentials_list(
    ctx: Arc<AdminContext>,
    consumer: &str,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return store_absent(request_id);
    };
    match store.list_credentials_for_consumer(consumer) {
        Ok(rows) if rows.is_empty() => {
            if store.lookup_consumer(consumer).ok().flatten().is_none() {
                envelope(
                    404,
                    "unknown_consumer",
                    &format!("no consumer '{consumer}'"),
                    request_id,
                )
            } else {
                json_response(
                    200,
                    serde_json::json!({ "consumer": consumer, "credentials": [] }),
                )
            }
        }
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "consumer": consumer,
                "credentials": rows.iter().map(|r| serde_json::json!({
                    "id": r.id,
                    "kind": r.kind.as_str(),
                    "created_at": r.created_at,
                    "revoked_at": r.revoked_at,
                    "retire_at": r.retire_at,
                })).collect::<Vec<_>>(),
            }),
        ),
        Err(e) => envelope(500, "credentials_list_failed", &e.to_string(), request_id),
    }
}

/// POST /consumers/{name}/credentials: issue a NEW api key. Body:
/// `{"key": "<the new secret>"}` (REQUIRED — the gateway returns
/// nothing derived from it beyond the row id; the operator already
/// holds the secret). The hash is computed with the dataplane's OWN
/// pepper state (the same format the config seed path and the
/// authenticator use), so the key authenticates from the next request.
/// The OLD credentials keep working until retired: this call OPENS
/// the dual-validity window.
async fn credentials_issue(
    ctx: Arc<AdminContext>,
    consumer: &str,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return store_absent(request_id);
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return envelope(
                400,
                "credential_issue_invalid",
                &format!("body is not valid JSON: {err}"),
                request_id,
            )
        }
    };
    let Some(key) = parsed.get("key").and_then(|v| v.as_str()) else {
        return envelope(
            400,
            "credential_issue_invalid",
            "body must carry {\"key\": \"<new secret>\"}",
            request_id,
        );
    };
    if key.len() < 16 || key.len() > 512 {
        return envelope(
            400,
            "credential_issue_invalid",
            "key length must be 16..=512 bytes (rotation is not the moment for a \
             weak secret)",
            request_id,
        );
    }
    let Some(record) = store.lookup_consumer(consumer).ok().flatten() else {
        return envelope(
            404,
            "unknown_consumer",
            &format!("no consumer '{consumer}' in the state store"),
            request_id,
        );
    };
    let selector = dwara_core::config::credentials::credential_selector(key);
    let hash = ctx.dp.hash_new_credential(key);
    match store.add_credential(
        record.id,
        dwara_core::state::store::CredentialKind::ApiKey,
        hash,
        None,
        selector,
    ) {
        Ok(row) => {
            tracing::info!(
                code = "credential_issued",
                consumer = consumer,
                credential_id = row.id,
                "api key issued (dual-validity window open; retire the old key \
                 when clients have switched)"
            );
            json_response(
                201,
                serde_json::json!({
                    "consumer": consumer,
                    "credential_id": row.id,
                    "created_at": row.created_at,
                    "note": "the new key authenticates immediately; existing \
                             keys keep working until retired",
                }),
            )
        }
        Err(e) => envelope(500, "credential_issue_failed", &e.to_string(), request_id),
    }
}

/// POST /credentials/{id}/retire: schedule (or, with no `at_ms`, execute
/// immediately) a credential's retirement — the dual-validity window's
/// far edge. Body: `{"at_ms": <epoch ms>}` optional; absent/now/past =
/// effective immediately.
async fn credentials_retire(
    ctx: Arc<AdminContext>,
    credential_id: i64,
    body: Bytes,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return store_absent(request_id);
    };
    let at_ms: Option<i64> = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(v) => v.get("at_ms").and_then(|m| m.as_i64()),
            Err(_) => {
                return envelope(
                    400,
                    "credential_retire_invalid",
                    "body must be empty or {\"at_ms\": <epoch ms>}",
                    request_id,
                )
            }
        }
    };
    let at_secs = at_ms.map(|ms| ms.div_euclid(1000));
    match store.retire_credential(credential_id, at_secs.unwrap_or_else(now_secs)) {
        Ok(true) => {
            tracing::info!(
                code = "credential_retired",
                credential_id = credential_id,
                at = at_secs.unwrap_or_else(now_secs),
                "credential retirement scheduled"
            );
            json_response(
                200,
                serde_json::json!({
                    "credential_id": credential_id,
                    "retire_at": at_secs.unwrap_or_else(now_secs),
                    "effective": if at_secs.is_some_and(|t| t > now_secs()) { "scheduled" } else { "immediate" },
                }),
            )
        }
        Ok(false) => envelope(
            404,
            "credential_not_active",
            &format!(
                "no active credential {credential_id} (unknown, already \
                      revoked, or already retiring earlier)"
            ),
            request_id,
        ),
        Err(e) => envelope(500, "credential_retire_failed", &e.to_string(), request_id),
    }
}

// --- DW-087: MCP gateway admin endpoints ---

/// GET /mcp/sessions (DW-087): list active (non-expired) MCP sessions
/// from the state store, ordered by creation time descending.
async fn mcp_sessions_list(ctx: Arc<AdminContext>, request_id: &str) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return envelope(
            503,
            "state_store_not_configured",
            "a state store is required for MCP session management",
            request_id,
        );
    };
    match store.list_active_mcp_sessions() {
        Ok(sessions) => json_response(
            200,
            serde_json::json!({
                "sessions": sessions.iter().map(|(id, consumer, created, last_used, expires, client_info)| {
                    serde_json::json!({
                        "session_id": id,
                        "consumer": consumer,
                        "created_at": created,
                        "last_used_at": last_used,
                        "expires_at": expires,
                        "client_info": client_info,
                    })
                }).collect::<Vec<_>>(),
            }),
        ),
        Err(e) => envelope(500, "mcp_sessions_list_failed", &e.to_string(), request_id),
    }
}

/// DELETE /mcp/sessions/:id (DW-087): teardown an MCP session by id.
/// Returns 200 regardless of whether a row was deleted (idempotent).
async fn mcp_session_delete(
    ctx: Arc<AdminContext>,
    id: &str,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.state_store() else {
        return envelope(
            503,
            "state_store_not_configured",
            "a state store is required for MCP session management",
            request_id,
        );
    };
    match store.delete_mcp_session(id) {
        Ok(()) => json_response(200, serde_json::json!({"deleted": id})),
        Err(e) => envelope(500, "mcp_session_delete_failed", &e.to_string(), request_id),
    }
}

/// GET /mcp/tools (DW-087): list configured MCP tools from the current
/// snapshot's `ai.mcp` config block. Returns the tool name, description,
/// input schema, upstream reference, path, method, timeout, and whether
/// the tool has an authz attachment.
async fn mcp_tools_list(ctx: Arc<AdminContext>, _request_id: &str) -> Response<AdminBody> {
    let snapshot = ctx.state.snapshot();
    let gateway = snapshot.gateway();
    let Some(ai) = &gateway.ai else {
        return json_response(200, serde_json::json!({"tools": []}));
    };
    let Some(mcp) = &ai.mcp else {
        return json_response(200, serde_json::json!({"tools": []}));
    };
    let tools: Vec<_> = mcp
        .tools
        .iter()
        .map(|(name, t)| {
            serde_json::json!({
                "name": name,
                "description": t.description,
                "input_schema": t.input_schema,
                "upstream": t.upstream,
                "path": t.path,
                "method": t.method,
                "timeout_ms": t.timeout_ms,
                "authz": t.authz.is_some(),
            })
        })
        .collect();
    json_response(200, serde_json::json!({"tools": tools}))
}

/// GET /mcp/calls (DW-087): query MCP tool call analytics. Query
/// params: from_ms, to_ms (required), session_id, consumer,
/// tool_name (optional filters), limit (optional, default 10000, max
/// 10000).
async fn mcp_calls_query(
    ctx: Arc<AdminContext>,
    req: &Request<Incoming>,
    request_id: &str,
) -> Response<AdminBody> {
    let Some(store) = ctx.dp.analytics() else {
        return analytics_absent(request_id);
    };
    let params = query_params(req.uri());
    let (Some(from_ms), Some(to_ms)) = (
        param(&params, "from_ms").and_then(|v| v.parse::<i64>().ok()),
        param(&params, "to_ms").and_then(|v| v.parse::<i64>().ok()),
    ) else {
        return envelope(
            400,
            "mcp_calls_bad_window",
            "from_ms and to_ms are required query parameters",
            request_id,
        );
    };
    let q = dwara_core::analytics::query::McpToolCallQuery {
        from_ms,
        to_ms,
        session_id: param(&params, "session_id").map(|s| s.to_string()),
        consumer: param(&params, "consumer").map(|s| s.to_string()),
        tool_name: param(&params, "tool_name").map(|s| s.to_string()),
        limit: param(&params, "limit").and_then(|v| v.parse::<i64>().ok()),
    };
    match store.query(|c| dwara_core::analytics::query::mcp_tool_calls(c, &q)) {
        Ok(rows) => json_response(
            200,
            serde_json::json!({
                "query": {
                    "from_ms": q.from_ms,
                    "to_ms": q.to_ms,
                    "session_id": q.session_id,
                    "consumer": q.consumer,
                    "tool_name": q.tool_name,
                },
                "rows": rows,
            }),
        ),
        Err(e) => envelope(500, "mcp_calls_query_failed", &e.to_string(), request_id),
    }
}

#[cfg(test)]
mod supervision_tests {
    // White-box tests staying in src/ per AGENTS.md: the admin
    // supervision wiring is private to this crate, and inducing a REAL
    // accept-loop panic through the public surface is not externally
    // expressible (the same reasoning as dwara-bin's listener
    // supervision, #120). The shared supervisor's own semantics are
    // pinned in dwara-core's supervision module; these pin what admin
    // adds on top: the respawn budget and the clean-shutdown path
    // through the real serve().

    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{serve, supervise_admin_accept, ListenMode, MAX_ADMIN_RESPAWNS};

    /// Silences (and counts) the default panic hook for spawned-task
    /// panics so these tests do not spray backtraces into the log; the
    /// original hook is restored on drop.
    struct PanicHookQuiet {
        prev: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync>,
    }

    impl PanicHookQuiet {
        fn install() -> Self {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_info| {}));
            PanicHookQuiet { prev }
        }
    }

    impl Drop for PanicHookQuiet {
        fn drop(&mut self) {
            let prev = std::mem::replace(
                &mut self.prev,
                Box::new(|_info: &std::panic::PanicHookInfo| {}),
            );
            std::panic::set_hook(prev);
        }
    }

    #[tokio::test]
    async fn panicking_admin_incarnations_respawn_to_the_admin_budget_then_give_up() {
        let _quiet = PanicHookQuiet::install();
        let spawns = AtomicU32::new(0);
        supervise_admin_accept("127.0.0.1:0", || {
            spawns.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async { panic!("induced admin accept-loop panic") })
        })
        .await;
        // One initial incarnation plus MAX_ADMIN_RESPAWNS respawns; the
        // next panic exhausts the budget and supervision gives up
        // (admin listener left down loudly, process keeps running).
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            MAX_ADMIN_RESPAWNS + 1,
            "admin supervision respawns exactly to the budget"
        );
    }

    #[tokio::test]
    async fn serve_returns_ok_after_a_clean_shutdown() {
        // The full public path: serve() runs its accept incarnation
        // under supervision; a shutdown signal must end the incarnation
        // cleanly (drain included), end supervision, and return Ok —
        // never a silent death, never a hang.
        let state = std::sync::Arc::new(dwara_core::snapshot::ConfigState::new());
        state
            .compile_and_publish(
                &dwara_core::config::parse_gateway(
                    "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: 18080\n\
                     routes:\n  - name: r1\n    service: svc\n\
                     \x20   match:\n      path:\n        type: prefix\n        value: /api\n\
                     \x20   action:\n        type: proxy\n\
                     services:\n  - name: svc\n    upstream: echo\n\
                     upstreams:\n  - name: echo\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n",
                )
                .expect("config parses"),
            )
            .expect("config publishes");
        let dp = dwara_core::proxy::DataPlane::new(std::sync::Arc::clone(&state));
        let ctx = std::sync::Arc::new(super::AdminContext::new(
            state,
            dp,
            std::path::PathBuf::from("unused-dwara.yaml"),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let (tx, rx) = tokio::sync::watch::channel(());
        let handle = tokio::spawn(serve(ctx, listener, ListenMode::DevPlaintext, rx));
        // Signal shutdown; the receiver was never polled before this,
        // so the incarnation's changed() fires even though it may not
        // have entered its select yet.
        tx.send(()).expect("shutdown signal sent");
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("serve finishes after shutdown");
        assert!(outcome.expect("serve task must not panic").is_ok());
    }

    #[tokio::test]
    async fn respawned_admin_incarnation_serves_on_the_same_socket() {
        // The #130 acceptance property: a panicked accept incarnation is
        // respawned on the SAME bound socket (no re-bind, no port loss)
        // and the respawned incarnation keeps serving. Modelled through
        // the admin supervision wiring with a real listener: incarnation
        // one serves one connection then panics; the respawn must serve
        // the next connection on the same port.
        let _quiet = PanicHookQuiet::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shared = std::sync::Arc::new(listener);
        let spawns = std::sync::Arc::new(AtomicU32::new(0));
        let counter = std::sync::Arc::clone(&spawns);
        let supervision = tokio::spawn(async move {
            supervise_admin_accept("same-socket-test", move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let listener = std::sync::Arc::clone(&shared);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // Accept-loop shape: one accepted connection per
                    // incarnation, mirroring accept_incarnation's
                    // accept-then-spawn rhythm without the hyper body.
                    let (mut sock, _) = listener.accept().await.expect("accept");
                    let mut one = [0u8; 1];
                    sock.read_exact(&mut one).await.expect("read probe");
                    if one[0] == b'1' {
                        // First incarnation: served its connection, now
                        // dies like a buggy accept loop.
                        panic!("induced admin accept-loop panic");
                    }
                    // Respawned incarnation: same socket, keeps serving.
                    sock.write_all(b"up").await.expect("reply write");
                })
            })
            .await;
            spawns.load(Ordering::SeqCst)
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Connection one: consumed (and closed) by the panicking
        // incarnation. EOF proves the panic completed before the
        // respawn is probed.
        let mut first = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .expect("first connect within timeout")
        .expect("first connect succeeds");
        first.write_all(b"1").await.expect("first probe write");
        let mut eof = [0u8; 1];
        first
            .read_exact(&mut eof)
            .await
            .expect_err("panicking incarnation closed the connection");

        // Connection two: must be served by the RESPAWNED incarnation
        // accepting on the same bound socket (the kernel backlog holds
        // it until the respawn enters accept()).
        let mut second = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .expect("second connect within timeout")
        .expect("second connect succeeds on the same port");
        second.write_all(b"2").await.expect("second probe write");
        let mut got = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            second.read_exact(&mut got),
        )
        .await
        .expect("respawn reply within timeout")
        .expect("respawn reply read");
        assert_eq!(
            &got, b"up",
            "respawned incarnation serves on the same socket"
        );

        let count = tokio::time::timeout(std::time::Duration::from_secs(2), supervision)
            .await
            .expect("supervision ends after the respawn serves and returns cleanly")
            .expect("supervision task ended cleanly");
        assert_eq!(count, 2, "exactly one respawn, then a clean end");
    }

    #[tokio::test]
    async fn shutdown_signaled_before_a_respawn_ends_the_incarnation_immediately() {
        // Pins the receiver-clone semantics documented on
        // supervise_admin_accept: a respawn created AFTER shutdown was
        // signaled must observe the already-sent signal at once (the
        // clone inherits the never-updated seen version) instead of
        // waiting for a second signal that never comes. Without this,
        // a panic racing shutdown would strand a respawned accept loop
        // forever.
        let _quiet = PanicHookQuiet::install();
        let (tx, rx) = tokio::sync::watch::channel(());
        // Signal BEFORE any incarnation exists.
        tx.send(()).expect("shutdown signal sent");
        let spawns = std::sync::Arc::new(AtomicU32::new(0));
        let counter = std::sync::Arc::clone(&spawns);
        let done = tokio::spawn(async move {
            supervise_admin_accept("race-shutdown-test", move || {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let mut shutdown = rx.clone();
                tokio::spawn(async move {
                    if n == 0 {
                        // First incarnation: dies like a buggy accept
                        // loop that raced the shutdown signal.
                        panic!("induced admin accept-loop panic");
                    }
                    // Respawn: an accept-loop-shaped task that exits on
                    // shutdown — which was ALREADY signaled.
                    shutdown
                        .changed()
                        .await
                        .expect("already-sent shutdown observed");
                })
            })
            .await;
            spawns.load(Ordering::SeqCst)
        });
        let count = tokio::time::timeout(std::time::Duration::from_secs(2), done)
            .await
            .expect("supervision ends: respawn observed the already-sent shutdown")
            .expect("supervision task ended cleanly");
        assert_eq!(count, 2, "one panic, one immediate-exit respawn");
    }
}
