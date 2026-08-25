//! Admin API (DW-022, feature analysis 4.18; decision 6: mTLS-only).
//!
//! A small, separate hyper server surface for operators:
//!
//! - `GET /config` — the CURRENT published gateway config as normalized
//!   YAML, with `x-dwara-config-generation` / `x-dwara-config-hash`
//!   headers identifying the generation. SECURITY EXPOSURE: the returned
//!   document contains credential material (consumer secrets, basic-auth
//!   passwords, HMAC keys, JWT secrets) in PLAINTEXT — any client
//!   holding a valid admin client certificate can read it. Treat admin
//!   client certificates as secret-bearing and distribute them
//!   accordingly; the mTLS CA chain IS the access control here.
//! - `PATCH /config` — FULL-document YAML replacement (v1 has no partial
//!   merge: silent-merge of unknown subtrees is a footgun, so a PATCH
//!   body must be the complete config). The body is parsed, validated,
//!   and compiled as a dry run FIRST; on any issue the response is 400
//!   carrying EVERY problem (the same error envelope style as the
//!   dataplane). On success the new config is written ATOMICALLY to the
//!   config file (temp file + rename, so the file watcher and restarts
//!   observe exactly what was published) and then published to the
//!   running dataplane. Documented consequence: the gateway's config
//!   watcher also observes the rename and re-publishes the identical
//!   content (generation advances once more, harmlessly).
//! - `GET /health` — gateway readiness, config generation, and
//!   per-upstream per-endpoint health labels.
//! - `GET /stats` — cheap live state only: state-store schema version
//!   (when a store is attached), per-upstream breaker states, the
//!   active-requests gauge, and the config generation.
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
//! take effect on restart).

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

/// Everything the admin handlers need: the published-config state, the
/// dataplane (for refresh/health/stats), the config file path (for
/// atomic writes), and the write lock serializing PATCHes.
pub struct AdminContext {
    state: Arc<ConfigState>,
    dp: Arc<DataPlane>,
    config_path: PathBuf,
    patch_lock: Arc<Mutex<()>>,
}

impl AdminContext {
    pub fn new(state: Arc<ConfigState>, dp: Arc<DataPlane>, config_path: PathBuf) -> Self {
        AdminContext {
            state,
            dp,
            config_path,
            patch_lock: Arc::new(Mutex::new(())),
        }
    }
}

/// How the admin listener accepts connections.
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
    })
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
    match (method.as_str(), path.as_str()) {
        // GET /config: credential material (secrets, passwords, keys) is
        // returned in PLAINTEXT — any admin client-cert holder can read
        // it; treat admin certs as secret-bearing (see crate docs).
        ("GET", "/config") => {
            let snapshot = ctx.state.snapshot();
            let body = gateway_to_yaml(snapshot.gateway()).unwrap_or_default();
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
        ("GET", "/stats") => json_response(200, stats_body(&ctx)),
        // A known resource path with the wrong method.
        (_, "/config" | "/health" | "/stats") => envelope(
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

/// Serve the admin API on an already-bound listener until `shutdown`
/// fires, then drain gracefully (in-flight requests complete; anything
/// still draining when the process exits is closed by process exit).
pub async fn serve(
    ctx: Arc<AdminContext>,
    listener: TcpListener,
    mode: ListenMode,
    mut shutdown: watch::Receiver<()>,
) -> std::io::Result<()> {
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
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
        match &tls_config {
            Some(config) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(config));
                tokio::spawn(async move {
                    // A failed handshake here is the mTLS gate doing its
                    // job (no client cert, or a cert from the wrong CA).
                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                        serve_conn(watcher, ctx, tls_stream).await;
                    }
                });
            }
            None => {
                tokio::spawn(serve_conn(watcher, ctx, stream));
            }
        }
    }
    drop(listener);
    // Drain: in-flight admin requests complete; anything still open when
    // the process exits is closed by process exit (the binary's overall
    // shutdown budget governs).
    let drain = graceful.shutdown();
    drain.await;
    tracing::info!(code = "admin_drained", "admin listener drained");
    Ok(())
}

async fn serve_conn<S>(
    watcher: hyper_util::server::graceful::Watcher,
    ctx: Arc<AdminContext>,
    stream: S,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let auto = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
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
