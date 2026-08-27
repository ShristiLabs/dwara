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
