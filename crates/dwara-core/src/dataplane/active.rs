//! Active health checks (DW-013, feature analysis 4.5).
//!
//! Passive health (DW-012) watches real traffic; active health PROBES. For
//! every upstream that configures `active_health` (and therefore the
//! passive `health` block), one probe loop task per endpoint runs:
//!
//! ```text
//! loop { sleep(interval + uniform(0..jitter)); probe; report }
//! ```
//!
//! # Probe mechanics
//!
//! Probes go DIRECTLY to the endpoint (`address:port`), bypassing load
//! balancing and the pooled upstream client — a probe must examine one
//! specific endpoint, not whoever the balancer would pick. Each `http`
//! probe speaks HTTP/1.1 over its own connection (plaintext toward `http1`
//! upstreams, rustls with the same webpki root set and the endpoint
//! address as server name toward `https`/`http2` upstreams), issues
//! `GET {path}` with `Connection: close`, and classifies the FIRST status
//! line it reads: 2xx = success; anything else (3xx included — redirects
//! are not followed — 4xx, 5xx, truncation, timeout, transport error) =
//! failure. `tcp` probes succeed when the TCP connect completes within
//! `timeout_ms`. Documented limitation: `http2`-protocol upstreams that
//! refuse HTTP/1.1 on a separate connection will read as failing; use
//! `kind: tcp` for those. Likewise, upstreams whose certificates chain to
//! a PRIVATE CA (not the webpki root set) cannot be probed with `kind:
//! http` — the TLS handshake fails validation; use `kind: tcp` until
//! custom probe trust roots exist.
//!
//! # Timing
//!
//! Each cycle sleeps `interval` + uniform(0..`jitter`) BEFORE probing, so
//! the realized period is interval + jitter + probe duration and the tick
//! drifts late by that sum per cycle (no fixed-wallclock scheduling); the
//! jitter exists to keep probe storms from synchronizing across endpoints.
//!
//! # Reporting model (precedence over passive)
//!
//! Probe results report into the SAME per-endpoint
//! [`crate::resilience::health::EndpointHealth`] tracker the passive
//! checker and the load balancer use, so both systems feed one ejection
//! state and the existing pick filter removes failing endpoints from
//! rotation:
//!
//! - **Both run concurrently.** Either signal can eject: a passive report
//!   ejects at the passive `consecutive_failures` threshold; an active
//!   report ejects at `failure_threshold`. They share the tracker's
//!   consecutive-failure streak, so the last report's parameters decide
//!   whether that streak ejects — the coherent reading is "either can
//!   eject, on its own threshold, from one shared streak".
//! - **Active reports use the consecutive path only.** Probe reports go
//!   through [`EndpointHealth::report_probe`], which never inserts an
//!   observation into the rolling window — synthetic probes must not be
//!   mixed into real-traffic ratios — and the probe's report parameters
//!   additionally disable the failure-ratio/volume rule
//!   (`failure_min_volume = u32::MAX`) as a second line of defense. The
//!   passive window/eject/half-open parameters stay in force.
//! - **Ejection** follows the passive model: after `failure_threshold`
//!   consecutive failed probes the endpoint leaves rotation for
//!   `health.eject_ms`. Probe failures while already ejected leave the
//!   window alone (they cannot extend it).
//! - **Recovery** is probe-driven: `success_threshold` consecutive
//!   successful probes report a success, and a success observed on an
//!   ejected (or half-open) tracker restores it outright — with active
//!   health on, a healthy probe streak re-admits the endpoint even before
//!   `eject_ms` expires, which is the point of probing. A probe success
//!   below the threshold is reported only when the endpoint is currently
//!   available (it just resets the failure streak; it never re-admits).
//!   Best-effort under races, exactly like the rest of the tracker.
//!
//! # Task lifecycle
//!
//! [`ActiveProbes`] owns one [`tokio::task::JoinSet`] for every probe
//! loop. The operator (dwara-bin) calls [`ActiveProbes::respawn`] after
//! every snapshot swap (startup and each reload): all previous loops are
//! aborted and new ones spawned for the new generation's upstreams.
//! Endpoints whose `address:port` persists across the swap keep their
//! tracker (the balancer carries it, DW-011/DW-012 semantics), so an
//! ejection streak survives a reload even though the probe task restarts.
//! Dropping [`ActiveProbes`] (or calling [`ActiveProbes::abort_all`])
//! aborts every loop — the graceful-shutdown path.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::config::{ActiveHealth, ProbeKind};
use crate::dataplane::balance::UpstreamLb;
use crate::dataplane::upstream::UpstreamRegistry;
use crate::resilience::health::{EndpointHealth, HealthParams};
use crate::snapshot::Snapshot;

/// Resolved (validated) active-probe parameters, copied into each probe
/// loop so a config rebuild cannot change a running loop mid-flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveParams {
    pub kind: ProbeKind,
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub success_threshold: u32,
    pub failure_threshold: u32,
    pub jitter: Duration,
}

impl ActiveParams {
    /// Resolve from the config form (serde already applied defaults).
    pub fn from_config(a: &ActiveHealth) -> Self {
        ActiveParams {
            kind: a.kind,
            path: a.path.clone(),
            interval: Duration::from_millis(a.interval_ms),
            timeout: Duration::from_millis(a.timeout_ms),
            success_threshold: a.success_threshold,
            failure_threshold: a.failure_threshold,
            jitter: Duration::from_millis(a.jitter_ms),
        }
    }
}

/// Report parameters for probe outcomes: the passive window/eject/half-open
/// parameters with the ACTIVE thresholds substituted and the ratio rule
/// disabled (see the module docs).
///
/// Public for testing the probe report-parameters contract.
pub fn report_params(active: &ActiveParams, passive: &HealthParams) -> HealthParams {
    HealthParams {
        window_ms: passive.window_ms,
        consecutive_failures: active.failure_threshold.max(1),
        failure_ratio: 1.0,
        failure_min_volume: u32::MAX,
        eject_ms: passive.eject_ms,
        half_open_probes: passive.half_open_probes,
    }
}

/// `address:port` with IPv6 literals bracketed (same rule as the upstream
/// client).
fn authority(address: &str, port: u16) -> String {
    let host = if address.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{address}]")
    } else {
        address.to_string()
    };
    format!("{host}:{port}")
}

/// Read the response status line over `io` and classify it. Reads
/// accumulate until CRLF is seen (a status line may arrive fragmented
/// across segments), the 4 KB cap is hit, or the peer closes; the outer
/// probe timeout bounds the whole loop (a stalled peer simply never gets
/// a verdict before the attempt future is dropped = failure).
async fn http_status_ok<S>(io: &mut S, authority: &str, path: &str) -> std::io::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: dwara-probe\r\n\
         Connection: close\r\n\r\n"
    );
    io.write_all(req.as_bytes()).await?;
    io.flush().await?;
    const CAP: usize = 4096;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            break; // closed: parse whatever arrived
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= CAP || buf.windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }
    if buf.is_empty() {
        return Ok(false); // closed before any status line
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    Ok(matches!(status, Some(s) if (200..300).contains(&s)))
}

/// One direct probe of `address:port`, bounded by `timeout` (connect plus
/// response for http). `scheme` is the upstream's dial scheme ("http" or
/// "https"). Returns whether the endpoint answered healthy.
pub async fn probe_once(
    kind: ProbeKind,
    scheme: &str,
    address: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> bool {
    match kind {
        ProbeKind::Tcp => {
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect((address, port)))
                .await
                .is_ok_and(|r| r.is_ok())
        }
        ProbeKind::Http => {
            let attempt = async {
                let tcp = tokio::net::TcpStream::connect((address, port)).await?;
                if scheme != "https" {
                    let mut io = tcp;
                    let ok = http_status_ok(&mut io, &authority(address, port), path).await?;
                    let _ = io.shutdown().await;
                    Ok::<bool, std::io::Error>(ok)
                } else {
                    // Same trust model as the pooled client: webpki roots,
                    // endpoint address as server name (works for hostname
                    // endpoints and IP endpoints with IP-SAN certificates).
                    let mut cfg = rustls::ClientConfig::builder()
                        .with_root_certificates(webpki_roots_store())
                        .with_no_client_auth();
                    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
                    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
                    let name = match rustls::pki_types::ServerName::try_from(address.to_string()) {
                        Ok(n) => n,
                        Err(_) => return Ok(false),
                    };
                    let mut tls = connector.connect(name, tcp).await?;
                    let ok = http_status_ok(&mut tls, &authority(address, port), path).await?;
                    let _ = tls.shutdown().await;
                    Ok(ok)
                }
            };
            tokio::time::timeout(timeout, attempt)
                .await
                .map(|r| r.unwrap_or(false))
                .unwrap_or(false)
        }
    }
}

fn webpki_roots_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

// Process-local xorshift64* seed for full jitter (no `rand` dependency;
// same approach as the balancer's random-2).
static JITTER_RNG: AtomicU64 = AtomicU64::new(0x853c_49e6_748f_ea9b);

/// Public for testing the probe-jitter bound contract.
pub fn next_below(bound_ms: u64) -> u64 {
    if bound_ms == 0 {
        return 0;
    }
    loop {
        let x = JITTER_RNG.load(Ordering::Relaxed);
        let mut y = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        y ^= y >> 12;
        y ^= y << 25;
        y ^= y >> 27;
        if JITTER_RNG
            .compare_exchange(x, y, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            // Multiply-shift reduction (Lemire-style): unbiased enough for
            // jitter at these widths.
            return ((y as u128 * bound_ms as u128) >> 64) as u64;
        }
    }
}

/// Give up on a probe loop after this many consecutive panicked
/// iterations; the endpoint keeps its passive tracker (passive-only
/// health) and the operator sees a loud log.
const MAX_CONSECUTIVE_PANICS: u32 = 3;

/// `catch_unwind` for futures (std has no `FutureExt::catch_unwind`):
/// each poll of `fut` runs under `catch_unwind`, so a panic raised at any
/// await point inside `fut` surfaces as `Err` instead of unwinding the
/// loop task.
pub fn catch_unwind_future<F: Future>(
    fut: F,
) -> impl Future<Output = Result<F::Output, Box<dyn std::any::Any + Send>>> {
    let mut fut = Box::pin(fut);
    std::future::poll_fn(move |cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(poll) => poll.map(Ok),
            Err(panic) => std::task::Poll::Ready(Err(panic)),
        }
    })
}

/// The per-endpoint probe loop. Runs until the task is aborted by a
/// respawn or shutdown; every iteration reports into `tracker` via
/// [`EndpointHealth::report_probe`] (probe results never enter the
/// passive ratio window).
///
/// A panicking iteration must not kill the loop silently: each iteration
/// body runs under [`catch_unwind_future`], a panic is logged loudly, and
/// the loop continues after a backoff of one `interval`. After
/// [`MAX_CONSECUTIVE_PANICS`] consecutive panics the loop gives up
/// (logged) and the endpoint stays passive-only until the next respawn.
async fn probe_loop(
    lb: Arc<UpstreamLb>,
    address: String,
    port: u16,
    tracker: Arc<EndpointHealth>,
    active: ActiveParams,
    passive: HealthParams,
    scheme: &'static str,
) {
    let report = report_params(&active, &passive);
    let mut success_streak: u32 = 0;
    let mut consecutive_panics: u32 = 0;
    loop {
        sleep(active.interval).await;
        let jitter = Duration::from_millis(next_below(active.jitter.as_millis() as u64));
        sleep(jitter).await;
        let iteration = async {
            let ok = probe_once(
                active.kind,
                scheme,
                &address,
                port,
                &active.path,
                active.timeout,
            )
            .await;
            let now = lb.now_ms();
            if ok {
                success_streak += 1;
                // Below the success threshold a success only matters when
                // the endpoint is already available (reset the shared
                // failure streak); re-admission needs the full threshold.
                if success_streak >= active.success_threshold || tracker.is_available(now) {
                    tracker.report_probe(&report, now, false);
                }
            } else {
                success_streak = 0;
                tracker.report_probe(&report, now, true);
            }
        };
        match catch_unwind_future(iteration).await {
            Ok(()) => consecutive_panics = 0,
            Err(panic) => {
                consecutive_panics += 1;
                let detail = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_string());
                tracing::error!(
                    code = "active_probe_panicked",
                    endpoint = %format!("{address}:{port}"),
                    "active probe loop panicked ({consecutive_panics}/{MAX_CONSECUTIVE_PANICS}): {detail}"
                );
                if consecutive_panics >= MAX_CONSECUTIVE_PANICS {
                    tracing::error!(
                        code = "active_probe_abandoned",
                        endpoint = %format!("{address}:{port}"),
                        "active probe loop giving up after {MAX_CONSECUTIVE_PANICS} \
                         consecutive panics; passive health continues for this endpoint"
                    );
                    return;
                }
                success_streak = 0;
                sleep(active.interval).await; // backoff before the retry
            }
        }
    }
}

/// Owns every active-probe loop task for the running generation. Call
/// [`ActiveProbes::respawn`] on startup and after every snapshot swap;
/// dropping it (or shutdown) aborts all loops.
#[derive(Default)]
pub struct ActiveProbes {
    tasks: JoinSet<()>,
}

impl ActiveProbes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Abort all current probe loops and spawn fresh ones for every
    /// upstream in `snapshot` that configures `active_health`. Trackers are
    /// taken from the CURRENT registry generation (call after
    /// `DataPlane::refresh`), so loops probe the same live tracker the
    /// balancer filters with. Upstreams without active health spawn
    /// nothing.
    pub fn respawn(&mut self, registry: &UpstreamRegistry, snapshot: &Snapshot) {
        self.abort_all();
        for u in &snapshot.gateway().upstreams {
            let Some(active_cfg) = &u.active_health else {
                continue;
            };
            // Validation guarantees health.is_some(); a directly
            // constructed (unvalidated) pair simply does not probe.
            let Some(passive_cfg) = &u.health else {
                continue;
            };
            let Some(handle) = registry.get(&u.name) else {
                continue;
            };
            let active = ActiveParams::from_config(active_cfg);
            let passive = HealthParams::from_config(passive_cfg);
            let scheme: &'static str = if handle.scheme() == "https" {
                "https"
            } else {
                "http"
            };
            for (address, port, tracker) in handle.lb().health_targets() {
                let Some(tracker) = tracker else { continue };
                self.tasks.spawn(probe_loop(
                    Arc::clone(handle.lb()),
                    address,
                    port,
                    tracker,
                    active.clone(),
                    passive,
                    scheme,
                ));
            }
        }
    }

    /// Abort every probe loop (they stop at the next await point).
    pub fn abort_all(&mut self) {
        self.tasks.abort_all();
    }

    /// Number of live probe-loop tasks (spawned minus finished/aborted
    /// that have been reaped). Observability/tests.
    pub fn task_count(&mut self) -> usize {
        while self.tasks.try_join_next().is_some() {}
        self.tasks.len()
    }
}
