//! Registry plugin source resolution (DW-165).
//!
//! A plugin entry with `source:` names a remote `.wasm` artifact
//! (registry URL + mandatory SHA-256 digest + optional Ed25519
//! signature/key material). This module resolves every such entry to a
//! VERIFIED local file BEFORE the wasm load step (`PluginLifecycle::
//! load`), so a registry plugin enters the runtime through exactly the
//! same read/compile/health path as a local `wasm:` plugin — there is
//! no partial load: an artifact that cannot be resolved or fails
//! verification never reaches wasmtime, and the plugin is marked
//! `Crashed` at publish (fail-closed for its routes, DW-157/158
//! vocabulary).
//!
//! ## Resolution pipeline (per `source:` plugin)
//!
//! 1. **Scheme check** — only `https://` is fetchable. `oci://`
//!    references parse in config but are rejected with a clear
//!    validation error in this version (see the registry spec in the
//!    user docs); the resolver repeats the rejection defensively.
//! 2. **Digest format check** — `source.digest` must be a 64-char
//!    SHA-256 hex string (case-insensitive; normalized lowercase).
//! 3. **Cache lookup** — the artifact is content-addressed:
//!    `<cache_dir>/<digest>.wasm` (`source.cache_path` overrides the
//!    location, not the verification; it must be a relative path with
//!    no `..` segments — containment, see [`PluginSourceConfig::
//!    cache_path_violation`]). A present cache file whose bytes do
//!    not hash to the pinned digest is a tampered/corrupt entry and
//!    FAILS CLOSED with a digest-mismatch error naming the expected
//!    and actual digests — it is never silently re-fetched (an
//!    operator must see that the file named for one digest holds
//!    another). A cache hit still verifies the signature.
//! 4. **Download** (cache miss only, and only while the per-publish
//!    budget has time left) — one HTTPS GET, HTTP/1.1, redirects NOT
//!    followed, response size capped. See the downloader note below
//!    for why this is a hand-rolled client.
//! 5. **Digest verification** — downloaded bytes must hash to the
//!    pinned digest; mismatch fails closed naming both digests.
//! 6. **Signature verification** — when `signature`/`public_key` (or
//!    pinned `plugin_registry.public_keys`) are configured, an
//!    Ed25519 signature over the artifact bytes must verify. A plugin
//!    with no signature is REJECTED when the registry pins keys, and
//!    a `public_key` without a `signature` is rejected as a config
//!    mistake (a key that verifies nothing).
//! 7. **Atomic cache write** — tmp file in the same directory, fsync,
//!    rename into place. A crash mid-write can never leave a partial
//!    artifact under the digest name; the next resolve either sees the
//!    complete file or downloads again.
//!
//! ## Downloader (why a hand-rolled client)
//!
//! dwara-core has no reqwest/ureq; the repo precedent for outbound
//! HTTP is the events domain's hand-rolled HTTP/1.1 client
//! (`events::webhook`, tokio-based). That client is private to
//! `events`, which the wasm domain must not import (`check_deps.py`:
//! wasm <- config, plugins), and it is async while resolution runs
//! inside the SYNCHRONOUS `DataPlane::reload_plugins` (called from
//! async reload loops — a nested `block_on` would panic). So this
//! module carries its own minimal SYNCHRONOUS HTTPS GET: std
//! `TcpStream` + rustls `ClientConnection` (both already direct
//! dependencies), public webpki roots, the same egress posture as
//! webhooks (operator-configured URL, SSRF egress filter applied at
//! connect time when enabled, redirects not followed).
//!
//! ## Time budget (review finding: no unbounded holds)
//!
//! Two layers bound every resolution, because a registry that drips
//! one byte per read would otherwise defeat a per-read timeout (each
//! read resets it) and hold a thread forever:
//!
//! - a per-READ timeout (10s connect, 30s per read), and
//! - a per-PUBLISH total budget ([`RESOLUTION_BUDGET`], 60s across
//!   ALL source plugins of one publish), checked before each download
//!   and inside the fetcher's read loop. A cache hit needs no network
//!   and is never budget-gated. Budget exhaustion fails the affected
//!   plugin closed with a step-named error ([`SourceError::
//!   ResolutionBudgetExceeded`] / a `DownloadFailed` naming the
//!   budget), never a hang.
//!
//! The binary's reload path additionally runs the whole resolution on
//! `tokio::task::spawn_blocking` (DNS via getaddrinfo and the sync
//! TLS reads are blocking syscalls), so the async reload task awaits
//! instead of holding a worker thread; see `dwara-bin`'s reload
//! driver.
//!
//! ## Cache layout
//!
//! ```text
//! <cache_dir>/                 (plugin_registry.cache_dir, default ./plugin-cache)
//!   <sha256-digest>.wasm       one immutable artifact per digest
//!   .<sha256-digest>.wasm.tmp<pid>   transient write target (never read)
//! ```
//!
//! Artifacts are content-addressed: two plugins pinning the same
//! digest share one file, and a restart (or a second gateway process)
//! re-resolves from the cache without network access — the
//! restart-safety test pins this by pointing `url` at a dead port and
//! resolving from cache alone.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::config::ssrf::SsrfFilter;
use crate::config::{Gateway, PluginRegistryConfig, PluginSourceConfig};

/// Default cache directory when `plugin_registry.cache_dir` is absent
/// (relative to the gateway working directory, the same posture as the
/// ACME `state_dir` default).
pub const DEFAULT_CACHE_DIR: &str = "./plugin-cache";

/// Hard cap on one downloaded artifact (bytes). proxy-wasm filter
/// modules are small; this binds a hostile registry answer.
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Cap on the response head while locating the blank line (bytes).
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// TCP connect timeout per address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-read timeout on the established connection. This bounds ONE
/// read/write, not the exchange: a registry that drips one byte per
/// read resets it every time. The wall-clock bound on the whole
/// resolution is [`RESOLUTION_BUDGET`], enforced in the read loop.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Total wall-clock budget for registry-source resolution per publish,
/// shared across ALL `source:` plugins (review finding: a drip-feeding
/// or hung registry must not hold the reload path unboundedly, and N
/// plugins must not stack N budgets). Checked before each download and
/// between reads in the fetch loop; cache hits are never budget-gated
/// (they need no network). Exhaustion fails the affected plugin closed
/// with a step-named error; the next publish retries.
pub const RESOLUTION_BUDGET: Duration = Duration::from_secs(60);

/// `User-Agent` stamped on registry fetches.
const USER_AGENT: &str = "dwara-plugin-registry";

/// Per-plugin resolution results keyed by plugin name (only
/// `source:` plugins appear). Built by [`resolve_sources`]; consumed
/// by `PluginLifecycle::load`.
pub type SourceResolutions = HashMap<String, Result<PathBuf, SourceError>>;

/// Why a `source:` plugin could not be resolved. Every variant names
/// the plugin and the exact pipeline step that failed; `Display`
/// messages are operator-facing (they reach the crashed-plugin error
/// string on the status surface and the publish-time log line).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The URL uses `oci://`, which is not supported in this version.
    OciUnsupported { plugin: String, url: String },
    /// The URL is not a usable `https://` reference.
    InvalidUrl {
        plugin: String,
        url: String,
        reason: String,
    },
    /// `source.digest` is not a 64-char hex SHA-256.
    InvalidDigest {
        plugin: String,
        digest: String,
        reason: String,
    },
    /// The cache file exists but cannot be read (permissions, IO).
    CacheUnreadable {
        plugin: String,
        path: String,
        error: String,
    },
    /// Artifact bytes do not hash to the pinned digest. `origin`
    /// distinguishes the cached copy from a fresh download.
    DigestMismatch {
        plugin: String,
        origin: &'static str,
        expected: String,
        actual: String,
    },
    /// Ed25519 verification failed (bad key/sig material, wrong key,
    /// or a missing signature where the registry pins keys).
    SignatureRejected { plugin: String, reason: String },
    /// The artifact was not cached and the download failed.
    DownloadFailed {
        plugin: String,
        url: String,
        detail: String,
    },
    /// The verified artifact could not be written to the cache.
    CacheWriteFailed {
        plugin: String,
        path: String,
        error: String,
    },
    /// `source.cache_path` escapes the plugin cache directory. The
    /// resolver creates directories and writes artifact bytes at the
    /// operator-chosen path, so containment is enforced before any
    /// lookup or download happens.
    InvalidCachePath {
        plugin: String,
        path: String,
        reason: String,
    },
    /// The per-publish resolution budget ran out before this plugin's
    /// download could start (a hung or drip-feeding registry). The
    /// plugin fails closed; the next publish retries.
    ResolutionBudgetExceeded { plugin: String, budget_secs: u64 },
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::OciUnsupported { plugin, url } => write!(
                f,
                "plugin '{plugin}': source.url '{url}' uses oci://, which is not \
                 supported in this version; publish the artifact over https:// or \
                 pre-fetch it with `dwara-cli plugin install` and reference the \
                 local file with `wasm`"
            ),
            SourceError::InvalidUrl {
                plugin,
                url,
                reason,
            } => write!(
                f,
                "plugin '{plugin}': source.url '{url}' is not usable: {reason} \
                 (must be an https:// URL)"
            ),
            SourceError::InvalidDigest {
                plugin,
                digest,
                reason,
            } => write!(
                f,
                "plugin '{plugin}': source.digest is invalid ({reason}); got \
                 '{digest}' — expected a 64-char hex-encoded SHA-256"
            ),
            SourceError::CacheUnreadable {
                plugin,
                path,
                error,
            } => write!(
                f,
                "plugin '{plugin}': cached artifact at {path} could not be read \
                 (cache lookup step): {error}"
            ),
            SourceError::DigestMismatch {
                plugin,
                origin,
                expected,
                actual,
            } => write!(
                f,
                "plugin '{plugin}': digest verification failed for the {origin} \
                 artifact: source.digest pins {expected} but the bytes hash to \
                 {actual}; the artifact was NOT loaded"
            ),
            SourceError::SignatureRejected { plugin, reason } => write!(
                f,
                "plugin '{plugin}': Ed25519 signature verification failed: {reason}"
            ),
            SourceError::DownloadFailed {
                plugin,
                url,
                detail,
            } => write!(
                f,
                "plugin '{plugin}': download from '{url}' failed (download step): \
                 {detail}; the artifact was not cached — pre-fetch it with \
                 `dwara-cli plugin install` into the plugin cache and reload"
            ),
            SourceError::CacheWriteFailed {
                plugin,
                path,
                error,
            } => write!(
                f,
                "plugin '{plugin}': verified artifact could not be cached at \
                 {path} (cache write step): {error}"
            ),
            SourceError::InvalidCachePath {
                plugin,
                path,
                reason,
            } => write!(
                f,
                "plugin '{plugin}': source.cache_path '{path}' is not usable \
                 ({reason}); it must be a relative path under the plugin cache \
                 dir (plugin_registry.cache_dir) with no parent segments — an \
                 escaping cache_path would write the artifact outside the cache"
            ),
            SourceError::ResolutionBudgetExceeded {
                plugin,
                budget_secs,
            } => write!(
                f,
                "plugin '{plugin}': registry source resolution exceeded the \
                 {budget_secs}s per-publish budget before its download step; the \
                 plugin was not resolved (fail-closed) — the next publish retries; \
                 pre-fetch the artifact with `dwara-cli plugin install` if the \
                 registry is slow"
            ),
        }
    }
}

impl std::error::Error for SourceError {}

/// The download step as a callable: production wires [`https_get`]
/// (real TLS, SSRF-checked, deadline-bounded); the integration tests
/// inject bytes so the download-side verification pipeline runs
/// without a TLS server. `#[doc(hidden)]`: a test seam, not public
/// API.
#[doc(hidden)]
pub type FetchFn = fn(&str, &SsrfFilter, Instant) -> Result<Vec<u8>, String>;

/// Resolve every `source:` plugin in the gateway config to a verified
/// local artifact path. Local `wasm:`/`native` plugins are absent from
/// the map. Successes are logged (cache vs download); failures are
/// logged by the lifecycle when they mark the plugin Crashed (this
/// function stays quiet on errors so the crash log line is the single
/// publish-time record). The whole resolution runs under the
/// [`RESOLUTION_BUDGET`] per-publish budget.
pub fn resolve_sources(gateway: &Gateway) -> SourceResolutions {
    resolve_sources_with_fetch(gateway, https_get, Instant::now() + RESOLUTION_BUDGET)
}

/// Resolve with an injected download step and an explicit deadline.
/// `#[doc(hidden)]`: the seam the integration tests use to exercise
/// the download-side digest/signature verification (injected bytes)
/// and the budget gate (an already-past deadline) deterministically,
/// without a TLS registry.
#[doc(hidden)]
pub fn resolve_sources_with_fetch(
    gateway: &Gateway,
    fetch: FetchFn,
    deadline: Instant,
) -> SourceResolutions {
    let cache_root = PathBuf::from(
        gateway
            .plugin_registry
            .as_ref()
            .and_then(|r| r.cache_dir.clone())
            .unwrap_or_else(|| DEFAULT_CACHE_DIR.to_string()),
    );
    let ssrf = gateway
        .ssrf_filter
        .as_ref()
        .map(SsrfFilter::from_config)
        .unwrap_or_else(SsrfFilter::disabled);
    let mut out = HashMap::new();
    for plugin in &gateway.plugins {
        let Some(source) = &plugin.source else {
            continue;
        };
        let result = resolve_one(
            &plugin.name,
            source,
            gateway.plugin_registry.as_ref(),
            &cache_root,
            &ssrf,
            fetch,
            deadline,
        );
        if let Ok((path, via)) = &result {
            tracing::info!(
                code = "plugin_source_resolved",
                plugin = %plugin.name,
                artifact = %path.display(),
                via,
                "DW-165: registry plugin source resolved and verified"
            );
        }
        out.insert(plugin.name.clone(), result.map(|(path, _)| path));
    }
    out
}

/// Resolve one `source:` entry through the documented pipeline.
/// `fetch` is the download step (production: [`https_get`]; tests
/// inject bytes); `deadline` is the per-publish resolution budget.
fn resolve_one(
    plugin: &str,
    source: &PluginSourceConfig,
    registry: Option<&PluginRegistryConfig>,
    cache_root: &Path,
    ssrf: &SsrfFilter,
    fetch: FetchFn,
    deadline: Instant,
) -> Result<(PathBuf, &'static str), SourceError> {
    // Step 1: scheme. https only; oci is a documented v1 rejection.
    if source.url.starts_with("oci://") {
        return Err(SourceError::OciUnsupported {
            plugin: plugin.to_string(),
            url: source.url.clone(),
        });
    }
    if !source.url.starts_with("https://") {
        return Err(SourceError::InvalidUrl {
            plugin: plugin.to_string(),
            url: source.url.clone(),
            reason: "must use the https:// scheme".to_string(),
        });
    }

    // Step 2: digest format (case-insensitive hex, normalized).
    let digest = source.digest.to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        let reason = if digest.len() != 64 {
            format!("wrong length: {} chars, expected 64", digest.len())
        } else {
            "contains non-hex characters".to_string()
        };
        return Err(SourceError::InvalidDigest {
            plugin: plugin.to_string(),
            digest: source.digest.clone(),
            reason,
        });
    }

    // Step 3: cache lookup (content-addressed under the digest).
    // Containment first (review finding): cache_path is
    // operator-chosen and the resolver create_dir_all + writes bytes
    // there — it must stay inside the cache dir. Validation rejects
    // this earlier with a field-named issue; the resolver repeats the
    // rejection defensively (the same posture as every other check).
    if let Some(p) = &source.cache_path {
        if let Some(reason) = PluginSourceConfig::cache_path_violation(p) {
            return Err(SourceError::InvalidCachePath {
                plugin: plugin.to_string(),
                path: p.clone(),
                reason: reason.to_string(),
            });
        }
    }
    let cache_path: PathBuf = match &source.cache_path {
        // Relative TO THE CACHE ROOT (containment): a validated
        // cache_path never escapes it, and the artifact always lands
        // under the operator's cache dir.
        Some(p) => cache_root.join(p),
        None => cache_root.join(format!("{digest}.wasm")),
    };
    if cache_path.is_file() {
        let bytes = std::fs::read(&cache_path).map_err(|e| SourceError::CacheUnreadable {
            plugin: plugin.to_string(),
            path: cache_path.display().to_string(),
            error: e.to_string(),
        })?;
        let actual = super::lifecycle::sha256_hex(&bytes);
        if actual != digest {
            // Tampered or corrupt cache entry: fail closed, never a
            // silent re-download (see module docs).
            return Err(SourceError::DigestMismatch {
                plugin: plugin.to_string(),
                origin: "cached",
                expected: digest,
                actual,
            });
        }
        verify_signature(plugin, source, registry, &bytes)?;
        return Ok((cache_path, "cache"));
    }

    // Budget gate (review finding): network work only starts while
    // the per-publish budget has time left. Cache hits above are
    // never budget-gated — they need no network.
    if Instant::now() >= deadline {
        return Err(SourceError::ResolutionBudgetExceeded {
            plugin: plugin.to_string(),
            budget_secs: RESOLUTION_BUDGET.as_secs(),
        });
    }

    // Step 4/5: download + digest verification.
    let bytes =
        fetch(&source.url, ssrf, deadline).map_err(|detail| SourceError::DownloadFailed {
            plugin: plugin.to_string(),
            url: source.url.clone(),
            detail,
        })?;
    let actual = super::lifecycle::sha256_hex(&bytes);
    if actual != digest {
        return Err(SourceError::DigestMismatch {
            plugin: plugin.to_string(),
            origin: "downloaded",
            expected: digest,
            actual,
        });
    }

    // Step 6: signature verification (before the bytes are cached or
    // loaded — an unsigned-when-required artifact never lands).
    verify_signature(plugin, source, registry, &bytes)?;

    // Step 7: atomic cache write (tmp + fsync + rename).
    atomic_write(&cache_path, &bytes).map_err(|e| SourceError::CacheWriteFailed {
        plugin: plugin.to_string(),
        path: cache_path.display().to_string(),
        error: e.to_string(),
    })?;
    Ok((cache_path, "download"))
}

/// Verify the configured Ed25519 signature rules over `artifact`:
///
/// - `signature` + `public_key` set: the signature must verify against
///   the per-plugin key.
/// - `plugin_registry.public_keys` non-empty: the signature is
///   REQUIRED and must verify against at least one pinned key (in
///   addition to any per-plugin key).
/// - `public_key` WITHOUT `signature`: rejected (review finding — a
///   key that verifies nothing is a config mistake, not a mode).
/// - No signature and no pinned keys: digest-only mode (trusted
///   registry), documented as such.
fn verify_signature(
    plugin: &str,
    source: &PluginSourceConfig,
    registry: Option<&PluginRegistryConfig>,
    artifact: &[u8],
) -> Result<(), SourceError> {
    let rejected = |reason: String| {
        Err(SourceError::SignatureRejected {
            plugin: plugin.to_string(),
            reason,
        })
    };
    let pinned: &[String] = registry.map(|r| r.public_keys.as_slice()).unwrap_or(&[]);

    let Some(sig_hex) = &source.signature else {
        if source.public_key.is_some() {
            return rejected(
                "source.public_key is set but source.signature is not; a key \
                 without a signature verifies nothing — sign the artifact or \
                 remove the key"
                    .to_string(),
            );
        }
        if pinned.is_empty() {
            return Ok(()); // digest-only mode
        }
        return rejected(
            "the registry pins public keys (plugin_registry.public_keys) but \
             source.signature is not set; unsigned artifacts are rejected"
                .to_string(),
        );
    };

    // Per-plugin key first (when configured).
    if let Some(pk_hex) = &source.public_key {
        verify_with_key(plugin, artifact, pk_hex, sig_hex, "source.public_key")?;
    } else if pinned.is_empty() {
        return rejected(
            "source.signature is set but neither source.public_key nor \
             plugin_registry.public_keys is configured"
                .to_string(),
        );
    }

    // Pinned registry keys: the signature must match one of them.
    if !pinned.is_empty() {
        let ok = pinned
            .iter()
            .any(|pk_hex| verify_with_key_quiet(artifact, pk_hex, sig_hex).is_some());
        if !ok {
            return rejected(format!(
                "the signature does not verify against any of the {} pinned \
                 plugin_registry.public_keys keys",
                pinned.len()
            ));
        }
    }
    Ok(())
}

/// Verify `sig_hex` over `artifact` with `pk_hex`, mapping every
/// failure (bad key/sig material included — defense in depth behind
/// validation) to a [`SourceError::SignatureRejected`] naming the key
/// source (`field`).
fn verify_with_key(
    plugin: &str,
    artifact: &[u8],
    pk_hex: &str,
    sig_hex: &str,
    field: &str,
) -> Result<(), SourceError> {
    let reason = match verify_with_key_quiet(artifact, pk_hex, sig_hex) {
        Some(()) => return Ok(()),
        None => format!("the signature does not verify against {field}"),
    };
    Err(SourceError::SignatureRejected {
        plugin: plugin.to_string(),
        reason,
    })
}

/// The quiet verifier: `Some(())` on success, `None` on any failure
/// (bad hex, wrong length, bad key bytes, failed check). Callers
/// translate to step-naming errors.
fn verify_with_key_quiet(artifact: &[u8], pk_hex: &str, sig_hex: &str) -> Option<()> {
    let key_bytes = decode_hex(pk_hex)?;
    let sig_bytes = decode_hex(sig_hex)?;
    let key_arr: [u8; 32] = key_bytes.try_into().ok()?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&key_arr).ok()?;
    let sig = Signature::from_bytes(&sig_arr);
    key.verify_strict(artifact, &sig).ok()
}

/// Decode a hex string (even length, ASCII hex digits only).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Write `bytes` to `path` atomically: tmp file in the SAME directory
/// (rename must not cross filesystems), fsync before rename so a crash
/// never leaves a truncated artifact under the final name, then
/// rename. Restart-safe: a reader sees either the old complete file or
/// the new complete file, never a partial write.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "artifact".to_string());
    let tmp = path.with_file_name(format!(".{file_name}.tmp{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// --- minimal synchronous HTTPS GET -----------------------------------------
//
// See the module docs for why this exists (and why it is sync). The
// shape mirrors events::webhook's client where the concerns overlap:
// operator-configured URL (no SSRF boundary against the config
// author), connect-time SSRF filter when enabled, public webpki
// roots, HTTP/1.1, redirects not followed, one bounded exchange —
// bounded by BOTH the per-read timeout and the per-publish `deadline`
// (checked in the read loop; a drip-feeding registry cannot outlast
// it by resetting the per-read timer).

/// Perform one HTTPS GET and return the response body. `detail`
/// errors are operator-facing strings (they land inside
/// [`SourceError::DownloadFailed`]).
fn https_get(url: &str, ssrf: &SsrfFilter, deadline: Instant) -> Result<Vec<u8>, String> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| format!("URL does not parse: {e}"))?;
    if uri.scheme_str() != Some("https") {
        return Err("only https:// URLs are fetched".to_string());
    }
    let host = uri
        .host()
        .ok_or_else(|| "URL has no host".to_string())?
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // ServerName wants the bare host (IPv6 brackets stripped for
    // dialing/TLS, bracketed for the Host header).
    let dial_host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host)
        .to_string();

    // Resolve + (when enabled) SSRF-check at connect time, then dial
    // the first address that accepts (DNS rebinding mitigation: the
    // check runs against what we actually connect to).
    let addrs: Vec<std::net::SocketAddr> =
        std::net::ToSocketAddrs::to_socket_addrs(&(dial_host.as_str(), port))
            .map_err(|e| format!("DNS resolution failed: {e}"))?
            .collect();
    if ssrf.is_enabled() {
        for addr in &addrs {
            if let Err(reason) = ssrf.check(addr.ip()) {
                return Err(format!("SSRF egress filter rejected target: {reason}"));
            }
        }
    }
    let mut last_err = String::from("no addresses resolved");
    let mut stream: Option<TcpStream> = None;
    for addr in &addrs {
        // Never spend more of the budget on a connect than the budget
        // has left.
        let connect_budget =
            CONNECT_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        if connect_budget.is_zero() {
            return Err(deadline_detail());
        }
        match TcpStream::connect_timeout(addr, connect_budget) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let tcp = stream.ok_or_else(|| format!("connect failed: {last_err}"))?;
    tcp.set_nodelay(true).ok();
    tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();

    // TLS (rustls, sync): public roots, no client cert, HTTP/1.1 ALPN.
    let name = rustls::pki_types::ServerName::try_from(dial_host.clone())
        .map_err(|_| format!("host '{dial_host}' is not a usable TLS server name"))?;
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(webpki_root_store())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let req = format!(
        "GET {path_and_query} HTTP/1.1\r\nhost: {host_header}\r\n\
         user-agent: {USER_AGENT}\r\naccept: application/wasm, \
         application/octet-stream\r\nconnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .map_err(|e| format!("request write failed: {e}"))?;
    tls.flush()
        .map_err(|e| format!("request flush failed: {e}"))?;

    // Read to EOF (Connection: close), capped at head cap + artifact
    // cap and by the per-publish deadline: the per-read timeout below
    // is clamped to the budget's remainder and re-checked every
    // iteration, so a registry dripping one byte per read cannot reset
    // its way past the budget. A peer that closes without a TLS
    // close_notify (common for plain static hosts) surfaces as
    // UnexpectedEof/reset AFTER bytes arrived — treated as
    // end-of-stream; the framing parse below is what decides whether
    // the body is complete.
    let mut raw = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if raw.len() > MAX_HEAD_BYTES + MAX_ARTIFACT_BYTES {
            return Err(format!(
                "response exceeds the {} MiB artifact cap",
                MAX_ARTIFACT_BYTES / (1024 * 1024)
            ));
        }
        let remaining = deadline.checked_duration_since(Instant::now());
        let Some(remaining) = remaining else {
            return Err(deadline_detail());
        };
        // Per-read timeout, clamped to the remaining budget (the sock
        // is owned by the TLS stream now).
        tls.sock
            .set_read_timeout(Some(IO_TIMEOUT.min(remaining)))
            .ok();
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) && !raw.is_empty() =>
            {
                break;
            }
            Err(e) => return Err(format!("response read failed: {e}")),
        }
    }
    parse_response(&raw)
}

/// The step-naming detail for a budget exhaustion inside the fetch
/// (flows into `SourceError::DownloadFailed`).
fn deadline_detail() -> String {
    format!(
        "resolution deadline exceeded: the {}s per-publish budget for \
         registry source resolution ran out mid-download",
        RESOLUTION_BUDGET.as_secs()
    )
}

/// Parse a raw HTTP/1.1 response: status line, headers, body framing
/// (Content-Length, chunked, or read-to-EOF). Only 200 is accepted;
/// redirects are deliberately not followed (a registry behind a
/// redirect must be configured at its final URL — the same posture as
/// webhook deliveries). Public for the integration tests in
/// `tests/wasm_plugin_source.rs`, which pin the framing edge cases
/// (truncation, caps, hostile chunk sizes) as pure functions.
pub fn parse_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let Some(pos) = find_subslice(raw, b"\r\n\r\n") else {
        return Err("response head was not terminated (no blank line)".to_string());
    };
    if pos > MAX_HEAD_BYTES {
        return Err(format!(
            "response head exceeded the {MAX_HEAD_BYTES} byte cap"
        ));
    }
    let head = std::str::from_utf8(&raw[..pos])
        .map_err(|_| "response head is not valid UTF-8".to_string())?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "unparseable status line".to_string())?;
    if status != 200 {
        return Err(format!(
            "HTTP {status} (redirects are not followed; configure the \
             artifact's final URL)"
        ));
    }
    let body = &raw[pos + 4..];
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        } else if name == "content-length" {
            content_length = value.parse::<usize>().ok();
        }
    }
    if chunked {
        return decode_chunked(body);
    }
    if let Some(len) = content_length {
        // Cap before truncation so a short body with a hostile
        // over-cap Content-Length reports the cap, not a truncation.
        if len > MAX_ARTIFACT_BYTES {
            return Err(format!(
                "Content-Length {len} exceeds the {} MiB artifact cap",
                MAX_ARTIFACT_BYTES / (1024 * 1024)
            ));
        }
        if body.len() < len {
            return Err(format!(
                "truncated body: Content-Length says {len}, got {} bytes",
                body.len()
            ));
        }
        return Ok(body[..len].to_vec());
    }
    // No framing header: Connection: close read-to-EOF is the body.
    Ok(body.to_vec())
}

/// Minimal chunked transfer decoding (hex size; optional chunk
/// extensions after `;` ignored; final 0-chunk ends the body, trailers
/// after it are accepted and dropped). Public for the integration
/// tests in `tests/wasm_plugin_source.rs`, which pin the hostile
/// framings (overflow size lines, over-cap sizes, malformed hex,
/// missing CRLFs) as pure functions.
///
/// Hostile-input hardening (review finding): every size flows through
/// checked arithmetic. A size line like `ffffffffffffffff` used to
/// wrap `out.len() + size` past the cap check (and `size + 2` past
/// the truncation guard), reaching `&body[..size]` as a slice panic
/// that killed startup or unwound the reload watcher. Now the size
/// line must be 1-16 ASCII hex digits, the parsed size is rejected
/// outright above the artifact cap, and both additions are checked.
pub fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let cap_err = || {
        format!(
            "chunked body exceeds the {} MiB artifact cap",
            MAX_ARTIFACT_BYTES / (1024 * 1024)
        )
    };
    let mut out = Vec::new();
    loop {
        let Some(line_end) = find_subslice(body, b"\r\n") else {
            return Err("chunked body: missing chunk size line".to_string());
        };
        let line = std::str::from_utf8(&body[..line_end])
            .map_err(|_| "chunked body: size line is not valid UTF-8".to_string())?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        // Validate BEFORE parsing: 1-16 ASCII hex digits only, so the
        // parsed value can never be near usize::MAX.
        if size_str.is_empty()
            || size_str.len() > 16
            || !size_str.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(format!("chunked body: bad chunk size '{size_str}'"));
        }
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| format!("chunked body: bad chunk size '{size_str}'"))?;
        body = &body[line_end + 2..];
        if size == 0 {
            break; // trailers (if any) follow; ignored
        }
        // A single chunk over the cap is rejected outright; checked
        // adds below keep the aggregate cap check unskippable.
        if size > MAX_ARTIFACT_BYTES {
            return Err(cap_err());
        }
        let next_len = out.len().checked_add(size).ok_or_else(cap_err)?;
        if next_len > MAX_ARTIFACT_BYTES {
            return Err(cap_err());
        }
        let need = size
            .checked_add(2)
            .ok_or_else(|| "chunked body: truncated chunk".to_string())?;
        if body.len() < need {
            return Err("chunked body: truncated chunk".to_string());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[need..]; // skip the chunk's trailing CRLF
    }
    Ok(out)
}

/// Find `needle` in `haystack` (a tiny `windows().position()` helper;
/// `slice::windows` over the caps involved is fine at these sizes).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Public webpki root store for registry TLS verification. Local
/// re-statement of the same set the webhook client and the pooled
/// upstream connector default to (the wasm domain must not import
/// events/security for it; the roots are the identical public set).
fn webpki_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}
