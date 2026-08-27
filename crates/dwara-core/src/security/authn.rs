//! Request authentication (DW-019, feature analysis section 4.6).
//!
//! Three credential families behind one [`Authenticator`] trait:
//!
//! - **API keys**: `X-API-Key: <key>`. The lookup SELECTOR is
//!   `hex(sha256(key))` — never the plaintext key — and the stored hash is
//!   `sha256:<hex(sha256(key))>`, verified with a constant-time comparison
//!   (`subtle`). Optional memory-hard verification: a credential whose
//!   stored hash is a PHC string (`$argon2id$...`, admin-supplied through
//!   the state store) is verified with argon2id. Trade-off (documented
//!   choice): sha256+ct-compare is the pragmatic gateway standard — an
//!   argon2 verify is memory-hard and tens of milliseconds, far too slow
//!   for a per-request hot path, so config-declared keys are always hashed
//!   with sha256 at seed time and argon2id is opt-in per credential.
//! - **Basic**: `Authorization: Basic base64(user:pass)`. The username is
//!   the selector (`hex(sha256(user))`, the same selector space as API
//!   keys) and the password is verified against the stored hash through
//!   the SAME hashing path as API keys. Basic credentials therefore live
//!   in the state store (config declares API keys, not username/password
//!   pairs); the resolved identity is reported with kind `api_key`.
//!   REQUIREMENT: store-managed Basic credentials must store argon2id PHC
//!   strings (`$argon2id$...`) — a human-chosen password hashed with plain
//!   unsalted sha256 is offline-dictionary bait (see the hardening notes
//!   below). Note also that usernames remain enumerable: the selector is
//!   a deterministic hash of the username with no secret input, so an
//!   attacker with the store can confirm username guesses offline.
//! - **JWT**: `Authorization: Bearer <token>`, verified per
//!   [`JwtProvider`][crate::config::JwtProvider] config: JWKS fetched from
//!   the provider's URL, cached, refreshed after `refresh_secs` (the
//!   refresh happens BEFORE a stale cached set is used, so retired issuer
//!   keys cannot keep verifying forever; a failed refresh degrades to the
//!   cached keys, and a RECENTLY failed refresh backs off for
//!   `min(5s, refresh_secs)` — subsequent stale lookups skip the fetch
//!   and answer from the cache immediately, so a down/slow endpoint
//!   cannot chain every Bearer request through a serialized 5s fetch
//!   timeout) AND on an unknown `kid` (rotation: a fresh key id
//!   appearing mid-flight triggers a re-fetch and the token then verifies
//!   — no restart, no failure). Refresh-triggered (unknown-kid) fetches
//!   are throttled to one per `min(5s, refresh_secs)` — forged random-kid
//!   tokens cannot drive a JWKS fetch storm. `iss`/`aud`/`exp`/`nbf` are
//!   validated with `leeway_secs` skew tolerance; the algorithm allowlist
//!   (default RS256/ES256) is enforced BEFORE any signature work (`none`
//!   and `HS*` are asymmetric-confusion bait and never allowed).
//!
//! Accepted formats (composite dispatch on request shape):
//! `X-API-Key` wins over `Authorization`; within `Authorization`, `Basic`
//! and `Bearer` are distinguished by the scheme token. A gateway with NO
//! consumers and NO JWT providers has authentication disabled: the
//! authenticator resolves `Anonymous` for everything and `Authorization`
//! is forwarded upstream untouched (pass-through mode). Once ANY
//! credential is configured, the gateway INTERPRETS `Authorization` —
//! except that `Bearer` stays pass-through unless a JWT provider exists
//! (a gateway fronting an OAuth-protected upstream without its own JWT
//! config must keep forwarding tokens).
//!
//! Identity-to-consumer mapping: API keys and Basic map via the credential
//! record; JWTs map via the provider's `consumer` binding, or by matching
//! a consumer's `jwt` credential `issuer` (with audience containment when
//! the credential lists audiences) against the token's `iss`.
//!
//! Consumer-identity headers (spoof prevention): the proxy strips every
//! client-supplied `X-Consumer-*` header and injects a trusted
//! `X-Consumer-Name` upstream when authentication resolved a consumer —
//! see `proxy` (the strip/inject lives on the forward path).
//!
//! # Hardening notes (residual risks and the road to closing them)
//!
//! The stored-hash fast path is UNSALTED sha256, and the selector is
//! unsalted sha256 of the presented material. That is deliberate for
//! machine-generated config keys (constant-time, index-friendly, and a
//! search over the stored hashes is not a dictionary attack when the key
//! is 256 bits of entropy), but it leaves a residual offline-dictionary
//! risk for WEAK secrets: an attacker who exfiltrates the store can
//! brute-force low-entropy keys or passwords against the unsalted
//! selectors/hashes at sha256 speed, offline, and confirm username
//! guesses via the deterministic Basic selector. Mitigations in place:
//! the DB file is mode 0600, hashes/selectors are redacted from `Debug`,
//! and store-managed credentials may use argon2id PHC strings (REQUIRED
//! for Basic passwords). Before the store becomes the credential source
//! of truth for human-chosen secrets (a future `SecretSource` seam), the
//! stored hashes should be peppered/HMAC'd with a key held outside the
//! DB — an HMAC transform is still fast-path friendly and turns a DB
//! leak into a search that also needs the pepper.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hyper::header::HeaderMap;
use hyper::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use subtle::ConstantTimeEq;
use tower_service::Service;

use crate::config::credentials::{credential_selector, sha256_hex, sha256_stored_hash};
use crate::config::{Credential, Gateway, JwtProvider as JwtProviderConfig};
use crate::observability::Observability;
use crate::state::store::{CredentialKind, CredentialRecord, StateStore};

const X_API_KEY: hyper::header::HeaderName = hyper::header::HeaderName::from_static("x-api-key");

/// Upper bound on a JWKS response body (1 MiB): a key set is a few KiB;
/// anything larger is a misbehaving or hostile endpoint.
const JWKS_BODY_CAP: u64 = 1024 * 1024;

/// Connect timeout for JWKS fetches: key refresh is on the request path
/// (first token / rotation), so it must fail fast rather than hang a
/// client request for minutes.
const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The resolved caller identity of one request. `None` (from
/// [`Authenticator::authenticate`]) is Anonymous — no credential family
/// applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub consumer_name: String,
    pub credential_kind: CredentialKind,
    /// JWT only: a subset of the token's claims (string- and
    /// number-valued top-level claims, plus arrays of strings flattened
    /// to their space-separated form — the OAuth `scope` convention,
    /// DW-020 — capped at 32 entries). Never contains the raw token.
    pub claims: BTreeMap<String, String>,
}

/// Authentication failure. `Invalid` is a caller-side problem (401);
/// `Unavailable` is a gateway-side problem (500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Invalid(&'static str),
    Unavailable(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Invalid(m) => write!(f, "invalid credentials: {m}"),
            AuthError::Unavailable(m) => write!(f, "authentication unavailable: {m}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// One pluggable authenticator (dyn-compatible seam). `Ok(None)` is
/// Anonymous; `Err(AuthError::Invalid(..))` means a credential was
/// PRESENTED and rejected.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Option<Identity>, AuthError>;

    /// The `WWW-Authenticate` challenge value for 401 responses, built
    /// from the schemes this authenticator actually interprets.
    fn challenge(&self) -> String;
}

// --- hashing ---------------------------------------------------------------
//
// The selector/stored-hash FORMATS live in `config::credentials` (part of
// the credential schema contract shared with the state store); this
// module re-imports them and owns the VERIFICATION path below.

/// Verify a presented secret against a stored hash, in constant time for
/// the sha256 path (`subtle::ConstantTimeEq` over the encoded digests —
/// comparing hex strings byte-wise is length-equal and timing-uniform).
/// Supported formats: `sha256:<hex>` and PHC argon2id strings
/// (`$argon2id$...`). Unknown formats verify false (never accept).
///
/// Public for testing the stored-hash verification contract.
pub fn verify_secret(stored_hash: &str, presented: &str) -> bool {
    if let Some(hexdigest) = stored_hash.strip_prefix("sha256:") {
        if hexdigest.len() != 64 || !hexdigest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        let computed = sha256_hex(presented.as_bytes());
        // Compare the ASCII encodings: both are fixed 64-byte buffers of
        // hex digits, so ct_eq is well-defined and length-matched.
        return computed.as_bytes().ct_eq(hexdigest.as_bytes()).into();
    }
    if stored_hash.starts_with("$argon2") {
        let parsed = argon2::PasswordHash::new(stored_hash);
        let Ok(parsed) = parsed else { return false };
        let alg = argon2::Argon2::default();
        use argon2::PasswordVerifier as _;
        return alg.verify_password(presented.as_bytes(), &parsed).is_ok();
    }
    false
}

// --- credential registry ---------------------------------------------------

/// One verifiable credential as the authenticator sees it.
#[derive(Debug, Clone)]
pub struct KnownCredential {
    pub consumer_name: String,
    pub kind: CredentialKind,
    pub hash: String,
}

impl From<&CredentialRecord> for KnownCredential {
    fn from(r: &CredentialRecord) -> Self {
        KnownCredential {
            consumer_name: r.consumer_name.clone(),
            kind: r.kind,
            hash: r.hash.clone(),
        }
    }
}

/// Where credential records come from: the state store (hot-cached; the
/// `DWARA_STATE_DB` deployment) or config consumers hashed in-memory at
/// startup. Both paths unify behind one lookup API (a private
/// selector-keyed search shared by the API-key and Basic paths).
pub enum CredentialRegistry {
    Store(Arc<StateStore>),
    Config(HashMap<String, Arc<Vec<KnownCredential>>>),
}

impl CredentialRegistry {
    /// Build the config-only registry: every consumer's API-key credential
    /// is hashed at startup (the config value is then dropped; the
    /// registry holds only selectors and hashes).
    pub fn from_config(gateway: &Gateway) -> Self {
        let mut map: HashMap<String, Arc<Vec<KnownCredential>>> = HashMap::new();
        for consumer in &gateway.consumers {
            for credential in &consumer.credentials {
                if let Credential::ApiKey { key } = credential {
                    if key.is_empty() {
                        continue;
                    }
                    let selector = credential_selector(key);
                    let entry = Arc::make_mut(map.entry(selector).or_default());
                    entry.push(KnownCredential {
                        consumer_name: consumer.name.clone(),
                        kind: CredentialKind::ApiKey,
                        hash: sha256_stored_hash(key),
                    });
                }
            }
        }
        CredentialRegistry::Config(map)
    }

    /// Look up the active credentials for a selector (hash of the
    /// presented material — never plaintext).
    async fn lookup(&self, selector: &str) -> Result<Vec<KnownCredential>, AuthError> {
        match self {
            CredentialRegistry::Store(store) => {
                let entry = store
                    .lookup_credential(selector)
                    .map_err(|e| AuthError::Unavailable(e.to_string()))?;
                let entry = entry.unwrap_or_default();
                Ok(entry
                    .iter()
                    .map(|r| KnownCredential::from(r.as_ref()))
                    .collect())
            }
            CredentialRegistry::Config(map) => Ok(map
                .get(selector)
                .map(|v| v.as_ref().clone())
                .unwrap_or_default()),
        }
    }
}

// --- JWKS fetching ---------------------------------------------------------

/// A connection that is either plaintext TCP or TLS: the single response
/// type of [`JwksConnector`] for `http://` and `https://` JWKS URLs.
/// `WithHyperIo` adapts a tokio stream to BOTH hyper's runtime IO traits
/// and tokio's, which is exactly what the tokio-rustls 0.26 connect bound
/// and the hyper legacy client's pool each ask for.
enum MaybeTls {
    Plain(hyper_util::rt::tokio::WithHyperIo<tokio::net::TcpStream>),
    Tls(
        Box<
            tokio_rustls::client::TlsStream<
                hyper_util::rt::tokio::WithHyperIo<tokio::net::TcpStream>,
            >,
        >,
    ),
}

impl tokio::io::AsyncRead for MaybeTls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeTls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for MaybeTls {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

/// Plain-or-TLS connector for one-shot JWKS GETs (hyper-util legacy
/// client plumbing; reuses the workspace rustls stack, no new HTTP
/// dependency). Trust defaults to the webpki public roots; a provider's
/// `trusted_ca_file` (#121) replaces them so an https JWKS endpoint
/// behind a private CA is fetchable — the same trust model the upstream
/// connector gives `trusted_ca_file` upstreams.
#[derive(Clone)]
struct JwksConnector {
    http: hyper_util::client::legacy::connect::HttpConnector,
    tls: tokio_rustls::TlsConnector,
}

impl JwksConnector {
    /// `trusted_ca` is the provider's `trusted_ca_file` path when set.
    /// Fails when the bundle cannot be loaded/parsed, so the provider is
    /// disabled at build time (see `CompositeAuthenticator::build`)
    /// instead of failing every fetch at request time.
    fn new(trusted_ca: Option<&str>) -> Result<Self, AuthError> {
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false); // scheme routing happens here
        let roots = match trusted_ca {
            Some(path) => crate::security::tls::root_store_from_pem_file(path).map_err(|e| {
                AuthError::Unavailable(format!("trusted_ca_file '{path}' could not be loaded: {e}"))
            })?,
            None => crate::security::tls::webpki_root_store(),
        };
        let cfg = crate::security::tls::https_h1_client_config(roots);
        Ok(JwksConnector {
            http,
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
        })
    }
}

impl Service<Uri> for JwksConnector {
    type Response = hyper_util::rt::TokioIo<MaybeTls>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(std::io::Error::other)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| std::io::Error::other("jwks url has no host"))?
                .to_string();
            let stream = tokio::time::timeout(JWKS_CONNECT_TIMEOUT, http.call(uri.clone()))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "jwks connect timed out")
                })?
                .map_err(std::io::Error::other)?
                // The HttpConnector hands back a TokioIo<TcpStream>; unwrap to
                // the raw stream and re-adapt with WithHyperIo (which satisfies
                // BOTH tokio's and hyper's IO traits) so the tls branch and the
                // plaintext branch share one adaptable stream type.
                .into_inner();
            match uri.scheme_str() {
                Some("https") => {
                    // rustls requires a DNS ServerName; IPs and anything
                    // else fail the handshake (documented: JWKS endpoints
                    // are named services).
                    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
                        .map_err(|e| {
                            std::io::Error::other(format!("jwks host is not a valid tls name: {e}"))
                        })?;
                    let tls_stream = tokio::time::timeout(
                        JWKS_CONNECT_TIMEOUT,
                        tls.connect(name, hyper_util::rt::tokio::WithHyperIo::new(stream)),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "jwks tls handshake timed out",
                        )
                    })??;
                    Ok(hyper_util::rt::TokioIo::new(MaybeTls::Tls(Box::new(
                        tls_stream,
                    ))))
                }
                // http:// JWKS: plaintext.
                _ => Ok(hyper_util::rt::TokioIo::new(MaybeTls::Plain(
                    hyper_util::rt::tokio::WithHyperIo::new(stream),
                ))),
            }
        })
    }
}

/// Shared JWKS cache for one provider URL: the cached key set plus the
/// refresh bookkeeping. Entries live on the dataplane keyed by URL, so a
/// config reload reuses the cache (rotation state survives reloads).
pub struct JwksCacheEntry {
    keys: RwLock<Arc<JwkSet>>,
    last_refresh: RwLock<Instant>,
    /// When the last refresh-triggered (unknown-kid) fetch started.
    /// Unknown-kid fetches are refused for a minimum spacing afterwards
    /// (see [`JwtVerifier::key_for`]) so forged random-kid tokens cannot
    /// drive a fetch-per-request storm.
    last_forced_refresh: RwLock<Option<Instant>>,
    /// When the last refresh FAILED. While this is within
    /// `min(5s, refresh_secs)`, stale-path refresh attempts skip the
    /// fetch entirely and fall through to the cached keys (see
    /// [`JwtVerifier::key_for`]): with a down/slow endpoint, every Bearer
    /// request would otherwise pay a fetch attempt serialized on
    /// `refresh_lock` (5s connect timeout each), chaining concurrent
    /// traffic through queued timeouts. A successful refresh clears it.
    last_failed_refresh: RwLock<Option<Instant>>,
    /// Serializes refreshes; concurrent unknown-kid misses coalesce into
    /// one fetch.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl JwksCacheEntry {
    fn new() -> Self {
        JwksCacheEntry {
            keys: RwLock::new(Arc::new(JwkSet { keys: Vec::new() })),
            last_refresh: RwLock::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(86400))
                    .unwrap_or(Instant::now()),
            ),
            last_forced_refresh: RwLock::new(None),
            last_failed_refresh: RwLock::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }
}

/// One configured JWT provider at runtime: config + HTTP client + cache.
pub struct JwtVerifier {
    cfg: JwtProviderConfig,
    algorithms: Vec<Algorithm>,
    http: Client<JwksConnector, http_body_util::Full<bytes::Bytes>>,
    cache: Arc<JwksCacheEntry>,
    /// jwks_refresh_total{provider} child (DW-021), incremented on every
    /// JWKS fetch attempt (stale-path and rotation-triggered alike).
    jwks_refresh: Option<prometheus::IntCounter>,
}

impl JwtVerifier {
    fn build(
        cfg: JwtProviderConfig,
        cache: Arc<JwksCacheEntry>,
        obs: Option<&Observability>,
    ) -> Result<Self, AuthError> {
        let algorithms = parse_algorithms(&cfg.algorithms).ok_or_else(|| {
            AuthError::Unavailable(format!(
                "jwt provider '{}' lists an unsupported or disallowed algorithm",
                cfg.name
            ))
        })?;
        let jwks_refresh = obs.map(|o| o.jwks_refresh_counter(cfg.name.as_str()));
        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_timer(TokioTimer::new());
        // #121: the provider's trusted_ca_file (private-CA JWKS
        // endpoints) feeds the fetcher's TLS trust; a broken bundle
        // disables this provider (see CompositeAuthenticator::build)
        // rather than breaking every Bearer request with a fetch
        // failure. Built before the struct so `cfg` is not yet moved.
        let connector = JwksConnector::new(cfg.trusted_ca_file.as_deref())?;
        Ok(JwtVerifier {
            cfg,
            algorithms,
            http: builder.build(connector),
            cache,
            jwks_refresh,
        })
    }

    async fn fetch(&self) -> Result<Arc<JwkSet>, AuthError> {
        // Every fetch (stale-path or rotation-triggered) counts in the
        // jwks_refresh_total metric (DW-021) — attempts, not successes, so
        // a flapping endpoint is visible.
        if let Some(counter) = &self.jwks_refresh {
            counter.inc();
        }
        // Record the outcome for the stale-path failed-refresh backoff: a
        // failed fetch arms it, a successful one clears it (see
        // [`JwksCacheEntry::last_failed_refresh`]).
        let result = self.fetch_once().await;
        match &result {
            Ok(_) => {
                *self
                    .cache
                    .last_failed_refresh
                    .write()
                    .expect("jwks cache poisoned") = None;
            }
            Err(_) => {
                *self
                    .cache
                    .last_failed_refresh
                    .write()
                    .expect("jwks cache poisoned") = Some(Instant::now());
            }
        }
        result
    }

    async fn fetch_once(&self) -> Result<Arc<JwkSet>, AuthError> {
        let uri: Uri = self
            .cfg
            .jwks_url
            .parse()
            .map_err(|e| AuthError::Unavailable(format!("jwks url is invalid: {e}")))?;
        let req = hyper::Request::builder()
            .uri(uri)
            .method(hyper::Method::GET)
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(|e| AuthError::Unavailable(format!("jwks request build failed: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| AuthError::Unavailable(format!("jwks fetch failed: {e:#}")))?;
        if !resp.status().is_success() {
            return Err(AuthError::Unavailable(format!(
                "jwks endpoint answered {}",
                resp.status()
            )));
        }
        // `Limited` enforces the body cap DURING streaming, so an
        // oversized (hostile) key set fails mid-read instead of being
        // buffered whole first.
        let body = http_body_util::BodyExt::collect(http_body_util::Limited::new(
            resp.into_body(),
            JWKS_BODY_CAP as usize,
        ))
        .await
        .map_err(|e| AuthError::Unavailable(format!("jwks body read failed: {e}")))?;
        let body = body.to_bytes();
        let set: JwkSet = serde_json::from_slice(&body)
            .map_err(|e| AuthError::Unavailable(format!("jwks body is not a jwk set: {e}")))?;
        let set = Arc::new(set);
        *self.cache.keys.write().expect("jwks cache poisoned") = Arc::clone(&set);
        *self
            .cache
            .last_refresh
            .write()
            .expect("jwks cache poisoned") = Instant::now();
        Ok(set)
    }

    /// Find the JWK for `kid`/`alg`, refreshing when the cache is stale or
    /// the kid is unknown (rotation). Refreshes are serialized; a caller
    /// that lost the refresh race re-checks the freshly cached set.
    ///
    /// ## Stale caches refresh BEFORE use
    ///
    /// Once the cache age exceeds `refresh_secs`, the next key lookup
    /// refreshes under the lock BEFORE serving a cached key: a stale set
    /// must not keep verifying a retired issuer key indefinitely. If that
    /// refresh FAILS, the cached keys keep serving (documented degradation
    /// — an endpoint disturbance is not an immediate outage), except when
    /// the cache is empty (nothing to degrade to: `Unavailable`).
    ///
    /// ## Failed stale refreshes back off
    ///
    /// A FAILED stale-path refresh arms a backoff: for the next
    /// `min(5s, refresh_secs)`, stale-path lookups skip the fetch entirely
    /// and answer from the cached keys immediately. Without this, a
    /// down/slow JWKS endpoint would make EVERY Bearer request pay a fetch
    /// attempt serialized on the refresh lock (a 5s connect timeout each),
    /// chaining concurrent traffic through queued timeouts. A successful
    /// refresh clears the backoff; an EMPTY cache never backs off (there
    /// is nothing to degrade to, so the `Unavailable` error surfaces).
    ///
    /// ## Unknown-kid refreshes are throttled
    ///
    /// A fresh cache with an unknown `kid` triggers one deliberate
    /// rotation fetch — and then NO further refresh-triggered fetches for
    /// `min(5s, refresh_secs)`: subsequent unknown-kid requests answer 401
    /// from the (freshly fetched) cached set. Forged random-kid tokens
    /// therefore buy at most one JWKS fetch per window and cannot drive a
    /// fetch storm through the serialized refresh lock (which would stall
    /// all Bearer traffic). One genuine rotation flip still pays at most
    /// one fetch — the flip's own request performs it. The AGE-based
    /// refresh above is deliberately NOT throttled: it fires at most once
    /// per `refresh_secs` by construction.
    async fn key_for(&self, kid: Option<&str>, alg: Algorithm) -> Result<Jwk, AuthError> {
        let stale_after = Duration::from_secs(self.cfg.refresh_secs.max(1));
        let forced_min_interval = JWKS_FORCED_REFRESH_MIN_INTERVAL.min(stale_after);
        let fresh = {
            let keys = self.cache.keys.read().expect("jwks cache poisoned");
            let last = *self.cache.last_refresh.read().expect("jwks cache poisoned");
            if last.elapsed() < stale_after {
                if let Some(jwk) = find_jwk(&keys, kid, alg) {
                    return Ok(jwk.clone());
                }
            }
            last.elapsed() < stale_after
        };
        let _guard = self.cache.refresh_lock.lock().await;
        if !fresh {
            // Cache age exceeded refresh_secs: refresh BEFORE serving the
            // cached key (a stale set must not keep verifying retired
            // issuer keys forever). Failure degrades to the cached set
            // unless there is nothing cached to serve.
            let still_stale = {
                let last = *self.cache.last_refresh.read().expect("jwks cache poisoned");
                last.elapsed() >= stale_after
            };
            if still_stale {
                let cached_nonempty = !self
                    .cache
                    .keys
                    .read()
                    .expect("jwks cache poisoned")
                    .keys
                    .is_empty();
                // Failed-refresh backoff: when the previous refresh failed
                // recently and there ARE cached keys to degrade to, skip
                // the fetch — answer from the cache immediately instead of
                // chaining every Bearer request through a doomed fetch
                // attempt (5s connect timeout each) on the refresh lock.
                let in_failure_backoff = cached_nonempty && {
                    let failed = *self
                        .cache
                        .last_failed_refresh
                        .read()
                        .expect("jwks cache poisoned");
                    failed.is_some_and(|t| t.elapsed() < forced_min_interval)
                };
                if !in_failure_backoff {
                    match self.fetch().await {
                        Ok(set) => {
                            return find_jwk(&set, kid, alg)
                                .cloned()
                                .ok_or(AuthError::Invalid("token key id is unknown"));
                        }
                        Err(e) => {
                            if !cached_nonempty {
                                return Err(e);
                            }
                            // Degraded mode: fall through to the cached set.
                        }
                    }
                }
            }
            let keys = self.cache.keys.read().expect("jwks cache poisoned");
            return find_jwk(&keys, kid, alg)
                .cloned()
                .ok_or(AuthError::Invalid("token key id is unknown"));
        }
        // Fresh cache, unknown kid: the rotation path. Re-check the cached
        // set under the lock first — a concurrent request's fetch may have
        // already delivered our kid.
        {
            let keys = self.cache.keys.read().expect("jwks cache poisoned");
            if let Some(jwk) = find_jwk(&keys, kid, alg) {
                return Ok(jwk.clone());
            }
        }
        // Claim the throttle
        // window BEFORE fetching so a failed fetch also spends it (the
        // endpoint saw the traffic either way).
        let eligible = {
            let mut last = self
                .cache
                .last_forced_refresh
                .write()
                .expect("jwks cache poisoned");
            match *last {
                Some(t) if t.elapsed() < forced_min_interval => false,
                _ => {
                    *last = Some(Instant::now());
                    true
                }
            }
        };
        if !eligible {
            // Refused for the throttle window: answer 401 from the cached
            // set without touching the JWKS endpoint.
            return Err(AuthError::Invalid("token key id is unknown"));
        }
        let set = self.fetch().await?;
        find_jwk(&set, kid, alg)
            .cloned()
            .ok_or(AuthError::Invalid("token key id is unknown"))
    }
}

fn find_jwk<'a>(set: &'a JwkSet, kid: Option<&str>, alg: Algorithm) -> Option<&'a Jwk> {
    let family = algorithm_family(alg);
    set.keys
        .iter()
        .filter(|k| match kid {
            Some(id) => k.common.key_id.as_deref() == Some(id),
            None => true,
        })
        // Family filter (defense against a mixed set): RSA keys answer
        // RS*/PS*, EC keys answer ES*, OKP answers Ed*.
        .find(|k| {
            matches!(
                (&k.algorithm, family.as_str()),
                (AlgorithmParameters::RSA(_), "RS" | "PS")
                    | (AlgorithmParameters::EllipticCurve(_), "ES")
                    | (AlgorithmParameters::OctetKeyPair(_), "Ed")
            )
        })
}

/// The JWK key family an algorithm verifies with ("RS", "ES", "Ed", ...).
fn algorithm_family(alg: Algorithm) -> String {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => "HS".into(),
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => "RS".into(),
        Algorithm::ES256 | Algorithm::ES384 => "ES".into(),
        Algorithm::EdDSA => "Ed".into(),
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => "PS".into(),
    }
}

/// Public for testing the JWT algorithm-allowlist contract.
pub fn parse_algorithms(names: &[String]) -> Option<Vec<Algorithm>> {
    use std::str::FromStr as _;
    if names.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let alg = match name.to_ascii_uppercase().as_str() {
            "HS256" | "HS384" | "HS512" | "NONE" => {
                // Asymmetric verification only: symmetric algorithms would
                // make the gateway a shared-secret holder and enable
                // alg-confusion downgrade; "none" is never a choice.
                return None;
            }
            other => Algorithm::from_str(other).ok()?,
        };
        out.push(alg);
    }
    Some(out)
}

// --- composite -------------------------------------------------------------

/// Upper bound on the spacing between refresh-triggered (unknown-kid)
/// JWKS fetches, before rate limiting or any other control: a forged
/// token with a random `kid` must never buy the attacker a JWKS fetch.
/// The effective window is `min(5s, refresh_secs)` so a tight refresh
/// cadence tightens the throttle too.
const JWKS_FORCED_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// The gateway's single authenticator: dispatches on the request's
/// credential shape (X-API-Key / Basic / Bearer) and consults the
/// credential registry plus the configured JWT providers.
pub struct CompositeAuthenticator {
    registry: CredentialRegistry,
    jwt: Vec<Arc<JwtVerifier>>,
    /// issuer -> (consumer name, audiences) from consumers' jwt
    /// credentials: the claims-based consumer mapping for tokens whose
    /// provider has no explicit `consumer` binding.
    jwt_consumer_index: HashMap<String, (String, Vec<String>)>,
    /// Whether ANY credential family is active; when false the composite
    /// is a no-op (pass-through mode).
    enabled: bool,
}

impl CompositeAuthenticator {
    /// The disabled authenticator: no registry, no providers, anonymous
    /// for everything (pass-through mode). The dataplane's placeholder
    /// before [`Self::build`] runs.
    pub fn disabled() -> Self {
        CompositeAuthenticator {
            registry: CredentialRegistry::Config(HashMap::new()),
            jwt: Vec::new(),
            jwt_consumer_index: HashMap::new(),
            enabled: false,
        }
    }
    /// Build from one config generation. `store` is the DWARA_STATE_DB
    /// store when deployed; without it credentials come from config,
    /// hashed in-memory. `jwks_caches` carries JWKS cache entries ACROSS
    /// rebuilds (keyed by URL) so reloads keep rotation state.
    pub fn build(
        gateway: &Gateway,
        store: Option<Arc<StateStore>>,
        jwks_caches: &mut HashMap<String, Arc<JwksCacheEntry>>,
        obs: Option<&Observability>,
    ) -> Arc<Self> {
        let registry = match store {
            Some(store) => CredentialRegistry::Store(store),
            None => CredentialRegistry::from_config(gateway),
        };
        let mut jwt = Vec::new();
        for cfg in &gateway.jwt_providers {
            let cache = jwks_caches
                .entry(cfg.jwks_url.clone())
                .or_insert_with(|| Arc::new(JwksCacheEntry::new()))
                .clone();
            match JwtVerifier::build(cfg.clone(), cache, obs) {
                Ok(v) => jwt.push(Arc::new(v)),
                Err(e) => {
                    tracing::error!(code = "jwt_provider_disabled", "jwt provider disabled: {e}")
                }
            }
        }
        let mut jwt_consumer_index = HashMap::new();
        for consumer in &gateway.consumers {
            for credential in &consumer.credentials {
                if let Credential::Jwt { issuer, audiences } = credential {
                    jwt_consumer_index
                        .insert(issuer.clone(), (consumer.name.clone(), audiences.clone()));
                }
            }
        }
        let enabled = !gateway.consumers.is_empty() || !jwt.is_empty();
        Arc::new(CompositeAuthenticator {
            registry,
            jwt,
            jwt_consumer_index,
            enabled,
        })
    }

    async fn authenticate_api_key_or_basic(
        &self,
        selector: &str,
        presented_secret: &str,
    ) -> Result<Option<Identity>, AuthError> {
        let candidates = self.registry.lookup(selector).await?;
        for cred in &candidates {
            if cred.kind != CredentialKind::ApiKey {
                continue;
            }
            if verify_secret(&cred.hash, presented_secret) {
                return Ok(Some(Identity {
                    consumer_name: cred.consumer_name.clone(),
                    credential_kind: CredentialKind::ApiKey,
                    claims: BTreeMap::new(),
                }));
            }
        }
        Err(AuthError::Invalid("unknown api key or basic credentials"))
    }

    async fn authenticate_jwt(&self, token: &str) -> Result<Option<Identity>, AuthError> {
        if self.jwt.is_empty() {
            // No provider configured: Bearer stays pass-through.
            return Ok(None);
        }
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| AuthError::Invalid("token header is malformed"))?;
        let kid = header.kid.as_deref();
        let mut last_invalid = AuthError::Invalid("token did not verify");
        let mut unavailable: Option<AuthError> = None;
        for verifier in &self.jwt {
            if !verifier.algorithms.contains(&header.alg) {
                last_invalid = AuthError::Invalid("token algorithm is not allowed");
                continue;
            }
            match self.verify_with(verifier, token, &header, kid).await {
                Ok(identity) => return Ok(Some(identity)),
                Err(e @ AuthError::Invalid(_)) => last_invalid = e,
                Err(e @ AuthError::Unavailable(_)) => unavailable = Some(e),
            }
        }
        // Error masking: when EVERY provider failed, a 401 ("invalid
        // token") would hide that one of them was down. If any provider
        // was Unavailable, surface the gateway-side failure (500-class)
        // so operators see it instead of a wall of caller-side 401s.
        if let Some(e) = unavailable {
            return Err(e);
        }
        Err(last_invalid)
    }

    async fn verify_with(
        &self,
        verifier: &JwtVerifier,
        token: &str,
        header: &Header,
        kid: Option<&str>,
    ) -> Result<Identity, AuthError> {
        let jwk = verifier.key_for(kid, header.alg).await?;
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|_| AuthError::Invalid("jwk is not usable for this token"))?;
        // Asymmetric sanity: the JWK must actually be an asymmetric key
        // (RSA/EC/OKP) — a symmetric key in the set paired with an
        // allowed algorithm is a configuration error, not a secret.
        if !matches!(
            jwk.algorithm,
            AlgorithmParameters::RSA(_)
                | AlgorithmParameters::EllipticCurve(_)
                | AlgorithmParameters::OctetKeyPair(_)
        ) {
            return Err(AuthError::Invalid("jwk is not an asymmetric key"));
        }
        let mut validation = Validation::new(header.alg);
        validation.leeway = verifier.cfg.leeway_secs;
        if let Some(iss) = &verifier.cfg.issuer {
            validation.iss = Some(std::iter::once(iss.clone()).collect());
        }
        if let Some(aud) = &verifier.cfg.audience {
            validation.aud = Some(std::iter::once(aud.clone()).collect());
        }
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
            .map_err(|_| AuthError::Invalid("token failed verification"))?;
        let claims = &data.claims;
        // Consumer mapping: explicit provider binding first, then the
        // consumers' jwt-credential issuer index (with audience
        // containment when the credential lists audiences).
        let consumer_name = match &verifier.cfg.consumer {
            Some(name) => name.clone(),
            None => {
                let iss = claims
                    .get("iss")
                    .and_then(|v| v.as_str())
                    .ok_or(AuthError::Invalid("token has no string iss claim"))?;
                let (name, audiences) = self.jwt_consumer_index.get(iss).ok_or(
                    AuthError::Invalid("token issuer is not bound to a consumer"),
                )?;
                if !audiences.is_empty() {
                    let aud_matches = match claims.get("aud") {
                        Some(serde_json::Value::String(a)) => audiences.iter().any(|w| w == a),
                        Some(serde_json::Value::Array(a)) => a
                            .iter()
                            .filter_map(|v| v.as_str())
                            .any(|v| audiences.iter().any(|w| w == v)),
                        _ => false,
                    };
                    if !aud_matches {
                        return Err(AuthError::Invalid(
                            "token audience does not match the consumer binding",
                        ));
                    }
                }
                name.clone()
            }
        };
        let mut identity_claims = BTreeMap::new();
        if let Some(map) = claims.as_object() {
            for (k, v) in map {
                if identity_claims.len() >= 32 {
                    break;
                }
                match v {
                    serde_json::Value::String(s) => {
                        identity_claims.insert(k.clone(), s.clone());
                    }
                    serde_json::Value::Number(n) => {
                        identity_claims.insert(k.clone(), n.to_string());
                    }
                    // Array-of-strings claims are flattened to their
                    // space-separated form (the OAuth `scope` convention,
                    // which authorization's required_scopes matches either
                    // way — DW-020). NOTE: the map stores the flattened
                    // string, so ANY future consumer of identity claims
                    // sees arrays as space-joined strings, never as lists.
                    // Arrays holding non-strings are dropped, like every
                    // other non-scalar claim.
                    serde_json::Value::Array(a)
                        if !a.is_empty() && a.iter().all(|v| v.is_string()) =>
                    {
                        identity_claims.insert(
                            k.clone(),
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                    _ => {}
                }
            }
        }
        Ok(Identity {
            consumer_name,
            credential_kind: CredentialKind::Jwt,
            claims: identity_claims,
        })
    }
}

#[async_trait]
impl Authenticator for CompositeAuthenticator {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Option<Identity>, AuthError> {
        if !self.enabled {
            return Ok(None);
        }
        if let Some(key) = headers.get(&X_API_KEY).and_then(|v| v.to_str().ok()) {
            if key.is_empty() {
                return Err(AuthError::Invalid("empty api key"));
            }
            return self
                .authenticate_api_key_or_basic(&credential_selector(key), key)
                .await;
        }
        if let Some(value) = headers
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let (scheme, rest) = value.split_once(' ').unwrap_or((value, ""));
            if scheme.eq_ignore_ascii_case("basic") {
                let decoded = BASE64
                    .decode(rest.trim())
                    .map_err(|_| AuthError::Invalid("basic credentials are not valid base64"))?;
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| AuthError::Invalid("basic credentials are not utf-8"))?;
                let (user, pass) = decoded
                    .split_once(':')
                    .ok_or(AuthError::Invalid("basic credentials lack a ':' separator"))?;
                if user.is_empty() || pass.is_empty() {
                    return Err(AuthError::Invalid("basic credentials are empty"));
                }
                return self
                    .authenticate_api_key_or_basic(&credential_selector(user), pass)
                    .await;
            }
            if scheme.eq_ignore_ascii_case("bearer") {
                if rest.trim().is_empty() {
                    return Err(AuthError::Invalid("empty bearer token"));
                }
                return self.authenticate_jwt(rest.trim()).await;
            }
        }
        Ok(None)
    }

    fn challenge(&self) -> String {
        let mut parts = Vec::new();
        match &self.registry {
            CredentialRegistry::Config(m) if m.is_empty() => {}
            // The store path may hold credentials regardless of config,
            // so it conservatively offers the Basic challenge.
            CredentialRegistry::Store(_) | CredentialRegistry::Config(_) => {
                parts.push("Basic realm=\"dwara\"".to_string());
            }
        }
        if !self.jwt.is_empty() {
            parts.push("Bearer".to_string());
        }
        if parts.is_empty() {
            "Bearer".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Whether the gateway treats `X-Consumer-*` request headers as spoof
/// material: always — the proxy strips them and injects its own.
pub const CONSUMER_HEADER_PREFIX: &str = "x-consumer-";

/// The trusted consumer-identity header the gateway injects upstream.
pub const X_CONSUMER_NAME: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-consumer-name");
