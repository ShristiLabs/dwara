//! OpenID Connect: discovery, token introspection, revocation, token
//! exchange, and the authorization-code + PKCE relying-party flow
//! (DW-034).
//!
//! The gateway acts as an OIDC client (relying party) for two distinct
//! purposes:
//!
//! 1. **Token introspection (RFC 7662)** — on the request path, a
//!    presented `Authorization: Bearer` token that did not verify
//!    against any JWT provider (DW-019) is introspected against the
//!    configured OIDC provider's introspection endpoint. An `active:
//!    true` result resolves an `Identity`; `active: false` (or a
//!    non-2xx) is a 401. Introspection results are cached keyed by the
//!    token's SHA-256 hash with a configurable TTL — a cached `active:
//!    true` short-circuits the IdP call, while a cached `active: false`
//!    is NOT cached (re-checked on the next request so a revoked token
//!    is noticed promptly).
//! 2. **Authorization-code + PKCE (RFC 6749 section 4.1 + RFC 7636)** —
//!    the user-facing login flow: the gateway redirects an
//!    unauthenticated request to the IdP's authorization endpoint with
//!    a PKCE code challenge, handles the callback, and exchanges the
//!    code for access/refresh/ID tokens. This is the relying-party
//!    role; the resulting tokens are stored in a session cookie.
//!
//! Two management operations round out the flow:
//!
//! - **Token revocation (RFC 7009)** — POST to the revocation endpoint
//!   to revoke a token. An admin/CLI operation, not on the hot request
//!   path.
//! - **Token exchange (RFC 8693)** — exchange a subject token (the
//!   client's bearer token) for an actor token for an upstream, using
//!   the `urn:ietf:params:oauth:grant-type:token-exchange` grant type.
//!   This extends the OAuth2 client-credentials proxying pattern
//!   (DW-035).
//!
//! ## Discovery
//!
//! The provider's discovery document is fetched from
//! `{issuer}/.well-known/openid-configuration` (RFC 8414 / OIDC
//! Discovery 1.0) and cached for the provider's lifetime (it rarely
//! changes). The document supplies the introspection, revocation,
//! authorization, and token endpoints; config-level overrides
//! (`introspection_endpoint`, `revocation_endpoint`) take precedence
//! over the discovered values.
//!
//! ## HTTP
//!
//! All IdP HTTP calls use the `OidcConnector` (plain-or-TLS, the
//! `JwksConnector`/`OAuth2Connector` pattern), reusing the workspace
//! rustls stack with no new HTTP dependencies. A `trusted_ca_file`
//! replaces the webpki public roots for an IdP behind a private CA
//! (the same trust model as `JwtProvider::trusted_ca_file`).
//!
//! ## Error posture
//!
//! An introspection failure (network error, non-2xx, malformed
//! response) is governed by the provider's `fail_open` config: default
//! false (fail closed = 401, the gateway refuses to authenticate a
//! token it cannot introspect); true treats the failure as anonymous
//! (pass-through). Fail-open trades security for availability. The
//! error envelope never leaks the IdP's response body or headers.
//!
//! ## Caching
//!
//! The introspection cache ([`OidcIntrospectionCache`]) lives on the
//! dataplane (carried across generation swaps, the `jwks_caches` /
//! `oauth2_token_cache` precedent) so a config reload never discards a
//! cached `active: true` result. Entries are keyed by
//! `{provider_name}:{sha256_hex(token)}` and expire after
//! `introspection_cache_ttl_s`. The discovery document is cached
//! per-provider on the [`OidcClient`] (rebuilt per generation, like
//! `OAuth2Client`).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::connect::{Connected, Connection as HyperConnection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use tower_service::Service;

use crate::config::OidcProvider;

/// Connect timeout for IdP HTTP calls: discovery, introspection, and
/// token exchange are on the request path (first request / cache miss),
/// so they must fail fast rather than hang a client request.
const OIDC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on an IdP response body (1 MiB): a discovery document,
/// introspection response, or token response is a few KiB; anything
/// larger is a misbehaving or hostile endpoint.
const OIDC_BODY_CAP: usize = 1024 * 1024;

/// How long a cached discovery document is considered fresh before a
/// re-fetch is forced (1 hour): the document rarely changes, and a
/// re-fetch on every request would be wasteful. A generation swap
/// (config reload) rebuilds the client, which re-fetches discovery on
/// the next request anyway.
const DISCOVERY_FRESH_SECS: u64 = 3600;

/// Error contacting an OIDC provider (DW-034). The `Display` text is
/// logged, not sent to the client (the envelope never leaks IdP
/// internals). All variants surface to the client as 401 (fail closed)
/// or pass-through (fail open) per the provider's `fail_open` config.
#[derive(Debug)]
pub enum OidcError {
    /// The issuer or endpoint URL is invalid.
    InvalidEndpoint(String),
    /// The IdP returned a non-2xx status.
    EndpointStatus(u16),
    /// The IdP's response body could not be parsed (missing required
    /// field, non-string, malformed JSON).
    MalformedResponse(String),
    /// A network or HTTP error contacting the IdP.
    Fetch(String),
    /// The `trusted_ca_file` bundle could not be loaded.
    TlsConfig(String),
    /// The introspection result was `active: false` (the token is not
    /// valid / has been revoked). Distinct from a network error so the
    /// caller can map it to 401 (fail closed) regardless of `fail_open`.
    Inactive,
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcError::InvalidEndpoint(m) => {
                write!(f, "oidc endpoint is invalid: {m}")
            }
            OidcError::EndpointStatus(s) => {
                write!(f, "oidc endpoint returned status {s}")
            }
            OidcError::MalformedResponse(m) => {
                write!(f, "oidc response is malformed: {m}")
            }
            OidcError::Fetch(m) => write!(f, "oidc fetch failed: {m}"),
            OidcError::TlsConfig(m) => write!(f, "oidc tls config error: {m}"),
            OidcError::Inactive => write!(f, "oidc introspection returned active: false"),
        }
    }
}

impl std::error::Error for OidcError {}

/// A connection that is either plaintext TCP or TLS: the single
/// response type of `OidcConnector` for `http://` and `https://` IdP
/// endpoints. Mirrors the JWKS connector's `MaybeTls` (authn.rs) and
/// the OAuth2 connector's (oauth2.rs) — kept separate because the OIDC
/// connector carries a `trusted_ca_file` (private-CA IdP) the OAuth2
/// connector does not.
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

impl HyperConnection for MaybeTls {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// Plain-or-TLS connector for one-shot OIDC HTTP calls (hyper-util
/// legacy client plumbing; reuses the workspace rustls stack, no new
/// HTTP dependency). Trust defaults to the webpki public roots; a
/// provider's `trusted_ca_file` replaces them so an https IdP behind a
/// private CA is reachable — the same trust model the JWKS connector
/// gives `trusted_ca_file` JWT providers.
#[derive(Clone)]
struct OidcConnector {
    http: hyper_util::client::legacy::connect::HttpConnector,
    tls: tokio_rustls::TlsConnector,
}

impl OidcConnector {
    /// `trusted_ca` is the provider's `trusted_ca_file` path when set.
    /// Fails when the bundle cannot be loaded/parsed, so the provider is
    /// disabled at build time (see `build_oidc_clients`) instead of
    /// failing every request.
    fn new(trusted_ca: Option<&str>) -> Result<Self, OidcError> {
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false); // scheme routing happens here
        let roots = match trusted_ca {
            Some(path) => crate::security::tls::root_store_from_pem_file(path).map_err(|e| {
                OidcError::TlsConfig(format!("trusted_ca_file '{path}' could not be loaded: {e}"))
            })?,
            None => crate::security::tls::webpki_root_store(),
        };
        let cfg = crate::security::tls::https_h1_client_config(roots);
        Ok(OidcConnector {
            http,
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
        })
    }
}

impl Service<Uri> for OidcConnector {
    type Response = TokioIo<MaybeTls>;
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
                .ok_or_else(|| std::io::Error::other("oidc url has no host"))?
                .to_string();
            let stream = tokio::time::timeout(OIDC_CONNECT_TIMEOUT, http.call(uri.clone()))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "oidc connect timed out")
                })?
                .map_err(std::io::Error::other)?
                .into_inner();
            match uri.scheme_str() {
                Some("https") => {
                    let name = ServerName::try_from(host.clone()).map_err(|e| {
                        std::io::Error::other(format!("oidc host is not a valid tls name: {e}"))
                    })?;
                    let tls_stream = tokio::time::timeout(
                        OIDC_CONNECT_TIMEOUT,
                        tls.connect(name, hyper_util::rt::tokio::WithHyperIo::new(stream)),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "oidc tls handshake timed out",
                        )
                    })??;
                    Ok(TokioIo::new(MaybeTls::Tls(Box::new(tls_stream))))
                }
                _ => Ok(TokioIo::new(MaybeTls::Plain(
                    hyper_util::rt::tokio::WithHyperIo::new(stream),
                ))),
            }
        })
    }
}

/// The parsed OIDC discovery document (RFC 8414 / OIDC Discovery 1.0).
/// Only the fields the gateway consumes are extracted; unknown fields
/// are ignored (the document is forward-compatible by design).
#[derive(Debug, Clone)]
pub struct DiscoveryDocument {
    /// The issuer identifier (`iss` claim of tokens from this provider).
    pub issuer: String,
    /// The JWKS URI (not used for introspection, but available for
    /// future local JWT verification of ID tokens).
    pub jwks_uri: Option<String>,
    /// The introspection endpoint (RFC 7662).
    pub introspection_endpoint: Option<String>,
    /// The revocation endpoint (RFC 7009).
    pub revocation_endpoint: Option<String>,
    /// The authorization endpoint (RFC 6749 section 3.1).
    pub authorization_endpoint: Option<String>,
    /// The token endpoint (RFC 6749 section 3.2).
    pub token_endpoint: Option<String>,
}

impl DiscoveryDocument {
    /// Parse the discovery JSON, extracting the fields the gateway
    /// consumes. Missing optional fields yield `None` (the provider may
    /// not advertise every endpoint).
    fn parse(body: &[u8]) -> Result<Self, OidcError> {
        let json: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| OidcError::MalformedResponse(format!("discovery is not JSON: {e}")))?;
        let get = |k: &str| json.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        let issuer = get("issuer").ok_or_else(|| {
            OidcError::MalformedResponse("discovery document has no string 'issuer'".into())
        })?;
        Ok(DiscoveryDocument {
            issuer,
            jwks_uri: get("jwks_uri"),
            introspection_endpoint: get("introspection_endpoint"),
            revocation_endpoint: get("revocation_endpoint"),
            authorization_endpoint: get("authorization_endpoint"),
            token_endpoint: get("token_endpoint"),
        })
    }
}

/// The parsed token introspection response (RFC 7662 section 2.2).
/// `active` is the only REQUIRED field; the rest are optional and
/// extracted as strings for the identity map.
#[derive(Debug, Clone)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active (RFC 7662 section 2.2).
    pub active: bool,
    /// The subject identifier (`sub` claim).
    pub sub: Option<String>,
    /// The human-readable username (OIDC `preferred_username` or
    /// OAuth2 `username`).
    pub username: Option<String>,
    /// The scope string (space-delimited).
    pub scope: Option<String>,
    /// The issuer (`iss`) — checked against the provider's configured
    /// issuer for defense against token confusion.
    pub iss: Option<String>,
    /// The client ID the token was issued to.
    pub client_id: Option<String>,
    /// Token expiration (Unix epoch seconds).
    pub exp: Option<i64>,
    /// Raw JSON (for extracting arbitrary claims into the identity map).
    pub raw: serde_json::Value,
}

impl IntrospectionResponse {
    /// Parse the introspection JSON. `active` defaults to false when
    /// absent (RFC 7662 section 2.2: "If the introspection call is
    /// properly authorized but the token is not active, does not exist
    /// on this server, or is not authorized for introspection, then
    /// the authorization server returns a response with `active`
    /// false").
    fn parse(body: &[u8]) -> Result<Self, OidcError> {
        let raw: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| OidcError::MalformedResponse(format!("introspection is not JSON: {e}")))?;
        let active = raw.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        let get = |k: &str| raw.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        Ok(IntrospectionResponse {
            active,
            sub: get("sub"),
            username: get("username").or_else(|| get("preferred_username")),
            scope: get("scope"),
            iss: get("iss"),
            client_id: get("client_id"),
            exp: raw.get("exp").and_then(|v| v.as_i64()),
            raw,
        })
    }
}

/// One cached introspection result (DW-034): the parsed response and
/// when it expires (the gateway's `Instant` clock).
#[derive(Clone)]
struct CachedIntrospection {
    result: IntrospectionResponse,
    expires_at: Instant,
}

impl CachedIntrospection {
    fn is_fresh(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// Per-provider introspection cache (DW-034): lives on the dataplane so
/// a config reload reuses cached `active: true` results (the
/// `jwks_caches` / `oauth2_token_cache` precedent). Entries are keyed
/// by `{provider_name}:{sha256_hex(token)}`. Only `active: true`
/// results are cached; `active: false` is re-checked on every request
/// so a revoked token is noticed promptly.
pub struct OidcIntrospectionCache {
    inner: std::sync::Mutex<HashMap<String, CachedIntrospection>>,
}

impl OidcIntrospectionCache {
    /// The empty cache.
    pub fn new() -> Self {
        OidcIntrospectionCache {
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The cached `active: true` introspection for `provider` + `token`,
    /// if any and still fresh. Returns `None` for expired or absent
    /// entries (the caller re-introspects).
    fn get(&self, provider: &str, token: &str) -> Option<IntrospectionResponse> {
        let key = cache_key(provider, token);
        let inner = self.inner.lock().expect("oidc cache poisoned");
        let entry = inner.get(&key)?;
        if entry.is_fresh() {
            Some(entry.result.clone())
        } else {
            None
        }
    }

    /// Store a freshly introspected `active: true` result. `active:
    /// false` results are NOT stored (re-checked on the next request).
    fn put(&self, provider: &str, token: &str, result: IntrospectionResponse, ttl: Duration) {
        if !result.active {
            return;
        }
        let key = cache_key(provider, token);
        let entry = CachedIntrospection {
            result,
            expires_at: Instant::now() + ttl,
        };
        self.inner
            .lock()
            .expect("oidc cache poisoned")
            .insert(key, entry);
    }

    /// Invalidate the cached entry for `provider` + `token` (called
    /// after a revocation so the next request re-introspects).
    pub fn invalidate(&self, provider: &str, token: &str) {
        let key = cache_key(provider, token);
        self.inner.lock().expect("oidc cache poisoned").remove(&key);
    }
}

impl Default for OidcIntrospectionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OidcIntrospectionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcIntrospectionCache")
            .field("entries", &self.inner.lock().map(|m| m.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

/// The cache key: `{provider_name}:{sha256_hex(token)}`. The token is
/// hashed so the plaintext never lives in the cache key (the
/// selector-redaction precedent — a debug print of the cache must not
/// leak tokens).
fn cache_key(provider: &str, token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    format!("{}:{}", provider, hex_encode(&digest))
}

/// Lowercase hex encoding of a byte slice (the `sha256_hex` shape from
/// `config::credentials`, inlined to avoid a cross-domain import for a
/// trivial helper).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// One configured OIDC provider at runtime: config + HTTP client +
/// cached discovery document. The introspection cache lives on the
/// dataplane ([`OidcIntrospectionCache`]) so a config reload reuses
/// cached results.
pub struct OidcClient {
    cfg: OidcProvider,
    http: Client<OidcConnector, Full<bytes::Bytes>>,
    /// Cached discovery document (fetched lazily on the first request,
    /// re-fetched after `DISCOVERY_FRESH_SECS`).
    discovery: std::sync::Mutex<Option<(Arc<DiscoveryDocument>, Instant)>>,
    /// Serializes discovery fetches so concurrent requests coalesce
    /// into one discovery GET (the JWKS refresh-lock precedent).
    discovery_lock: tokio::sync::Mutex<()>,
}

impl OidcClient {
    /// Build the runtime client from config. The `trusted_ca_file` is
    /// loaded here (at build time) so a broken bundle disables this
    /// provider at build instead of failing every request.
    pub fn build(cfg: OidcProvider) -> Result<Arc<Self>, OidcError> {
        let connector = OidcConnector::new(cfg.trusted_ca_file.as_deref())?;
        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_timer(TokioTimer::new());
        Ok(Arc::new(OidcClient {
            cfg,
            http: builder.build(connector),
            discovery: std::sync::Mutex::new(None),
            discovery_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// The resolved config (for validation / introspection).
    pub fn config(&self) -> &OidcProvider {
        &self.cfg
    }

    /// The provider's name (a stable key for the introspection cache).
    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    /// Fetch the discovery document from
    /// `{issuer}/.well-known/openid-configuration`. The caller MUST
    /// hold the discovery lock so concurrent fetches coalesce.
    async fn fetch_discovery(&self) -> Result<Arc<DiscoveryDocument>, OidcError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.cfg.issuer.trim_end_matches('/')
        );
        let uri: Uri = url.parse().map_err(|e| {
            OidcError::InvalidEndpoint(format!("discovery url '{url}' is invalid: {e}"))
        })?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(bytes::Bytes::new()))
            .map_err(|e| OidcError::Fetch(format!("discovery request build failed: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| OidcError::Fetch(format!("discovery request failed: {e:#}")))?;
        if !resp.status().is_success() {
            return Err(OidcError::EndpointStatus(resp.status().as_u16()));
        }
        let body = Limited::new(resp.into_body(), OIDC_BODY_CAP)
            .collect()
            .await
            .map_err(|e| OidcError::Fetch(format!("discovery body read failed: {e}")))?
            .to_bytes();
        let doc = DiscoveryDocument::parse(&body)?;
        // Defense against a misconfigured or hostile IdP: the discovery
        // document's `issuer` MUST match the configured issuer (OIDC
        // Discovery 1.0 section 3). A mismatch is token-confusion bait.
        if doc.issuer != self.cfg.issuer {
            return Err(OidcError::MalformedResponse(format!(
                "discovery issuer '{}' does not match configured issuer '{}'",
                doc.issuer, self.cfg.issuer
            )));
        }
        let doc = Arc::new(doc);
        *self
            .discovery
            .lock()
            .expect("oidc discovery cache poisoned") = Some((Arc::clone(&doc), Instant::now()));
        Ok(doc)
    }

    /// The discovery document, fetching it on the first call and
    /// re-fetching after [`DISCOVERY_FRESH_SECS`]. Concurrent callers
    /// coalesce into one fetch (the discovery lock).
    async fn discovery(&self) -> Result<Arc<DiscoveryDocument>, OidcError> {
        // Fast path: a fresh cached document.
        {
            let guard = self
                .discovery
                .lock()
                .expect("oidc discovery cache poisoned");
            if let Some((doc, fetched_at)) = guard.as_ref() {
                if fetched_at.elapsed().as_secs() < DISCOVERY_FRESH_SECS {
                    return Ok(Arc::clone(doc));
                }
            }
        }
        // Slow path: serialize fetches. A concurrent caller that lost
        // the race re-checks the cache after the lock (the winner's
        // document is now cached).
        let _guard = self.discovery_lock.lock().await;
        {
            let guard = self
                .discovery
                .lock()
                .expect("oidc discovery cache poisoned");
            if let Some((doc, fetched_at)) = guard.as_ref() {
                if fetched_at.elapsed().as_secs() < DISCOVERY_FRESH_SECS {
                    return Ok(Arc::clone(doc));
                }
            }
        }
        self.fetch_discovery().await
    }

    /// The introspection endpoint URL: the config override takes
    /// precedence over the discovery-discovered value.
    async fn introspection_endpoint(&self) -> Result<String, OidcError> {
        if let Some(ep) = &self.cfg.introspection_endpoint {
            return Ok(ep.clone());
        }
        let doc = self.discovery().await?;
        doc.introspection_endpoint.clone().ok_or_else(|| {
            OidcError::InvalidEndpoint(
                "provider advertises no introspection endpoint and no override is configured"
                    .into(),
            )
        })
    }

    /// The revocation endpoint URL: the config override takes
    /// precedence over the discovery-discovered value.
    async fn revocation_endpoint(&self) -> Result<String, OidcError> {
        if let Some(ep) = &self.cfg.revocation_endpoint {
            return Ok(ep.clone());
        }
        let doc = self.discovery().await?;
        doc.revocation_endpoint.clone().ok_or_else(|| {
            OidcError::InvalidEndpoint(
                "provider advertises no revocation endpoint and no override is configured".into(),
            )
        })
    }

    /// The token endpoint URL (for token exchange and auth-code
    /// exchange): from the discovery document.
    async fn token_endpoint(&self) -> Result<String, OidcError> {
        let doc = self.discovery().await?;
        doc.token_endpoint.clone().ok_or_else(|| {
            OidcError::InvalidEndpoint("provider advertises no token endpoint".into())
        })
    }

    /// The authorization endpoint URL (for the auth-code flow): from
    /// the discovery document.
    pub async fn authorization_endpoint(&self) -> Result<String, OidcError> {
        let doc = self.discovery().await?;
        doc.authorization_endpoint.clone().ok_or_else(|| {
            OidcError::InvalidEndpoint("provider advertises no authorization endpoint".into())
        })
    }

    /// Resolve the client secret (a `${...}` reference or inline value).
    /// The plaintext never leaves this call.
    fn secret(&self) -> Result<String, OidcError> {
        crate::config::credentials::resolve_configured_secret(&self.cfg.client_secret)
            .map_err(|e| OidcError::Fetch(format!("client_secret unresolvable: {e}")))
    }

    /// HTTP Basic auth header value (`Basic base64(client_id:secret)`).
    fn basic_auth(&self) -> Result<String, OidcError> {
        let secret = self.secret()?;
        Ok(format!(
            "Basic {}",
            BASE64.encode(format!("{}:{}", self.cfg.client_id, secret))
        ))
    }

    /// Introspect a bearer token (RFC 7662). Returns the parsed
    /// introspection response. The caller is responsible for caching
    /// (via [`OidcIntrospectionCache`]) and fail-open/fail-closed
    /// mapping. Client auth is HTTP Basic (RFC 7662 section 2.1);
    /// the token is sent as `token` in the form-encoded body.
    pub async fn introspect(
        &self,
        token: &str,
        cache: &OidcIntrospectionCache,
    ) -> Result<IntrospectionResponse, OidcError> {
        // Fast path: a cached `active: true` result.
        if let Some(cached) = cache.get(&self.cfg.name, token) {
            return Ok(cached);
        }
        let endpoint = self.introspection_endpoint().await?;
        let basic = self.basic_auth()?;
        let body = format!("token={}", &urlencode(token));
        let req = Request::builder()
            .method(Method::POST)
            .uri(endpoint.parse::<Uri>().map_err(|e| {
                OidcError::InvalidEndpoint(format!("introspection endpoint is invalid: {e}"))
            })?)
            .header(hyper::header::AUTHORIZATION, basic)
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| OidcError::Fetch(format!("introspection request build failed: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| OidcError::Fetch(format!("introspection request failed: {e:#}")))?;
        if !resp.status().is_success() {
            return Err(OidcError::EndpointStatus(resp.status().as_u16()));
        }
        let body = Limited::new(resp.into_body(), OIDC_BODY_CAP)
            .collect()
            .await
            .map_err(|e| OidcError::Fetch(format!("introspection body read failed: {e}")))?
            .to_bytes();
        let result = IntrospectionResponse::parse(&body)?;
        if !result.active {
            return Err(OidcError::Inactive);
        }
        // Defense against token confusion: when the introspection result
        // carries an `iss`, it MUST match the configured issuer. A
        // mismatched issuer means the token was issued by a different
        // IdP than the one this provider is configured for.
        if let Some(iss) = &result.iss {
            if iss != &self.cfg.issuer {
                return Err(OidcError::MalformedResponse(format!(
                    "introspection issuer '{iss}' does not match configured issuer '{}'",
                    self.cfg.issuer
                )));
            }
        }
        // Cache the active result.
        cache.put(
            &self.cfg.name,
            token,
            result.clone(),
            Duration::from_secs(self.cfg.introspection_cache_ttl_s),
        );
        Ok(result)
    }

    /// Revoke a token (RFC 7009). POST to the revocation endpoint with
    /// the token. This is an admin/management operation, not on the hot
    /// request path. The introspection cache entry for this token is
    /// invalidated so the next request re-introspects (or fails 401).
    /// Returns `Ok(())` on a 2xx response; the RFC notes a 200 is the
    /// success response and a 400 may indicate an unrecognized token
    /// (treated as an error here so the caller can report it).
    pub async fn revoke(
        &self,
        token: &str,
        cache: &OidcIntrospectionCache,
    ) -> Result<(), OidcError> {
        let endpoint = self.revocation_endpoint().await?;
        let basic = self.basic_auth()?;
        let body = format!("token={}", urlencode(token));
        let req = Request::builder()
            .method(Method::POST)
            .uri(endpoint.parse::<Uri>().map_err(|e| {
                OidcError::InvalidEndpoint(format!("revocation endpoint is invalid: {e}"))
            })?)
            .header(hyper::header::AUTHORIZATION, basic)
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| OidcError::Fetch(format!("revocation request build failed: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| OidcError::Fetch(format!("revocation request failed: {e:#}")))?;
        let status = resp.status();
        // Drain the body so the connection can be reused.
        let _ = Limited::new(resp.into_body(), OIDC_BODY_CAP)
            .collect()
            .await;
        if !status.is_success() {
            return Err(OidcError::EndpointStatus(status.as_u16()));
        }
        cache.invalidate(&self.cfg.name, token);
        Ok(())
    }

    /// Token exchange (RFC 8693): exchange a subject token for an
    /// actor token. The subject token is the client's bearer token
    /// (`subject_token`); the actor token is what the gateway forwards
    /// to the upstream. `audience` is the resource server the actor
    /// token is intended for (RFC 8693 section 2.1). Returns the actor
    /// token string on success.
    pub async fn exchange_token(
        &self,
        subject_token: &str,
        audience: &str,
    ) -> Result<String, OidcError> {
        let endpoint = self.token_endpoint().await?;
        let basic = self.basic_auth()?;
        // RFC 8693 section 2.1: grant_type, subject_token,
        // subject_token_type, audience (requested), and optionally
        // scope. The subject token is an access token
        // (urn:ietf:params:oauth:token-type:access_token); the actor
        // token is requested as an access token too.
        let mut body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
             &subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token\
             &audience={}",
            urlencode(subject_token),
            urlencode(audience)
        );
        if !self.cfg.scopes.is_empty() {
            body.push_str("&scope=");
            body.push_str(&urlencode(&self.cfg.scopes.join(" ")));
        }
        let req = Request::builder()
            .method(Method::POST)
            .uri(endpoint.parse::<Uri>().map_err(|e| {
                OidcError::InvalidEndpoint(format!("token endpoint is invalid: {e}"))
            })?)
            .header(hyper::header::AUTHORIZATION, basic)
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| OidcError::Fetch(format!("token exchange request build failed: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| OidcError::Fetch(format!("token exchange request failed: {e:#}")))?;
        if !resp.status().is_success() {
            return Err(OidcError::EndpointStatus(resp.status().as_u16()));
        }
        let body = Limited::new(resp.into_body(), OIDC_BODY_CAP)
            .collect()
            .await
            .map_err(|e| OidcError::Fetch(format!("token exchange body read failed: {e}")))?
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            OidcError::MalformedResponse(format!("token exchange is not JSON: {e}"))
        })?;
        let token = json
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                OidcError::MalformedResponse("token exchange response missing access_token".into())
            })?
            .to_string();
        if token.is_empty() {
            return Err(OidcError::MalformedResponse(
                "token exchange access_token is empty".into(),
            ));
        }
        Ok(token)
    }

    /// Exchange an authorization code for tokens (RFC 6749 section 4.1,
    /// the auth-code + PKCE flow). `code` is the authorization code
    /// from the IdP's callback redirect; `redirect_uri` is the
    /// gateway's callback URL; `code_verifier` is the PKCE verifier
    /// matching the challenge sent in the authorization request. Returns
    /// the parsed token response (access, refresh, ID token, etc.).
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenSet, OidcError> {
        let endpoint = self.token_endpoint().await?;
        let basic = self.basic_auth()?;
        let body = format!(
            "grant_type=authorization_code\
             &code={}&redirect_uri={}&code_verifier={}",
            urlencode(code),
            urlencode(redirect_uri),
            urlencode(code_verifier)
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri(endpoint.parse::<Uri>().map_err(|e| {
                OidcError::InvalidEndpoint(format!("token endpoint is invalid: {e}"))
            })?)
            .header(hyper::header::AUTHORIZATION, basic)
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| {
                OidcError::Fetch(format!("auth-code exchange request build failed: {e}"))
            })?;
        let resp =
            self.http.request(req).await.map_err(|e| {
                OidcError::Fetch(format!("auth-code exchange request failed: {e:#}"))
            })?;
        if !resp.status().is_success() {
            return Err(OidcError::EndpointStatus(resp.status().as_u16()));
        }
        let body = Limited::new(resp.into_body(), OIDC_BODY_CAP)
            .collect()
            .await
            .map_err(|e| OidcError::Fetch(format!("auth-code exchange body read failed: {e}")))?
            .to_bytes();
        TokenSet::parse(&body)
    }

    /// Build the authorization request URL for the auth-code + PKCE
    /// flow (RFC 6749 section 4.1.1 + RFC 7636). The gateway redirects
    /// the user agent to this URL; the IdP authenticates the user and
    /// redirects back to `redirect_uri` with an authorization code.
    /// `state` is an opaque value the gateway round-trips for CSRF
    /// protection; `code_challenge` is the PKCE challenge derived from
    /// `code_verifier` (S256: `base64url(sha256(verifier))`).
    pub async fn authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> Result<String, OidcError> {
        let endpoint = self.authorization_endpoint().await?;
        let mut params = vec![
            ("response_type", "code"),
            ("client_id", self.cfg.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ];
        let scope = self.cfg.scopes.join(" ");
        if !scope.is_empty() {
            params.push(("scope", scope.as_str()));
        }
        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(format!("{endpoint}?{query}"))
    }
}

impl std::fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClient")
            .field("name", &self.cfg.name)
            .field("issuer", &self.cfg.issuer)
            .field("client_id", &self.cfg.client_id)
            .field("client_secret", &"[redacted]")
            .field("scopes", &self.cfg.scopes)
            .field(
                "introspection_cache_ttl_s",
                &self.cfg.introspection_cache_ttl_s,
            )
            .field("fail_open", &self.cfg.fail_open)
            .finish_non_exhaustive()
    }
}

/// The token set returned by an auth-code exchange (RFC 6749 section
/// 5.1 + OIDC `id_token`). All fields except `access_token` are
/// optional.
#[derive(Debug, Clone)]
pub struct TokenSet {
    /// The access token (always present in a successful response).
    pub access_token: String,
    /// The token type (typically "Bearer").
    pub token_type: Option<String>,
    /// The refresh token (optional; for offline access).
    pub refresh_token: Option<String>,
    /// The ID token (OIDC; optional when the `openid` scope was not
    /// requested).
    pub id_token: Option<String>,
    /// Lifetime in seconds.
    pub expires_in: Option<u64>,
    /// The scope granted (may differ from requested).
    pub scope: Option<String>,
}

impl TokenSet {
    /// Parse a token response JSON body.
    fn parse(body: &[u8]) -> Result<Self, OidcError> {
        let json: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
            OidcError::MalformedResponse(format!("token response is not JSON: {e}"))
        })?;
        let get = |k: &str| json.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        let access_token = get("access_token").ok_or_else(|| {
            OidcError::MalformedResponse("token response missing access_token".into())
        })?;
        if access_token.is_empty() {
            return Err(OidcError::MalformedResponse("access_token is empty".into()));
        }
        Ok(TokenSet {
            access_token,
            token_type: get("token_type"),
            refresh_token: get("refresh_token"),
            id_token: get("id_token"),
            expires_in: json.get("expires_in").and_then(|v| v.as_u64()),
            scope: get("scope"),
        })
    }
}

/// Percent-encode a string for `application/x-www-form-urlencoded`
/// bodies (RFC 3986 unreserved characters kept; everything else
/// percent-encoded). Inlined to avoid a new dependency — the body
/// values are tokens, codes, and URLs whose characters are almost
/// entirely unreserved, so a minimal encoder is sufficient and correct.
fn urlencode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        // RFC 3986 unreserved: A-Z a-z 0-9 - _ . ~
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// Generate a PKCE code verifier (43..=128 random ASCII characters per
/// RFC 7636 section 4.1). Returns the verifier; the challenge is
/// `base64url(sha256(verifier))` (S256 method). The verifier MUST be
/// sent in the token exchange; the challenge is sent in the
/// authorization request. Uses a caller-provided 32-byte random seed
/// (the gateway does not pull in a crypto RNG crate; tests pass a
/// fixed seed for determinism, production callers use the OS RNG).
pub fn pkce_code_verifier(seed: &[u8; 32]) -> String {
    // RFC 7636 section 4.1: 43..=128 chars from the unreserved set
    // [A-Z][a-z][0-9]-._~. A 32-byte seed base64url-encoded yields 43
    // chars (the minimum), which is within the allowed range.
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed)
}

/// Derive the PKCE code challenge (S256) from a verifier: the
/// `base64url(sha256(verifier))` per RFC 7636 section 4.2.
pub fn pkce_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}
