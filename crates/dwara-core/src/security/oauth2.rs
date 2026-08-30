//! OAuth2 client-credentials proxying (DW-035, feature analysis 4.6).
//!
//! The gateway acts as an OAuth2 client itself: for an upstream with an
//! [`crate::config::OAuth2ClientCredentials`] block, it obtains an
//! access token from an external token endpoint using the
//! client-credentials grant (RFC 6749 section 4.4) and forwards that
//! token to the upstream as `Authorization: Bearer <token>` (replacing
//! any client-supplied `Authorization` header — the upstream sees the
//! gateway's token, not the client's). This is for service-to-service
//! calls where the gateway authenticates to the upstream with a token
//! it obtains from an OAuth2 token endpoint.
//!
//! ## Flow
//!
//! 1. Before forwarding a request to an upstream with
//!    `oauth2_client_credentials` configured, the gateway checks its
//!    token cache (per upstream, keyed by upstream name on the
//!    dataplane) for a valid token.
//! 2. If no valid token, it POSTs to the token endpoint with
//!    `grant_type=client_credentials`, the `client_id` and
//!    `client_secret` as HTTP Basic auth (RFC 6749 section 2.3.1), and
//!    `scope` (space-joined) when configured.
//! 3. The response (`{access_token, token_type, expires_in, scope}`) is
//!    cached with a TTL of `min(expires_in - skew,
//!    token_cache_ttl_s)` (or just `expires_in - skew` when no override
//!    is set). The skew (60 s) avoids using a token that expires while
//!    an in-flight request is still streaming.
//! 4. The gateway adds `Authorization: Bearer <token>` to the upstream
//!    request, REPLACING any existing `Authorization` header from the
//!    client.
//!
//! ## Caching
//!
//! The cache is a `Mutex<HashMap<UpstreamName, CachedToken>>` on the
//! dataplane. Token refresh is LAZY (on the first request after
//! expiry) — no background refresh task. A token is considered valid
//! while `Instant::now() < expires_at`; an expired entry is overwritten
//! by the next fetch. Concurrent fetches for the same upstream
//! serialize on a per-upstream `tokio::Mutex` so a token-endpoint
//! fetch-storm cannot be driven by concurrent requests (the JWKS
//! refresh-lock precedent).
//!
//! ## mTLS to the token endpoint
//!
//! An optional `mtls` block configures a client certificate for the TLS
//! handshake to the token endpoint itself (RFC 8705 `tls_client_auth`).
//! The token endpoint's SERVER certificate is verified against the
//! webpki public roots by default; a private-CA token endpoint is not
//! supported in this edition (the `trusted_ca_file` for the token
//! endpoint would be a separate config field; deferred until an
//! operator asks for it).
//!
//! ## Error posture
//!
//! A token-endpoint failure (network error, non-2xx response, malformed
//! body) surfaces to the client as 502 `oauth2_token_unavailable` — the
//! gateway cannot authenticate to the upstream and refuses to forward
//! without a token (never proxying unauthenticated). The error envelope
//! never leaks the token endpoint's response body or headers.

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
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use rustls::ClientConfig;
use tower_service::Service;

use crate::config::{OAuth2ClientCredentials, OAuth2Mtls};

/// Refresh skew: a token is treated as expired this long BEFORE its
/// real `expires_in` so an in-flight request does not stream past the
/// token's lifetime with a token the upstream would reject. 60 s is
/// the conventional margin (the same order as JWT leeway defaults).
const REFRESH_SKEW: Duration = Duration::from_secs(60);

/// Upper bound on a token-endpoint response body (1 MiB): a token
/// response is a few hundred bytes; anything larger is a misbehaving or
/// hostile endpoint.
const TOKEN_BODY_CAP: usize = 1024 * 1024;

/// Connect timeout for token-endpoint POSTs: token acquisition is on
/// the request path (first request / refresh), so it must fail fast
/// rather than hang a client request.
const TOKEN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// One cached access token for an upstream (DW-035).
#[derive(Clone)]
struct CachedToken {
    /// The raw access token string (inserted into `Bearer <token>`).
    token: String,
    /// When this token expires (the gateway's `Instant` clock): valid
    /// while `Instant::now() < expires_at`.
    expires_at: Instant,
}

impl CachedToken {
    /// Whether the token is still valid (not past its skew-adjusted
    /// expiry).
    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// Error acquiring a token (DW-035). All variants surface to the client
/// as 502 `oauth2_token_unavailable`; the `Display` text is logged, not
/// sent to the client (the envelope never leaks upstream internals).
#[derive(Debug)]
pub enum OAuth2Error {
    /// The token endpoint URL is invalid.
    InvalidEndpoint(String),
    /// The token endpoint returned a non-2xx status.
    EndpointStatus(u16),
    /// The token endpoint's response body could not be parsed as a
    /// valid token response (missing `access_token`, non-string, etc.).
    MalformedResponse(String),
    /// A network or HTTP error contacting the token endpoint.
    Fetch(String),
    /// The mTLS client certificate could not be loaded.
    MtlsConfig(String),
}

impl std::fmt::Display for OAuth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuth2Error::InvalidEndpoint(m) => {
                write!(f, "oauth2 token endpoint is invalid: {m}")
            }
            OAuth2Error::EndpointStatus(s) => {
                write!(f, "oauth2 token endpoint returned status {s}")
            }
            OAuth2Error::MalformedResponse(m) => {
                write!(f, "oauth2 token response is malformed: {m}")
            }
            OAuth2Error::Fetch(m) => write!(f, "oauth2 token fetch failed: {m}"),
            OAuth2Error::MtlsConfig(m) => {
                write!(f, "oauth2 mtls client certificate error: {m}")
            }
        }
    }
}

impl std::error::Error for OAuth2Error {}

/// A connection that is either plaintext TCP or TLS (with an optional
/// client certificate): the single response type of [`OAuth2Connector`]
/// for `http://` and `https://` token endpoints. Mirrors the JWKS
/// connector's `MaybeTls` (authn.rs) — kept separate because the OAuth2
/// connector carries an optional CLIENT certificate (mTLS to the token
/// endpoint) the JWKS connector never needs.
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

/// Plain-or-TLS connector for one-shot OAuth2 token POSTs (hyper-util
/// legacy client plumbing; reuses the workspace rustls stack, no new
/// HTTP dependency). Trust defaults to the webpki public roots; an
/// optional client certificate (RFC 8705 `tls_client_auth`) is loaded
/// from the `mtls` config block when present.
#[derive(Clone)]
struct OAuth2Connector {
    http: hyper_util::client::legacy::connect::HttpConnector,
    tls: tokio_rustls::TlsConnector,
}

impl OAuth2Connector {
    /// Build the connector. `mtls` loads a client certificate/key pair
    /// for the TLS handshake to the token endpoint (RFC 8705); `None`
    /// negotiates TLS with no client certificate. Fails when the cert
    /// or key files cannot be loaded/parsed, so the upstream's OAuth2
    /// config is disabled at build time instead of failing every
    /// request.
    fn new(mtls: Option<&OAuth2Mtls>) -> Result<Self, OAuth2Error> {
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false); // scheme routing happens here
        let roots = crate::security::tls::webpki_root_store();
        let builder = ClientConfig::builder().with_root_certificates(roots);
        let mut cfg = match mtls {
            Some(m) => {
                let certs = load_cert_chain(&m.client_cert)?;
                let key = load_private_key(&m.client_key)?;
                builder.with_client_auth_cert(certs, key).map_err(|e| {
                    OAuth2Error::MtlsConfig(format!("building client auth config: {e}"))
                })?
            }
            None => builder.with_no_client_auth(),
        };
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(OAuth2Connector {
            http,
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
        })
    }
}

impl Service<Uri> for OAuth2Connector {
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
                .ok_or_else(|| std::io::Error::other("oauth2 token url has no host"))?
                .to_string();
            let stream = tokio::time::timeout(TOKEN_CONNECT_TIMEOUT, http.call(uri.clone()))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "oauth2 connect timed out")
                })?
                .map_err(std::io::Error::other)?
                .into_inner();
            match uri.scheme_str() {
                Some("https") => {
                    let name = ServerName::try_from(host.clone()).map_err(|e| {
                        std::io::Error::other(format!("oauth2 host is not a valid tls name: {e}"))
                    })?;
                    let tls_stream = tokio::time::timeout(
                        TOKEN_CONNECT_TIMEOUT,
                        tls.connect(name, hyper_util::rt::tokio::WithHyperIo::new(stream)),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "oauth2 tls handshake timed out",
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

/// Load a PEM certificate chain for the mTLS client cert.
fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, OAuth2Error> {
    let ppath = std::path::PathBuf::from(path);
    let certs = CertificateDer::pem_file_iter(&ppath)
        .map_err(|e| OAuth2Error::MtlsConfig(format!("reading client cert '{path}': {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| OAuth2Error::MtlsConfig(format!("parsing client cert '{path}': {e}")))?;
    if certs.is_empty() {
        return Err(OAuth2Error::MtlsConfig(format!(
            "client cert '{path}' contains no certificates"
        )));
    }
    Ok(certs)
}

/// Load a PEM private key for the mTLS client cert. Returns the raw
/// `PrivateKeyDer` (rustls's `with_client_auth_cert` takes it directly;
/// the provider resolves the signing key internally).
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, OAuth2Error> {
    let ppath = std::path::PathBuf::from(path);
    let pem = std::fs::read(&ppath)
        .map_err(|e| OAuth2Error::MtlsConfig(format!("reading client key '{path}': {e}")))?;
    let key = PrivateKeyDer::pem_slice_iter(&pem)
        .next()
        .ok_or_else(|| OAuth2Error::MtlsConfig(format!("client key '{path}' has no private key")))?
        .map_err(|e| OAuth2Error::MtlsConfig(format!("parsing client key '{path}': {e}")))?;
    Ok(key)
}

/// One upstream's OAuth2 client-credentials configuration at runtime:
/// the resolved config plus a per-upstream HTTP client and a fetch
/// serialization lock. The token cache lives on the dataplane
/// ([`OAuth2TokenCache`]) so a config reload reuses cached tokens.
pub struct OAuth2Client {
    cfg: OAuth2ClientCredentials,
    http: Client<OAuth2Connector, Full<bytes::Bytes>>,
    /// Serializes token fetches for THIS upstream so concurrent
    /// requests coalesce into one token-endpoint POST (the JWKS
    /// refresh-lock precedent).
    fetch_lock: tokio::sync::Mutex<()>,
}

impl OAuth2Client {
    /// Build the runtime client from config. The `mtls` cert/key files
    /// are loaded here (at build time) so a broken bundle disables this
    /// upstream's OAuth2 at build instead of failing every request.
    pub fn build(cfg: OAuth2ClientCredentials) -> Result<Arc<Self>, OAuth2Error> {
        let connector = OAuth2Connector::new(cfg.mtls.as_ref())?;
        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_timer(TokioTimer::new());
        Ok(Arc::new(OAuth2Client {
            cfg,
            http: builder.build(connector),
            fetch_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// The resolved config (for validation / introspection).
    pub fn config(&self) -> &OAuth2ClientCredentials {
        &self.cfg
    }

    /// Fetch a fresh access token from the token endpoint (RFC 6749
    /// section 4.4). The caller MUST hold the per-upstream fetch lock
    /// so concurrent fetches coalesce.
    async fn fetch_token(&self) -> Result<CachedToken, OAuth2Error> {
        let uri: Uri = self.cfg.token_endpoint.parse().map_err(|e| {
            OAuth2Error::InvalidEndpoint(format!(
                "'{}' is not a valid URL: {e}",
                self.cfg.token_endpoint
            ))
        })?;
        // RFC 6749 section 2.3.1: client credentials as HTTP Basic auth
        // (base64(client_id:client_secret)). The secret is resolved
        // HERE from a `${...}` reference (DW-045) at build time; the
        // plaintext never leaves this call.
        let secret = crate::config::credentials::resolve_configured_secret(&self.cfg.client_secret)
            .map_err(|e| OAuth2Error::Fetch(format!("client_secret unresolvable: {e}")))?;
        let basic = BASE64.encode(format!("{}:{}", self.cfg.client_id, secret));
        // Request body: grant_type=client_credentials[&scope=...].
        let mut body = "grant_type=client_credentials".to_string();
        if !self.cfg.scopes.is_empty() {
            body.push_str("&scope=");
            body.push_str(&self.cfg.scopes.join(" "));
        }
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(hyper::header::AUTHORIZATION, format!("Basic {basic}"))
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| OAuth2Error::Fetch(format!("building token request: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| OAuth2Error::Fetch(format!("token endpoint request failed: {e:#}")))?;
        if !resp.status().is_success() {
            return Err(OAuth2Error::EndpointStatus(resp.status().as_u16()));
        }
        let body = Limited::new(resp.into_body(), TOKEN_BODY_CAP)
            .collect()
            .await
            .map_err(|e| OAuth2Error::Fetch(format!("token response body read failed: {e}")))?
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OAuth2Error::MalformedResponse(format!("not JSON: {e}")))?;
        let token = json
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OAuth2Error::MalformedResponse("missing string access_token".into()))?
            .to_string();
        if token.is_empty() {
            return Err(OAuth2Error::MalformedResponse(
                "access_token is empty".into(),
            ));
        }
        // token_type MUST be "Bearer" (case-insensitive) for this use;
        // other types (e.g. "mac") are not supported. Absent defaults
        // to Bearer per RFC 6749 section 5.1's examples.
        if let Some(tt) = json.get("token_type").and_then(|v| v.as_str()) {
            if !tt.eq_ignore_ascii_case("bearer") {
                return Err(OAuth2Error::MalformedResponse(format!(
                    "token_type '{tt}' is not 'bearer'"
                )));
            }
        }
        let expires_in = json
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        let ttl = self.effective_ttl(expires_in);
        Ok(CachedToken {
            token,
            expires_at: Instant::now() + ttl,
        })
    }

    /// The cache TTL: `min(expires_in - skew, override)` when an
    /// override is set, else `expires_in - skew` (clamped to at least
    /// 1 s so a token with a tiny `expires_in` is still cached briefly
    /// — a 0-s TTL would re-fetch on every request).
    fn effective_ttl(&self, expires_in: u64) -> Duration {
        let skew = REFRESH_SKEW.as_secs();
        let base = expires_in.saturating_sub(skew).max(1);
        match self.cfg.token_cache_ttl_s {
            Some(override_s) => Duration::from_secs(base.min(override_s)),
            None => Duration::from_secs(base),
        }
    }

    /// Test-only accessor for the TTL computation (DW-035): the unit
    /// suite pins the `min(expires_in - skew, override)` formula and the
    /// 1-second floor without spinning a mock token endpoint. The logic
    /// is unchanged — this only re-exposes the private method.
    #[doc(hidden)]
    pub fn effective_ttl_for_test(&self, expires_in: u64) -> Duration {
        self.effective_ttl(expires_in)
    }

    /// Acquire a valid token: return the cached one if still valid,
    /// else fetch a fresh one under the per-upstream fetch lock (so
    /// concurrent requests coalesce into one fetch). The `cache` is the
    /// dataplane's per-upstream token cache; the entry for this upstream
    /// is read and written under the cache's outer lock, while the
    /// network fetch happens under this client's inner fetch lock
    /// (released before the cache lock is re-acquired to store the
    /// result, so a slow fetch never blocks other upstreams' cache
    /// reads).
    pub async fn token(&self, cache: &OAuth2TokenCache) -> Result<String, OAuth2Error> {
        // Fast path: a cached token that is still valid.
        if let Some(token) = cache.get(self).filter(|t| t.is_valid()) {
            return Ok(token.token.clone());
        }
        // Slow path: serialize fetches for THIS upstream. A concurrent
        // caller that lost the race re-checks the cache after the lock
        // (the winner's token is now cached).
        let _guard = self.fetch_lock.lock().await;
        if let Some(token) = cache.get(self).filter(|t| t.is_valid()) {
            return Ok(token.token.clone());
        }
        let token = self.fetch_token().await?;
        let token_string = token.token.clone();
        cache.put(self, token);
        Ok(token_string)
    }
}

impl std::fmt::Debug for OAuth2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Client")
            .field("token_endpoint", &self.cfg.token_endpoint)
            .field("client_id", &self.cfg.client_id)
            .field("client_secret", &"[redacted]")
            .field("scopes", &self.cfg.scopes)
            .field("mtls", &self.cfg.mtls.is_some())
            .field("token_cache_ttl_s", &self.cfg.token_cache_ttl_s)
            .finish_non_exhaustive()
    }
}

/// Per-upstream OAuth2 token cache (DW-035): lives on the dataplane so
/// a config reload reuses cached tokens (the JWKS cache precedent).
/// Entries are keyed by upstream name; each holds the cached token and
/// its skew-adjusted expiry. Refresh is lazy (on the first request
/// after expiry) — no background task.
pub struct OAuth2TokenCache {
    inner: std::sync::Mutex<HashMap<String, CachedToken>>,
}

impl OAuth2TokenCache {
    /// The empty cache.
    pub fn new() -> Self {
        OAuth2TokenCache {
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The cached token for `client`'s upstream, if any (valid or not —
    /// the caller checks [`CachedToken::is_valid`]).
    fn get(&self, client: &OAuth2Client) -> Option<CachedToken> {
        self.inner
            .lock()
            .expect("oauth2 token cache poisoned")
            .get(&client.cfg.token_endpoint)
            .cloned()
    }

    /// Store a freshly fetched token for `client`'s upstream,
    /// overwriting any expired entry.
    fn put(&self, client: &OAuth2Client, token: CachedToken) {
        self.inner
            .lock()
            .expect("oauth2 token cache poisoned")
            .insert(client.cfg.token_endpoint.clone(), token);
    }
}

impl Default for OAuth2TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OAuth2TokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2TokenCache").finish_non_exhaustive()
    }
}
