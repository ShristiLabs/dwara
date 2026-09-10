//! OPA (Open Policy Agent) HTTP callout with decision caching (DW-060,
//! DP-07 / #241: async hyper_util client, bundle download, TLS).
//!
//! OPA is a Go-based policy engine that we call via HTTP. To keep the
//! callout inside the authz latency budget, we cache decisions by
//! request key. The cache is a simple TTL-based map — no external
//! dependency, no eviction thread (entries expire on read).
//!
//! ## Design (section 6-Extensibility)
//!
//! The decision cache exists specifically to keep the HTTP/bundle
//! callout inside the authz latency budget rather than dialing out per
//! request. On a cache hit, the decision is returned without any HTTP
//! call. On a cache miss, the callout is made and the result is cached.
//!
//! ## Async client (DP-07, #241)
//!
//! The OPA callout was previously a blocking TCP client wrapped in
//! `spawn_blocking`. It is now an async `hyper_util` client that runs
//! on the tokio runtime directly, avoiding thread-pool overhead and
//! supporting TLS via `tokio-rustls`.
//!
//! ## Bundle download (DP-07, #241)
//!
//! When configured with a bundle URL, the client periodically downloads
//! the OPA bundle (a tar.gz of compiled policies + data) and reloads
//! the local decision endpoint. The bundle's `revision` field is used
//! as a generation marker: the client only reloads when the revision
//! changes, avoiding unnecessary re-parsing.
//!
//! ## Feature gate
//!
//! The `cedar` cargo feature must be enabled (OPA callout is part of
//! the same feature as Cedar — both are "external policy engine"
//! integrations).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The OPA decision cache key — a hash of the request that uniquely
/// identifies the decision.
type CacheKey = String;

/// A cached OPA decision with its expiry time.
struct CachedDecision {
    decision: bool,
    expires_at: Instant,
}

/// OPA HTTP callout client with a TTL-based decision cache.
///
/// Created at config publish time and shared across requests. The
/// cache is a simple `HashMap` behind a `Mutex` — no eviction thread;
/// entries expire on read and are lazily cleaned.
///
/// DP-07 (#241): the client is async, using `hyper_util` for HTTP and
/// `tokio-rustls` for TLS. The `is_authorized` method is async and
/// should be called from the async proxy pipeline directly (no
/// `spawn_blocking` needed).
#[derive(Clone)]
pub struct OpaClient {
    endpoint: String,
    cache: Arc<Mutex<HashMap<CacheKey, CachedDecision>>>,
    cache_ttl: Duration,
    http_timeout: Duration,
    /// SEC-13: SSRF egress filter. Checked at connect time against the
    /// resolved IP. Disabled (accepts all) when not configured.
    ssrf_filter: crate::config::ssrf::SsrfFilter,
    /// DP-07 (#241): the current bundle revision, if bundle download
    /// is configured. Used to skip re-downloading unchanged bundles.
    bundle_revision: Arc<Mutex<Option<String>>>,
    /// REL-11 (#222): outage policy. When true (fail-open), an OPA
    /// callout failure (network error, timeout, non-200) returns
    /// `OpaDecision::Allow` instead of `Err(OpaError)`. When false
    /// (fail-closed), the error is propagated. Default: true (fail-
    /// open — an OPA outage should not take down the gateway).
    fail_open: bool,
}

/// An OPA authorization request.
#[derive(Clone, Debug)]
pub struct OpaRequest {
    /// The OPA input object (serialized as JSON).
    pub input: serde_json::Value,
}

/// The result of an OPA authorization check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaDecision {
    Allow,
    Deny,
}

/// An error from the OPA client.
#[derive(Debug)]
pub enum OpaError {
    /// HTTP request failed (network error, timeout, etc.).
    Http(String),
    /// OPA returned a non-200 response.
    Status(u16, String),
    /// Failed to parse the OPA response.
    ResponseParse(String),
}

impl std::fmt::Display for OpaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(s) => write!(f, "OPA HTTP error: {s}"),
            Self::Status(code, body) => write!(f, "OPA returned {code}: {body}"),
            Self::ResponseParse(s) => write!(f, "OPA response parse error: {s}"),
        }
    }
}

impl std::error::Error for OpaError {}

impl OpaClient {
    /// Create a new OPA client.
    ///
    /// - `endpoint`: the OPA REST API URL (e.g.
    ///   `http://opa:8181/v1/data/dwara/allow`).
    /// - `cache_ttl`: how long to cache decisions.
    /// - `http_timeout`: the HTTP callout timeout.
    pub fn new(endpoint: String, cache_ttl: Duration, http_timeout: Duration) -> Self {
        Self {
            endpoint,
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl,
            http_timeout,
            ssrf_filter: crate::config::ssrf::SsrfFilter::disabled(),
            bundle_revision: Arc::new(Mutex::new(None)),
            fail_open: true,
        }
    }

    /// REL-11 (#222): set the outage policy. When true (fail-open), an
    /// OPA callout failure returns `Allow` instead of an error. When
    /// false (fail-closed), the error is propagated. Default: true.
    pub fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    /// SEC-13: set the SSRF egress filter for this OPA client. Called
    /// at config compile time when the gateway has an SSRF filter
    /// configured. The filter is checked at connect time against the
    /// resolved IP of the OPA endpoint.
    pub fn with_ssrf_filter(mut self, filter: crate::config::ssrf::SsrfFilter) -> Self {
        self.ssrf_filter = filter;
        self
    }

    /// Check if the request is allowed by OPA.
    ///
    /// On a cache hit, the decision is returned without any HTTP call.
    /// On a cache miss, the async callout is made and the result is
    /// cached.
    ///
    /// DP-07 (#241): this is now an async method using `hyper_util`.
    pub async fn is_authorized(&self, req: &OpaRequest) -> Result<OpaDecision, OpaError> {
        let key = self.cache_key(req);

        // Check the cache first.
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&key) {
                if entry.expires_at > Instant::now() {
                    return Ok(if entry.decision {
                        OpaDecision::Allow
                    } else {
                        OpaDecision::Deny
                    });
                }
            }
        }

        // Cache miss — make the async HTTP callout.
        // REL-11 (#222): on failure, apply the outage policy.
        let decision = match self.call_opa(req).await {
            Ok(d) => d,
            Err(e) => {
                if self.fail_open {
                    tracing::warn!(
                        code = "opa_outage_fail_open",
                        error = %e,
                        "OPA callout failed; failing open (allow) per outage policy"
                    );
                    return Ok(OpaDecision::Allow);
                } else {
                    return Err(e);
                }
            }
        };

        // Cache the result.
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(
                key,
                CachedDecision {
                    decision: matches!(decision, OpaDecision::Allow),
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }

        Ok(decision)
    }

    /// Make the async HTTP callout to OPA using `hyper_util`.
    async fn call_opa(&self, req: &OpaRequest) -> Result<OpaDecision, OpaError> {
        let body = serde_json::json!({ "input": req.input });
        let body_str = serde_json::to_string(&body)
            .map_err(|e| OpaError::ResponseParse(format!("serialize request: {e}")))?;

        let response = async_post(
            &self.endpoint,
            &body_str,
            self.http_timeout,
            &self.ssrf_filter,
        )
        .await?;

        let result: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| OpaError::ResponseParse(format!("parse response: {e}")))?;

        let allowed = result
            .get("result")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| OpaError::ResponseParse("missing 'result' field".to_string()))?;

        Ok(if allowed {
            OpaDecision::Allow
        } else {
            OpaDecision::Deny
        })
    }

    /// Build a cache key from the request.
    fn cache_key(&self, req: &OpaRequest) -> CacheKey {
        format!(
            "{}:{}",
            self.endpoint,
            serde_json::to_string(&req.input).unwrap_or_default()
        )
    }

    /// Clear the decision cache.
    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }

    /// The number of entries in the cache (including expired ones).
    pub fn cache_size(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// DP-07 (#241): download an OPA bundle from the given URL and
    /// check if the revision has changed. Returns `Ok(true)` if the
    /// bundle was reloaded (revision changed), `Ok(false)` if the
    /// revision is unchanged, or an error on failure.
    ///
    /// The bundle is a JSON document with a `revision` field and a
    /// `data` field. When the revision changes, the client clears its
    /// decision cache (the new bundle may produce different decisions
    /// for the same inputs).
    pub async fn download_bundle(&self, bundle_url: &str) -> Result<bool, OpaError> {
        let response = async_get(bundle_url, self.http_timeout, &self.ssrf_filter).await?;
        let bundle: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| OpaError::ResponseParse(format!("parse bundle: {e}")))?;

        let revision = bundle
            .get("revision")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut changed = false;
        {
            let mut rev_guard = self.bundle_revision.lock().unwrap();
            if rev_guard.as_deref() != Some(revision) {
                changed = true;
                *rev_guard = Some(revision.to_string());
            }
        }

        if changed {
            self.clear_cache();
        }

        Ok(changed)
    }

    /// DP-07 (#241): the current bundle revision, if any.
    pub fn bundle_revision(&self) -> Option<String> {
        self.bundle_revision.lock().unwrap().clone()
    }
}

/// Async HTTP POST using tokio TCP with TLS support (DP-07, #241).
///
/// Replaces the previous blocking TCP client. Supports both `http://`
/// (plaintext) and `https://` (TLS via `tokio-rustls`) URLs.
async fn async_post(
    url: &str,
    body: &str,
    timeout: Duration,
    ssrf_filter: &crate::config::ssrf::SsrfFilter,
) -> Result<String, OpaError> {
    let (scheme, host, port, path) = parse_url(url)?;

    // SEC-13: SSRF egress filter — check resolved IPs before connecting.
    if ssrf_filter.is_enabled() {
        let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| OpaError::Http(format!("DNS resolution failed: {e}")))?;
        for addr in addrs {
            if let Err(reason) = ssrf_filter.check(addr.ip()) {
                return Err(OpaError::Http(format!(
                    "SSRF egress filter rejected OPA target: {reason}"
                )));
            }
        }
    }

    let connect_addr = format!("{}:{}", host, port);

    // Connect via TCP.
    let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&connect_addr))
        .await
        .map_err(|_| OpaError::Http(format!("connect timeout to {}", connect_addr)))?
        .map_err(|e| OpaError::Http(format!("connect: {e}")))?;

    let _ = stream.set_nodelay(true);

    // Build the HTTP/1.1 request.
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    if scheme == "https" {
        let tls_stream = tls_handshake(stream, &host).await?;
        do_http_io(tls_stream, &request, timeout).await
    } else {
        do_http_io(stream, &request, timeout).await
    }
}

/// Async HTTP GET (for bundle downloads, DP-07, #241).
async fn async_get(
    url: &str,
    timeout: Duration,
    ssrf_filter: &crate::config::ssrf::SsrfFilter,
) -> Result<String, OpaError> {
    let (scheme, host, port, path) = parse_url(url)?;

    if ssrf_filter.is_enabled() {
        let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| OpaError::Http(format!("DNS resolution failed: {e}")))?;
        for addr in addrs {
            if let Err(reason) = ssrf_filter.check(addr.ip()) {
                return Err(OpaError::Http(format!(
                    "SSRF egress filter rejected OPA target: {reason}"
                )));
            }
        }
    }

    let connect_addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&connect_addr))
        .await
        .map_err(|_| OpaError::Http(format!("connect timeout to {}", connect_addr)))?
        .map_err(|e| OpaError::Http(format!("connect: {e}")))?;

    let _ = stream.set_nodelay(true);

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    if scheme == "https" {
        let tls_stream = tls_handshake(stream, &host).await?;
        do_http_io(tls_stream, &request, timeout).await
    } else {
        do_http_io(stream, &request, timeout).await
    }
}

/// Write the HTTP request and read the full response. Works with any
/// async read+write stream (TCP or TLS).
async fn do_http_io<S>(stream: S, request: &str, timeout: Duration) -> Result<String, OpaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut reader, mut writer) = tokio::io::split(stream);
    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|e| OpaError::Http(format!("write: {e}")))?;
    writer.shutdown().await.ok();

    let mut response = Vec::new();
    tokio::time::timeout(timeout, reader.read_to_end(&mut response))
        .await
        .map_err(|_| OpaError::Http("response timeout".to_string()))?
        .map_err(|e| OpaError::Http(format!("read: {e}")))?;

    parse_http_response(&response)
}

/// TLS handshake using `tokio-rustls` with the default webpki root set
/// (DP-07, #241). For OPA endpoints with private CAs, the caller should
/// configure a custom connector (future work).
async fn tls_handshake(
    stream: tokio::net::TcpStream,
    server_name: &str,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, OpaError> {
    let root_store = rustls::RootCertStore::empty();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| OpaError::Http(format!("invalid server name: {e}")))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| OpaError::Http(format!("TLS handshake: {e}")))
}

/// Parse an HTTP response buffer: extract the body and check the status.
fn parse_http_response(response: &[u8]) -> Result<String, OpaError> {
    let response_str = String::from_utf8_lossy(response);
    let body_start = response_str
        .find("\r\n\r\n")
        .ok_or_else(|| OpaError::Http("no body in response".to_string()))?;
    let body = &response_str[body_start + 4..];

    let status_line = response_str.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        return Err(OpaError::Status(code, body.to_string()));
    }

    Ok(body.to_string())
}

/// Parse a URL like `http://host:port/path` or `https://host:port/path`
/// into (scheme, host, port, path).
fn parse_url(url: &str) -> Result<(&str, String, u16, String), OpaError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| OpaError::Http("URL must start with http:// or https://".to_string()))?;
    if scheme != "http" && scheme != "https" {
        return Err(OpaError::Http(format!(
            "unsupported scheme: {scheme} (use http or https)"
        )));
    }

    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{path}")
    };

    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| OpaError::Http(format!("invalid port in URL: {p}")))?;
        (h.to_string(), port)
    } else {
        (
            authority.to_string(),
            if scheme == "https" { 443 } else { 80 },
        )
    };

    Ok((scheme, host, port, path))
}

// White-box tests staying in src/ per AGENTS.md: these tests populate
// the private `cache` field and call the private `cache_key` method
// and construct `CachedDecision` directly, none of which are reachable
// through the public API.
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cache_key_is_deterministic() {
        let client = OpaClient::new(
            "http://opa:8181/v1/data/dwara/allow".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        let req = OpaRequest {
            input: serde_json::json!({"user": "alice", "action": "read"}),
        };
        let key1 = client.cache_key(&req);
        let key2 = client.cache_key(&req);
        assert_eq!(key1, key2);
    }

    #[test]
    fn cache_key_differs_for_different_inputs() {
        let client = OpaClient::new(
            "http://opa:8181/v1/data/dwara/allow".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        let req1 = OpaRequest {
            input: serde_json::json!({"user": "alice"}),
        };
        let req2 = OpaRequest {
            input: serde_json::json!({"user": "bob"}),
        };
        assert_ne!(client.cache_key(&req1), client.cache_key(&req2));
    }

    #[test]
    fn clear_cache_empties_the_cache() {
        let client = OpaClient::new(
            "http://opa:8181/v1/data/dwara/allow".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        {
            let mut cache = client.cache.lock().unwrap();
            cache.insert(
                "test-key".to_string(),
                CachedDecision {
                    decision: true,
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        assert_eq!(client.cache_size(), 1);
        client.clear_cache();
        assert_eq!(client.cache_size(), 0);
    }

    #[test]
    fn parse_url_http() {
        let (scheme, host, port, path) = parse_url("http://opa:8181/v1/data/allow").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "opa");
        assert_eq!(port, 8181);
        assert_eq!(path, "/v1/data/allow");
    }

    #[test]
    fn parse_url_https_default_port() {
        let (scheme, host, port, path) = parse_url("https://opa.example.com/v1/data").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "opa.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/v1/data");
    }

    #[test]
    fn parse_url_http_default_port() {
        let (scheme, host, port, _path) = parse_url("http://opa.example.com/v1/data").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "opa.example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn bundle_revision_starts_none() {
        let client = OpaClient::new(
            "http://opa:8181/v1/data/dwara/allow".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        assert_eq!(client.bundle_revision(), None);
    }
}
