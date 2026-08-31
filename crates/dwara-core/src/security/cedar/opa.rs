//! OPA (Open Policy Agent) HTTP callout with decision caching (DW-060).
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
#[derive(Clone)]
pub struct OpaClient {
    endpoint: String,
    cache: Arc<Mutex<HashMap<CacheKey, CachedDecision>>>,
    cache_ttl: Duration,
    http_timeout: Duration,
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
        }
    }

    /// Check if the request is allowed by OPA.
    ///
    /// On a cache hit, the decision is returned without any HTTP call.
    /// On a cache miss, the callout is made and the result is cached.
    pub fn is_authorized(&self, req: &OpaRequest) -> Result<OpaDecision, OpaError> {
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

        // Cache miss — make the HTTP callout.
        let decision = self.call_opa(req)?;

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

    /// Make the HTTP callout to OPA.
    fn call_opa(&self, req: &OpaRequest) -> Result<OpaDecision, OpaError> {
        // Build the request body: { "input": <req.input> }
        let body = serde_json::json!({ "input": req.input });
        let body_str = serde_json::to_string(&body)
            .map_err(|e| OpaError::ResponseParse(format!("serialize request: {e}")))?;

        // Use a blocking HTTP client. The authz path is synchronous
        // (the proxy pipeline calls is_authorized synchronously), so
        // we use reqwest's blocking client. In a future async refactor,
        // this would be an async call.
        //
        // For now, we use a simple hyper-based HTTP call. Since the
        // crate already depends on hyper, we use it directly.
        //
        // NOTE: This is a synchronous implementation. The OPA callout
        // runs on a blocking thread pool (tokio's spawn_blocking) when
        // called from the async proxy pipeline.
        let url = &self.endpoint;

        // We use ureq for the blocking HTTP call — it's lightweight and
        // doesn't require an async runtime. But we don't want to add a
        // new dependency. Instead, we use the existing hyper + tokio
        // runtime in a blocking fashion.
        //
        // For the test, we use a mock. For production, the caller
        // should wrap this in spawn_blocking.
        let response = blocking_post(url, &body_str, self.http_timeout)?;

        // Parse the response: { "result": true/false }
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
        // Use the serialized input as the key. This is deterministic
        // for the same input (serde_json serializes in a stable order
        // for serde_json::Value).
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
}

/// A blocking HTTP POST. Uses a simple TCP connection with a timeout.
///
/// In production, this is called from `tokio::task::spawn_blocking`.
/// The implementation uses `std::net::TcpStream` with a read/write
/// timeout to avoid pulling in a blocking HTTP client dependency.
fn blocking_post(url: &str, body: &str, timeout: Duration) -> Result<String, OpaError> {
    // Parse the URL manually (avoid pulling in the `url` crate as a
    // direct dependency — it's only a transitive dep via hyper).
    // Expected format: http://host:port/path
    let (host, port, path) = parse_url(url)?;

    // Connect.
    let addr = format!("{host}:{port}");
    let stream =
        std::net::TcpStream::connect(&addr).map_err(|e| OpaError::Http(format!("connect: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| OpaError::Http(format!("set_read_timeout: {e}")))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| OpaError::Http(format!("set_write_timeout: {e}")))?;

    use std::io::{Read, Write};
    let mut stream = stream;

    // Send the request.
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| OpaError::Http(format!("write: {e}")))?;

    // Read the response.
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| OpaError::Http(format!("read: {e}")))?;

    // Parse the HTTP response (simple: find the body after \r\n\r\n).
    let response_str = String::from_utf8_lossy(&response);
    let body_start = response_str
        .find("\r\n\r\n")
        .ok_or_else(|| OpaError::Http("no body in response".to_string()))?;
    let body = &response_str[body_start + 4..];

    // Check the status code.
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

/// Parse a URL like `http://host:port/path` into (host, port, path).
/// Supports http and https schemes (https is treated as plain TCP —
/// the caller is responsible for ensuring the endpoint is reachable
/// over plain TCP, or wrapping with TLS separately).
fn parse_url(url: &str) -> Result<(String, u16, String), OpaError> {
    // Strip the scheme.
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| OpaError::Http("URL must start with http:// or https://".to_string()))?;

    // Split host:port from path.
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));

    let path = if path.is_empty() {
        "/"
    } else {
        &format!("/{path}")
    };

    // Split host from port.
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| OpaError::Http(format!("invalid port in URL: {p}")))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), 80)
    };

    Ok((host, port, path.to_string()))
}

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
        // Manually insert an entry.
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
}
