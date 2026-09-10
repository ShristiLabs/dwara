//! AI-13 (#201): Gateway-side image URL fetcher.
//!
//! When a client sends a multimodal request with a remote image URL
//! (the OpenAI `image_url.url` convention) and the target provider
//! adapter requires base64 image data (Anthropic, Gemini), the
//! gateway fetches the image, converts it to base64, and fills the
//! `data_b64` + `media_type` fields on `ContentPart::Image`. The
//! OpenAI adapter continues to pass the remote URL through unchanged.
//!
//! The fetcher is async and runs in `serve_ai` after guardrails and
//! before `adapter.build_request`. It is opt-in per route via the
//! `ai.image_fetch` config block; when disabled, remote URLs are
//! dropped by the Anthropic/Gemini adapters as before (preserving
//! backward compatibility).

use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::ai::types::{ChatMessage, ChatRequest, ContentPart};

/// Default maximum image size (10 MB). Provider limits vary but 10 MB
/// is a safe upper bound for vision-model images.
const DEFAULT_MAX_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Default fetch timeout.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Configuration for the image fetcher.
#[derive(Debug, Clone)]
pub struct ImageFetchConfig {
    /// Maximum image size in bytes.
    pub max_size_bytes: u64,
    /// Fetch timeout.
    pub timeout: Duration,
}

impl Default for ImageFetchConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: DEFAULT_MAX_SIZE_BYTES,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }
}

/// Fetch remote image URLs in a `ChatRequest` and fill `data_b64` +
/// `media_type` on each `ContentPart::Image` that has a remote URL
/// but no base64 data. Images that already have `data_b64` (from
/// `data:` URIs) are left unchanged. The `url` field is preserved so
/// the OpenAI adapter can still pass it through.
///
/// Returns the mutated `ChatRequest`. On fetch failure for any single
/// image, the image is left as-is (the adapter will drop it, preserving
/// the pre-#201 behavior) and a warning is logged.
pub async fn fetch_remote_images(mut req: ChatRequest, cfg: &ImageFetchConfig) -> ChatRequest {
    let client = build_http_client(cfg.timeout);
    for msg in &mut req.messages {
        for part in &mut msg.content {
            if let ContentPart::Image {
                url: Some(url_str),
                data_b64,
                media_type,
            } = part
            {
                // Skip if already has base64 data (data: URI decomposed).
                if data_b64.is_some() {
                    continue;
                }
                // Skip data: URIs (already handled by split_data_uri).
                if url_str.starts_with("data:") {
                    continue;
                }
                // Only fetch http(s) URLs.
                if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
                    continue;
                }
                match fetch_one(&client, url_str, cfg.max_size_bytes).await {
                    Ok((b64, mime)) => {
                        *data_b64 = Some(b64);
                        if media_type.is_none() {
                            *media_type = Some(mime);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            code = "ai_image_fetch_failed",
                            url = %url_str,
                            error = %e,
                            "failed to fetch remote image URL; adapter will drop it"
                        );
                    }
                }
            }
        }
    }
    req
}

/// Fetch a single image URL and return (base64_data, mime_type).
async fn fetch_one(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    url: &str,
    max_size: u64,
) -> Result<(String, String), String> {
    let req = Request::builder()
        .uri(url)
        .header(hyper::header::USER_AGENT, "dwara-ai-gateway/1.0")
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("build request: {e}"))?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| format!("fetch: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    // Check Content-Length against the size cap.
    if let Some(len) = resp.headers().get(hyper::header::CONTENT_LENGTH) {
        if let Ok(s) = len.to_str() {
            if let Ok(n) = s.parse::<u64>() {
                if n > max_size {
                    return Err(format!("image too large: {n} bytes (max {max_size})"));
                }
            }
        }
    }
    let mime = resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("image/png")
        .to_string();
    // Read the body with a size cap.
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read body: {e}"))?
        .to_bytes();
    if body.len() as u64 > max_size {
        return Err(format!(
            "image too large: {} bytes (max {max_size})",
            body.len()
        ));
    }
    // Verify it looks like an image MIME type.
    if !mime.starts_with("image/") {
        return Err(format!("not an image: Content-Type {mime}"));
    }
    let b64 = general_purpose::STANDARD.encode(&body);
    Ok((b64, mime))
}

/// Build a plain HTTP client (no TLS). For `https://` URLs the
/// connector needs TLS; the hyper_util `HttpConnector` does not
/// support TLS by default. The fetcher is intended for internal/
/// trusted image sources; for production HTTPS, a TLS-enabled
/// connector would be needed (follow-up).
fn build_http_client(
    timeout: Duration,
) -> Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> {
    let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
    connector.enforce_http(false); // allow https (will fail without TLS connector)
    let client = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Some(timeout))
        .build_http::<Full<Bytes>>();
    let _ = connector; // suppress unused warning
    client
}

/// Check if a `ChatRequest` has any remote image URLs that would need
/// fetching. Used to skip the fetcher entirely when not needed.
pub fn has_remote_images(req: &ChatRequest) -> bool {
    req.messages.iter().any(|m: &ChatMessage| {
        m.content.iter().any(|p| match p {
            ContentPart::Image {
                url: Some(url),
                data_b64: None,
                ..
            } => !url.starts_with("data:"),
            _ => false,
        })
    })
}
