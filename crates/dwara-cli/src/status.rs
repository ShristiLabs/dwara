//! `dwara status` / `dwara top` (USA-02, #179): live operator views over
//! the admin API. `status` prints a one-shot snapshot (generation,
//! listeners, health, breakers, active requests); `top` refreshes a live
//! table of upstream load-balancer state and shedding.
//!
//! Both reuse the same plaintext HTTP/1.1 admin client the `tf` tool
//! uses (hyper, TokioIo). The admin URL defaults to
//! `http://127.0.0.1:2019` (the dev admin listener) and is overridable
//! via `--admin` or the `DWARA_ADMIN` env var.

use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpStream;

/// A plaintext HTTP/1.1 client for the dwara admin API. Only `http://`
/// is supported (the dev admin listener); `https://` (mTLS) is a
/// documented follow-up shared with the `tf` tool.
pub struct AdminClient {
    authority: String,
}

impl AdminClient {
    /// Create a client for `admin_url` (e.g. `http://127.0.0.1:2019`).
    pub fn new(admin_url: &str) -> Result<Self, String> {
        let authority = admin_url
            .strip_prefix("http://")
            .ok_or_else(|| format!("invalid admin URL: {admin_url} (expected http://host:port)"))?
            .trim_end_matches('/');
        Ok(AdminClient {
            authority: authority.to_string(),
        })
    }

    /// GET a JSON endpoint and return the parsed body.
    pub async fn get_json(&self, path: &str) -> Result<Value, String> {
        let stream = TcpStream::connect(&self.authority)
            .await
            .map_err(|e| format!("connect to {}: {e}", self.authority))?;
        let (mut tx, rx) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        let driver = tokio::spawn(async move {
            let _ = rx.await;
        });
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(path)
            .header(hyper::header::HOST, &self.authority)
            .header(hyper::header::CONNECTION, "close")
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| format!("build request: {e}"))?;
        let res = tx
            .send_request(req)
            .await
            .map_err(|e| format!("send request: {e}"))?;
        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("read body: {e}"))?
            .to_bytes();
        driver.abort();
        if !status.is_success() {
            return Err(format!(
                "GET {path} returned {status}: {}",
                String::from_utf8_lossy(&body)
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|e| format!("GET {path}: cannot parse JSON body: {e}"))
    }
}

/// The default admin URL: the dev admin listener.
pub const DEFAULT_ADMIN: &str = "http://127.0.0.1:2019";

/// Resolve the admin URL from `--admin`, else the `DWARA_ADMIN` env var,
/// else the default.
pub fn resolve_admin(admin: Option<&str>) -> String {
    if let Some(a) = admin {
        return a.to_string();
    }
    std::env::var("DWARA_ADMIN").unwrap_or_else(|_| DEFAULT_ADMIN.to_string())
}

/// `dwara status`: one-shot snapshot of the running gateway. Queries
/// `/runtime_info`, `/health`, and `/stats` and renders a human-readable
/// summary. Exit 0 on success, 1 on error.
pub async fn status(admin_url: &str) -> Result<String, String> {
    let client = AdminClient::new(admin_url)?;
    let info = client.get_json("/runtime_info").await?;
    let health = client.get_json("/health").await?;
    let stats = client.get_json("/stats").await?;

    let mut out = String::new();
    out.push_str("dwara gateway status\n");
    out.push_str("====================\n");
    out.push('\n');

    let version = info.get("version").and_then(Value::as_str).unwrap_or("?");
    let uptime = info
        .get("uptime_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let ready = info.get("ready").and_then(Value::as_bool).unwrap_or(false);
    let generation = info
        .get("config_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let config_hash = info
        .get("config_hash")
        .and_then(Value::as_str)
        .unwrap_or("?");

    out.push_str(&format!("version:       {version}\n"));
    out.push_str(&format!("uptime:        {}s\n", format_uptime(uptime)));
    out.push_str(&format!(
        "ready:         {}\n",
        if ready { "yes" } else { "no" }
    ));
    out.push_str(&format!("generation:    {generation}\n"));
    out.push_str(&format!("config hash:   {config_hash}\n"));
    out.push('\n');

    // Upstream health from /health.
    if let Some(upstreams) = health.get("upstreams").and_then(Value::as_object) {
        if !upstreams.is_empty() {
            out.push_str("upstreams:\n");
            for (name, body) in upstreams {
                out.push_str(&format!("  {name}:\n"));
                if let Some(endpoints) = body.get("endpoints").and_then(Value::as_object) {
                    for (addr, state) in endpoints {
                        out.push_str(&format!("    {addr:<40} {state}\n"));
                    }
                }
            }
            out.push('\n');
        }
    }

    // Breakers + active requests from /stats.
    let active = stats
        .get("active_requests")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    out.push_str(&format!("active requests: {active}\n"));

    if let Some(breakers) = stats.get("breakers").and_then(Value::as_object) {
        if !breakers.is_empty() {
            out.push_str("circuit breakers:\n");
            for (name, state) in breakers {
                let label = state.as_str().unwrap_or("?");
                out.push_str(&format!("  {name:<30} {label}\n"));
            }
        }
    }

    if let Some(cache) = stats.get("cache").and_then(Value::as_object) {
        let entries = cache.get("entries").and_then(Value::as_u64).unwrap_or(0);
        let purges = cache.get("purges").and_then(Value::as_u64).unwrap_or(0);
        out.push_str(&format!("cache: {entries} entries, {purges} purges\n"));
    }

    Ok(out)
}

/// `dwara top`: a live, refreshing view of upstream load-balancer state
/// and shedding. Polls `/clusters` and `/stats` every `interval_ms` and
/// re-renders a table. Runs until interrupted (Ctrl-C). Exit 0.
pub async fn top(admin_url: &str, interval_ms: u64) -> Result<(), String> {
    let client = AdminClient::new(admin_url)?;
    let interval = Duration::from_millis(interval_ms.max(100));

    loop {
        let clusters = client.get_json("/clusters").await?;
        let stats = client.get_json("/stats").await?;

        // Clear the screen (ANSI) and render the table.
        print!("\x1b[2J\x1b[H");
        print!("{}", render_top(&clusters, &stats));
        use std::io::Write as _;
        let _ = std::io::stdout().flush();

        tokio::time::sleep(interval).await;
    }
}

/// Render the `top` table from the `/clusters` and `/stats` JSON. Pure
/// function so it is unit-testable without a live gateway.
pub fn render_top(clusters: &Value, stats: &Value) -> String {
    let active = stats
        .get("active_requests")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let generation = stats
        .get("config_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let mut out = String::new();
    out.push_str(&format!(
        "dwara top  |  active: {active}  gen: {generation}\n"
    ));
    out.push_str(&format!(
        "{:<24} {:<14} {:<8} {:<10} {:<10} {:<12} {}\n",
        "UPSTREAM", "ALGORITHM", "SCHEME", "CONNS", "REQUESTS", "BREAKER", "ENDPOINTS"
    ));
    out.push_str(&"-".repeat(100));
    out.push('\n');

    if let Some(upstreams) = clusters.get("upstreams").and_then(Value::as_object) {
        for (name, body) in upstreams {
            let algo = body.get("algorithm").and_then(Value::as_str).unwrap_or("?");
            let scheme = body.get("scheme").and_then(Value::as_str).unwrap_or("?");
            let conns = body
                .get("connections_opened")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let reqs = body
                .get("requests_sent")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let breaker = body
                .get("breaker")
                .and_then(|b| b.get("state").and_then(Value::as_str))
                .unwrap_or_else(|| {
                    body.get("breaker")
                        .and_then(Value::as_str)
                        .unwrap_or("disabled")
                });
            let endpoints = body
                .get("endpoints")
                .and_then(Value::as_array)
                .map(|eps| {
                    eps.iter()
                        .filter_map(|e| {
                            let addr = e.get("address").and_then(Value::as_str)?;
                            let port = e.get("port").and_then(Value::as_u64)?;
                            let health = e.get("health").and_then(Value::as_str).unwrap_or("?");
                            let inflight = e.get("inflight").and_then(Value::as_u64).unwrap_or(0);
                            Some(format!("{addr}:{port}({health},{inflight})"))
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "{:<24} {:<14} {:<8} {:<10} {:<10} {:<12} {}\n",
                truncate(name, 24),
                algo,
                scheme,
                conns,
                reqs,
                breaker,
                endpoints
            ));
        }
    }

    out
}

/// Format an uptime in seconds as a human-readable string.
fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{days}d{hours}h{mins}m")
    } else if hours > 0 {
        format!("{hours}h{mins}m{s}s")
    } else if mins > 0 {
        format!("{mins}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// Truncate a string to `max` chars, appending "..." if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_top_empty() {
        let clusters = serde_json::json!({"upstreams": {}});
        let stats = serde_json::json!({"active_requests": 0, "config_generation": 1});
        let out = render_top(&clusters, &stats);
        assert!(out.contains("dwara top"));
        assert!(out.contains("UPSTREAM"));
    }

    #[test]
    fn render_top_with_upstream() {
        let clusters = serde_json::json!({
            "upstreams": {
                "api": {
                    "algorithm": "round_robin",
                    "scheme": "http",
                    "connections_opened": 10,
                    "requests_sent": 500,
                    "breaker": {"state": "closed"},
                    "endpoints": [
                        {"address": "10.0.0.1", "port": 8080, "health": "healthy", "inflight": 2},
                        {"address": "10.0.0.2", "port": 8080, "health": "healthy", "inflight": 3}
                    ]
                }
            }
        });
        let stats = serde_json::json!({"active_requests": 5, "config_generation": 3});
        let out = render_top(&clusters, &stats);
        assert!(out.contains("api"));
        assert!(out.contains("round_robin"));
        assert!(out.contains("closed"));
        assert!(out.contains("10.0.0.1:8080"));
    }

    #[test]
    fn format_uptime_checks() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(125), "2m5s");
        assert_eq!(format_uptime(3725), "1h2m5s");
        assert_eq!(format_uptime(90061), "1d1h1m");
    }

    #[test]
    fn resolve_admin_default() {
        // Env var may or may not be set; just check it returns a string.
        let a = resolve_admin(None);
        assert!(!a.is_empty());
    }

    #[test]
    fn admin_client_rejects_https() {
        assert!(AdminClient::new("https://127.0.0.1:2019").is_err());
    }

    #[test]
    fn admin_client_accepts_http() {
        assert!(AdminClient::new("http://127.0.0.1:2019").is_ok());
    }
}
