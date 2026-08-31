//! dwara web console v1 (read-only, OSS) -- DW-117.
//!
//! A static SPA served from the mTLS admin listener. The SPA fetches
//! from the admin API (same origin). No dataplane deps -- the SPA is
//! static, embedded at compile time via `include_str!`/`include_bytes!`.
//!
//! ## Views
//!
//! - Overview: gateway status, active requests, uptime, config epoch,
//!   route/listener counts.
//! - Routes: route table (name, path, service, methods).
//! - Upstreams: upstream/service health table (service, address,
//!   health, requests, errors).
//! - Health: raw health JSON.
//! - Analytics: Top-N analytics.
//! - Config: current config YAML dump.
//!
//! ## Done-when
//!
//! Operator can diagnose an outage entirely from the console; no
//! dataplane deps (SPA is static).
//!
//! ## Serving
//!
//! The console is served at `/console/` from the admin listener. The
//! admin handler checks for `/console` paths before dispatching to the
//! admin API handlers. The SPA fetches from the admin API endpoints
//! (`/health`, `/stats`, `/config`, `/config_dump`, `/analytics/top`)
//! on the same origin.

// Embed the static files at compile time. No runtime file system
// dependency, no external crate needed.
const INDEX_HTML: &str = include_str!("../static/index.html");
const STYLE_CSS: &str = include_str!("../static/style.css");
const APP_JS: &str = include_str!("../static/app.js");

/// A static file response: the body bytes and the content-type.
pub struct StaticFile {
    pub body: &'static [u8],
    pub content_type: &'static str,
}

/// Resolve a console path to a static file.
///
/// Returns `Some(file)` if the path matches a known static file,
/// `None` if the path is not a console path.
///
/// # Examples
///
/// ```
/// use dwara_console::resolve;
///
/// // Index page.
/// let file = resolve("/console/").unwrap();
/// assert_eq!(file.content_type, "text/html; charset=utf-8");
///
/// // CSS.
/// let file = resolve("/console/style.css").unwrap();
/// assert_eq!(file.content_type, "text/css; charset=utf-8");
///
/// // Unknown path.
/// assert!(resolve("/console/unknown").is_none());
/// ```
pub fn resolve(path: &str) -> Option<StaticFile> {
    match path {
        "/console" | "/console/" | "/console/index.html" => Some(StaticFile {
            body: INDEX_HTML.as_bytes(),
            content_type: "text/html; charset=utf-8",
        }),
        "/console/style.css" => Some(StaticFile {
            body: STYLE_CSS.as_bytes(),
            content_type: "text/css; charset=utf-8",
        }),
        "/console/app.js" => Some(StaticFile {
            body: APP_JS.as_bytes(),
            content_type: "application/javascript; charset=utf-8",
        }),
        _ => None,
    }
}

/// Check if a path is a console path (starts with `/console`).
pub fn is_console_path(path: &str) -> bool {
    path == "/console" || path.starts_with("/console/")
}

/// The number of static files embedded in the console.
pub const FILE_COUNT: usize = 3;

/// List all embedded file paths.
pub fn file_paths() -> &'static [&'static str] {
    &[
        "/console/index.html",
        "/console/style.css",
        "/console/app.js",
    ]
}
