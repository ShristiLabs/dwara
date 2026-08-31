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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_index() {
        let file = resolve("/console/").unwrap();
        assert_eq!(file.content_type, "text/html; charset=utf-8");
        assert!(!file.body.is_empty());
        assert!(file.body.starts_with(b"<!DOCTYPE html>"));
    }

    #[test]
    fn resolve_index_no_trailing_slash() {
        let file = resolve("/console").unwrap();
        assert_eq!(file.content_type, "text/html; charset=utf-8");
    }

    #[test]
    fn resolve_index_html() {
        let file = resolve("/console/index.html").unwrap();
        assert_eq!(file.content_type, "text/html; charset=utf-8");
    }

    #[test]
    fn resolve_style_css() {
        let file = resolve("/console/style.css").unwrap();
        assert_eq!(file.content_type, "text/css; charset=utf-8");
        assert!(!file.body.is_empty());
        assert!(file.body.starts_with(b":root"));
    }

    #[test]
    fn resolve_app_js() {
        let file = resolve("/console/app.js").unwrap();
        assert_eq!(file.content_type, "application/javascript; charset=utf-8");
        assert!(!file.body.is_empty());
        // The JS starts with a comment.
        assert!(file.body.starts_with(b"//"));
    }

    #[test]
    fn resolve_unknown_returns_none() {
        assert!(resolve("/console/unknown").is_none());
        assert!(resolve("/console/favicon.ico").is_none());
        assert!(resolve("/health").is_none());
        assert!(resolve("/").is_none());
    }

    #[test]
    fn is_console_path_matches() {
        assert!(is_console_path("/console"));
        assert!(is_console_path("/console/"));
        assert!(is_console_path("/console/index.html"));
        assert!(is_console_path("/console/style.css"));
        assert!(is_console_path("/console/app.js"));
    }

    #[test]
    fn is_console_path_rejects_non_console() {
        assert!(!is_console_path("/health"));
        assert!(!is_console_path("/stats"));
        assert!(!is_console_path("/config"));
        assert!(!is_console_path("/"));
        assert!(!is_console_path("/consolex"));
    }

    #[test]
    fn file_paths_lists_all() {
        let paths = file_paths();
        assert_eq!(paths.len(), FILE_COUNT);
        assert!(paths.contains(&"/console/index.html"));
        assert!(paths.contains(&"/console/style.css"));
        assert!(paths.contains(&"/console/app.js"));
    }

    #[test]
    fn index_html_has_nav_buttons() {
        let file = resolve("/console/").unwrap();
        let html = std::str::from_utf8(file.body).unwrap();
        assert!(html.contains("data-view=\"overview\""));
        assert!(html.contains("data-view=\"routes\""));
        assert!(html.contains("data-view=\"upstreams\""));
        assert!(html.contains("data-view=\"health\""));
        assert!(html.contains("data-view=\"analytics\""));
        assert!(html.contains("data-view=\"config\""));
    }

    #[test]
    fn index_html_references_assets() {
        let file = resolve("/console/").unwrap();
        let html = std::str::from_utf8(file.body).unwrap();
        assert!(html.contains("/console/style.css"));
        assert!(html.contains("/console/app.js"));
    }

    #[test]
    fn app_js_fetches_admin_endpoints() {
        let file = resolve("/console/app.js").unwrap();
        let js = std::str::from_utf8(file.body).unwrap();
        // The SPA fetches from the admin API.
        assert!(js.contains("fetchJSON('/health')"));
        assert!(js.contains("fetchJSON('/stats')"));
        assert!(js.contains("fetchJSON('/config')"));
        assert!(js.contains("fetchText('/config_dump')"));
        assert!(js.contains("fetchJSON('/analytics/top"));
    }

    #[test]
    fn app_js_has_auto_refresh() {
        let file = resolve("/console/app.js").unwrap();
        let js = std::str::from_utf8(file.body).unwrap();
        assert!(js.contains("startAutoRefresh"));
        assert!(js.contains("REFRESH_INTERVAL"));
    }

    #[test]
    fn app_js_is_read_only() {
        let file = resolve("/console/app.js").unwrap();
        let js = std::str::from_utf8(file.body).unwrap();
        // No PATCH, POST, PUT, or DELETE -- read-only.
        assert!(!js.contains("method: 'PATCH'"));
        assert!(!js.contains("method: 'POST'"));
        assert!(!js.contains("method: 'PUT'"));
        assert!(!js.contains("method: 'DELETE'"));
    }

    #[test]
    fn style_css_has_dark_theme() {
        let file = resolve("/console/style.css").unwrap();
        let css = std::str::from_utf8(file.body).unwrap();
        assert!(css.contains("--bg"));
        assert!(css.contains("--fg"));
        assert!(css.contains("--card-bg"));
    }

    #[test]
    fn all_files_non_empty() {
        for path in file_paths() {
            let file = resolve(path).unwrap();
            assert!(!file.body.is_empty(), "{path} is empty");
        }
    }
}
