//! Unit tests for the dwara web console (`dwara_console`).
//!
//! These tests exercise the public API of the console module: `resolve`
//! (static file resolution for console paths), `is_console_path`
//! (path classification), `file_paths` (the list of embedded files),
//! `StaticFile` (the response type), and `FILE_COUNT` (the constant
//! count of embedded files). They verify that the embedded SPA files
//! are present, non-empty, and contain the expected content.

use dwara_console::{file_paths, is_console_path, resolve, FILE_COUNT};

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
    // DW-118: fleet + editor views.
    assert!(html.contains("data-view=\"fleet\""));
    assert!(html.contains("data-view=\"editor\""));
}

#[test]
fn index_html_references_assets() {
    let file = resolve("/console/").unwrap();
    let html = std::str::from_utf8(file.body).unwrap();
    assert!(html.contains("/console/style.css"));
    assert!(html.contains("/console/app.js"));
}

#[test]
fn index_html_has_workspace_switcher() {
    let file = resolve("/console/").unwrap();
    let html = std::str::from_utf8(file.body).unwrap();
    // DW-118: workspace switcher in the top bar.
    assert!(html.contains("workspace-switcher"));
}

#[test]
fn app_js_fetches_admin_endpoints() {
    let file = resolve("/console/app.js").unwrap();
    let js = std::str::from_utf8(file.body).unwrap();
    // The SPA fetches from the admin API.
    assert!(js.contains("fetchJSON('/health')"));
    assert!(js.contains("fetchJSON('/stats')"));
    assert!(js.contains("fetchText('/config')"));
    assert!(js.contains("fetchJSON('/config_dump')"));
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
fn app_js_has_fleet_view() {
    let file = resolve("/console/app.js").unwrap();
    let js = std::str::from_utf8(file.body).unwrap();
    // DW-118: fleet view consumes the fleet admin endpoints.
    assert!(js.contains("renderFleet"));
    assert!(js.contains("/fleet/skew"));
    assert!(js.contains("/fleet/status"));
}

#[test]
fn app_js_has_config_editor() {
    let file = resolve("/console/app.js").unwrap();
    let js = std::str::from_utf8(file.body).unwrap();
    // DW-118: config editor with validation preview + publish.
    assert!(js.contains("renderEditor"));
    assert!(js.contains("/config/validate"));
    assert!(js.contains("method: 'PATCH'"));
    assert!(js.contains("method: 'POST'"));
}

#[test]
fn app_js_has_workspace_switcher() {
    let file = resolve("/console/app.js").unwrap();
    let js = std::str::from_utf8(file.body).unwrap();
    // DW-118: workspace switcher fetches from /workspaces.
    assert!(js.contains("initWorkspaceSwitcher"));
    assert!(js.contains("/workspaces"));
}

#[test]
fn app_js_has_live_charts_view() {
    let file = resolve("/console/app.js").unwrap();
    let js = std::str::from_utf8(file.body).unwrap();
    // #226: live charts view with canvas-based rendering.
    assert!(js.contains("renderLive"));
    assert!(js.contains("drawLatencyChart"));
    assert!(js.contains("/analytics/dashboard"));
    assert!(js.contains("/analytics/live"));
    assert!(js.contains("liveState"));
}

#[test]
fn app_js_has_crud_flows() {
    let file = resolve("/console/app.js").unwrap();
    let js = std::str::from_utf8(file.body).unwrap();
    // #226: CRUD flows for routes, upstreams, services, consumers, policies.
    assert!(js.contains("renderCrudEntity"));
    assert!(js.contains("renderRoutesCrud"));
    assert!(js.contains("renderUpstreamsCrud"));
    assert!(js.contains("openCreateDialog"));
    assert!(js.contains("openEditDialog"));
    assert!(js.contains("sendJSON"));
}

#[test]
fn app_js_has_ai_ops_view() {
    let file = resolve("/console/app.js").unwrap();
    let js = std::str::from_utf8(file.body).unwrap();
    // #226: AI ops view with credential pools, MCP, and experiments.
    assert!(js.contains("renderAiOps"));
    assert!(js.contains("/ai/credential-pools"));
    assert!(js.contains("/mcp/sessions"));
    assert!(js.contains("/mcp/tools"));
    assert!(js.contains("/experiments/prompt-overrides"));
}

#[test]
fn index_html_has_v3_nav_buttons() {
    let file = resolve("/console/").unwrap();
    let html = std::str::from_utf8(file.body).unwrap();
    // #226: live and aiops nav buttons.
    assert!(html.contains("data-view=\"live\""));
    assert!(html.contains("data-view=\"aiops\""));
}

#[test]
fn index_html_has_v3_footer() {
    let file = resolve("/console/").unwrap();
    let html = std::str::from_utf8(file.body).unwrap();
    // #226: footer updated to v3.
    assert!(html.contains("console v3"));
}

#[test]
fn style_css_has_v3_styles() {
    let file = resolve("/console/style.css").unwrap();
    let css = std::str::from_utf8(file.body).unwrap();
    // #226: live chart and modal styles.
    assert!(css.contains(".chart-card"));
    assert!(css.contains(".live-chart"));
    assert!(css.contains(".modal-overlay"));
    assert!(css.contains(".crud-toolbar"));
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
