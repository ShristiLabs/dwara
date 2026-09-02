//! Developer portal (DW-110): a read-only static HTML page
//! auto-generated from the configured OpenAPI spec sources.
//!
//! The portal aggregates the existing OpenAPI specs (file paths or
//! upstream `/openapi.json` endpoints) into a single listing of the
//! APIs, their versions, and links to the specs. It is served at a
//! configured reserved path (before route resolution, like `/healthz`).
//! The portal is read-only (no CRUD): it renders the specs the operator
//! already configured, it does not manage them.
//!
//! The config schema types ([`DevPortalConfig`], [`DevPortalSpec`])
//! live in [`crate::config`] (always present, so configs round-trip
//! without the `api_lifecycle` feature). This module re-exports them
//! as the runtime-facing aliases the portal builder consumes.

use std::sync::Arc;

use serde_json::Value;

pub use crate::config::{
    LifecyclePortalConfig as DevPortalConfig, LifecyclePortalSpec as DevPortalSpec,
};

/// The source kind of a developer portal spec (resolved from
/// [`DevPortalSpec`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevPortalSpecSource {
    File(String),
    Url(String),
}

/// A loaded OpenAPI spec entry for the portal: the source, the parsed
/// document (when loading succeeded), and the display name.
#[derive(Debug, Clone)]
pub struct LoadedSpec {
    pub source: DevPortalSpecSource,
    pub doc: Option<Value>,
    pub name: String,
    pub version: String,
    pub error: Option<String>,
}

/// The developer portal: a read-only static HTML page aggregating the
/// configured OpenAPI specs.
///
/// Built at config publish time from the configured spec sources. The
/// portal renders a simple HTML page listing the APIs, their versions,
/// and links to the specs. File specs are loaded (read + parsed) at
/// build time; URL specs are fetched lazily at render time (the
/// upstream may be down at publish time but up at render time).
#[derive(Clone)]
pub struct DevPortal {
    config: Arc<DevPortalConfig>,
    file_specs: Arc<Vec<LoadedSpec>>,
}

impl DevPortal {
    /// Build the portal from the configured spec sources. File specs
    /// are loaded (read + parsed) immediately; URL specs are deferred
    /// to render time. A file that cannot be read or parsed is recorded
    /// as an error entry (the portal still renders, listing the spec as
    /// unavailable) -- the portal is best-effort, never a hard failure.
    pub fn build(config: &DevPortalConfig) -> Self {
        let mut file_specs = Vec::new();
        for spec in &config.specs {
            let source = resolve_source(spec);
            match &source {
                DevPortalSpecSource::File(path) => {
                    file_specs.push(load_file_spec(path, spec.name.as_deref()));
                }
                DevPortalSpecSource::Url(_) => {
                    // Deferred to render time; record a placeholder so
                    // the listing shows the spec even before fetch.
                    file_specs.push(LoadedSpec {
                        source,
                        doc: None,
                        name: spec.name.clone().unwrap_or_default(),
                        version: String::new(),
                        error: None,
                    });
                }
            }
        }
        Self {
            config: Arc::new(config.clone()),
            file_specs: Arc::new(file_specs),
        }
    }

    /// The configured path the portal is served at.
    pub fn path(&self) -> &str {
        &self.config.path
    }

    /// Whether the portal is enabled.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// The file-backed specs loaded at build time.
    pub fn file_specs(&self) -> &[LoadedSpec] {
        &self.file_specs
    }

    /// Render the portal as an HTML page. File specs use the documents
    /// loaded at build time; URL specs are fetched at render time (a
    /// fetch failure is logged and the spec is listed as unavailable).
    pub fn render_html(&self) -> String {
        let mut specs: Vec<LoadedSpec> = self.file_specs.to_vec();
        // Fetch URL specs at render time.
        for spec in specs.iter_mut() {
            if let DevPortalSpecSource::Url(url) = &spec.source {
                match fetch_url_spec(url) {
                    Ok((doc, name, version)) => {
                        spec.doc = Some(doc);
                        spec.name = name;
                        spec.version = version;
                    }
                    Err(e) => {
                        spec.error = Some(e);
                        if spec.name.is_empty() {
                            spec.name = url_host(url).unwrap_or_else(|| url.clone());
                        }
                    }
                }
            }
        }
        render_portal_html(&specs)
    }
}

/// Resolve a [`DevPortalSpec`] into a [`DevPortalSpecSource`]. Returns
/// `File` when `file` is set, `Url` when `url` is set. When both are
/// set, `file` wins (validation rejects the both-set case, but this is
/// defensive). When neither is set, returns `File` with an empty path
/// (validation rejects the neither-set case).
fn resolve_source(spec: &DevPortalSpec) -> DevPortalSpecSource {
    if let Some(file) = &spec.file {
        return DevPortalSpecSource::File(file.clone());
    }
    if let Some(url) = &spec.url {
        return DevPortalSpecSource::Url(url.clone());
    }
    DevPortalSpecSource::File(String::new())
}

/// Load a file-backed OpenAPI spec: read the file, parse it as JSON,
/// extract the title and version. A read or parse failure is recorded
/// as an error entry (the portal still renders, listing the spec as
/// unavailable).
fn load_file_spec(path: &str, override_name: Option<&str>) -> LoadedSpec {
    let source = DevPortalSpecSource::File(path.to_string());
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return LoadedSpec {
                source,
                doc: None,
                name: override_name
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| file_stem(path).unwrap_or_else(|| path.to_string())),
                version: String::new(),
                error: Some(format!("read failed: {e}")),
            };
        }
    };
    match serde_json::from_str::<Value>(&content) {
        Ok(doc) => {
            let (name, version) = extract_title_version(&doc);
            LoadedSpec {
                source,
                doc: Some(doc),
                name: override_name
                    .map(|s| s.to_string())
                    .or(name)
                    .unwrap_or_else(|| file_stem(path).unwrap_or_else(|| path.to_string())),
                version: version.unwrap_or_default(),
                error: None,
            }
        }
        Err(e) => LoadedSpec {
            source,
            doc: None,
            name: override_name
                .map(|s| s.to_string())
                .unwrap_or_else(|| file_stem(path).unwrap_or_else(|| path.to_string())),
            version: String::new(),
            error: Some(format!("parse failed: {e}")),
        },
    }
}

/// Fetch a URL-backed OpenAPI spec at render time. Uses a blocking HTTP
/// GET (the portal render path is not the request hot path -- it is an
/// operator-facing static page). Returns the parsed document plus the
/// derived name and version.
fn fetch_url_spec(url: &str) -> Result<(Value, String, String), String> {
    // The portal render path is operator-facing and off the request hot
    // path; a blocking std HTTP client would need a dep, so we reuse
    // the std library's minimal HTTP/1.1 client via TcpStream. This is
    // deliberately minimal: no redirects, no TLS (http only here; https
    // URL specs are fetched by the dataplane's upstream client in a
    // future enhancement -- for now the portal lists them with a note).
    if url.starts_with("https://") {
        return Err(
            "https URL specs are not fetched by the portal renderer yet \
             (list the spec with its name/version from a file copy, or \
             expose the spec over http)"
                .to_string(),
        );
    }
    let (host, port, path) = parse_http_url(url)?;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream =
        TcpStream::connect((host.as_str(), port)).map_err(|e| format!("connect failed: {e}"))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    let body = extract_http_body(&buf)?;
    let doc: Value = serde_json::from_str(&body).map_err(|e| format!("parse failed: {e}"))?;
    let (name, version) = extract_title_version(&doc);
    Ok((
        doc,
        name.unwrap_or_else(|| host.clone()),
        version.unwrap_or_default(),
    ))
}

/// Parse an `http://host[:port]/path` URL into (host, port, path).
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "not an http URL".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.find(':') {
        Some(i) => {
            let h = &authority[..i];
            let p: u16 = authority[i + 1..]
                .parse()
                .map_err(|_| "invalid port".to_string())?;
            (h.to_string(), p)
        }
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

/// Extract the HTTP body from a raw response buffer (split on the
/// blank-line header/body separator).
fn extract_http_body(buf: &[u8]) -> Result<String, String> {
    let sep = b"\r\n\r\n";
    let idx = buf
        .windows(4)
        .position(|w| w == sep)
        .ok_or_else(|| "no header/body separator".to_string())?;
    let body = &buf[idx + 4..];
    String::from_utf8(body.to_vec()).map_err(|e| format!("body not utf-8: {e}"))
}

/// Extract the `info.title` and `info.version` from an OpenAPI doc.
fn extract_title_version(doc: &Value) -> (Option<String>, Option<String>) {
    let info = doc.get("info");
    let title = info
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    let version = info
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    (title, version)
}

/// The file stem (basename without extension) for a fallback display
/// name.
fn file_stem(path: &str) -> Option<String> {
    let base = path.rsplit('/').next()?;
    let stem = base.rsplit_once('.').map(|(s, _)| s).unwrap_or(base);
    Some(stem.to_string())
}

/// The host portion of a URL (for a fallback display name).
fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split('/').next()?;
    let host = authority.split(':').next()?;
    Some(host.to_string())
}

/// Render the portal HTML page from the loaded specs.
fn render_portal_html(specs: &[LoadedSpec]) -> String {
    let mut rows = String::new();
    if specs.is_empty() {
        rows.push_str(
            "      <tr><td colspan=\"4\" class=\"empty\">No APIs configured yet. \
             Add OpenAPI spec sources to the <code>lifecycle.portal.specs</code> \
             config block.</td></tr>\n",
        );
    } else {
        for spec in specs {
            let status = if let Some(e) = &spec.error {
                format!("<span class=\"error\">unavailable: {e}</span>")
            } else {
                "<span class=\"ok\">available</span>".to_string()
            };
            let link = match &spec.source {
                DevPortalSpecSource::File(p) => {
                    format!("<code>{}</code>", html_escape(p))
                }
                DevPortalSpecSource::Url(u) => {
                    format!(
                        "<a href=\"{}\" target=\"_blank\">{}</a>",
                        html_escape(u),
                        html_escape(u)
                    )
                }
            };
            rows.push_str(&format!(
                "      <tr>\n        <td>{}</td>\n        <td>{}</td>\n        \
                 <td>{}</td>\n        <td>{}</td>\n      </tr>\n",
                html_escape(&spec.name),
                html_escape(&spec.version),
                link,
                status,
            ));
        }
    }
    format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
  <meta charset=\"utf-8\">\n\
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
  <title>dwara developer portal</title>\n\
  <style>\n\
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}\n\
    h1 {{ font-size: 1.5rem; }}\n\
    table {{ border-collapse: collapse; width: 100%; }}\n\
    th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; }}\n\
    th {{ background: #f5f5f5; }}\n\
    .empty {{ color: #888; font-style: italic; }}\n\
    .ok {{ color: #2a7d2a; }}\n\
    .error {{ color: #b00; }}\n\
    code {{ background: #f5f5f5; padding: 0.1rem 0.3rem; border-radius: 3px; }}\n\
  </style>\n\
</head>\n\
<body>\n\
  <h1>dwara developer portal</h1>\n\
  <p>The APIs the gateway fronts, aggregated from the configured OpenAPI \
specs. This is a read-only listing -- spec management is via config.</p>\n\
  <table>\n\
    <thead>\n\
      <tr><th>API</th><th>Version</th><th>Spec</th><th>Status</th></tr>\n\
    </thead>\n\
    <tbody>\n\
{rows}\
    </tbody>\n\
  </table>\n\
</body>\n\
</html>\n",
        rows = rows,
    )
}

/// HTML-escape a string for safe interpolation into the portal page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
