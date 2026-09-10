//! SCALE-12 (#192): Remote/signed plugin registry CLI.
//!
//! Provides `dwara plugin search` and `dwara plugin install` commands.
//! The registry is a simple HTTP endpoint that serves a JSON manifest
//! of available plugins and their .wasm artifacts. The CLI downloads
//! artifacts, verifies their SHA-256 digest, and writes them to the
//! specified output directory.
//!
//! This is a lean-dependency implementation: instead of embedding an
//! HTTPS client in the CLI (which would require adding TLS
//! dependencies), it uses `curl` as an external tool for HTTP(S)
//! fetches. This is consistent with the project's approach in #187
//! (Kafka REST Proxy) and #190 (external Parquet conversion). The
//! operator is expected to have `curl` installed (available on all
//! major platforms). The `sha2` crate (already in the workspace
//! dependency tree) is used for digest verification.

use sha2::{Digest, Sha256};

/// The default plugin registry URL (the dwara community registry).
const DEFAULT_REGISTRY: &str = "https://registry.dwara.dev/plugins";

/// The result of a successful `plugin install` command.
pub struct InstallResult {
    pub name: String,
    pub path: String,
    pub digest: String,
}

/// Resolve the registry URL: CLI arg > env var > default.
fn resolve_registry(registry: Option<&str>) -> String {
    registry
        .map(|s| s.to_string())
        .or_else(|| std::env::var("DWARA_PLUGIN_REGISTRY").ok())
        .unwrap_or_else(|| DEFAULT_REGISTRY.to_string())
}

/// `dwara plugin search [--registry URL] [query]`
///
/// Fetches the registry's manifest (a JSON array of plugin entries)
/// and filters by the optional query (substring match on plugin
/// names). Prints the matching plugin names, versions, and digests.
pub fn search(registry: Option<&str>, query: Option<&str>) -> Result<String, String> {
    let base = resolve_registry(registry);
    let manifest_url = format!("{}/manifest.json", base.trim_end_matches('/'));
    let body = http_get_text(&manifest_url)?;
    let plugins: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| format!("invalid manifest JSON: {e}"))?;
    let mut out = String::new();
    for p in &plugins {
        let name = p
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        if let Some(q) = query {
            if !name.to_lowercase().contains(&q.to_lowercase()) {
                continue;
            }
        }
        let version = p
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let digest = p
            .get("digest")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        out.push_str(&format!("{name}\t{version}\t{digest}\n"));
    }
    if out.is_empty() {
        Ok("(no plugins found)".to_string())
    } else {
        Ok(out)
    }
}

/// `dwara plugin install <name> [--registry URL] [--digest HASH] [-o DIR]`
///
/// Fetches the plugin's manifest entry, downloads the .wasm artifact,
/// verifies its SHA-256 digest, and writes it to `<dir>/<name>.wasm`.
pub fn install(
    name: &str,
    registry: Option<&str>,
    digest: Option<&str>,
    dir: &str,
) -> Result<InstallResult, String> {
    let base = resolve_registry(registry);
    let manifest_url = format!("{}/manifest.json", base.trim_end_matches('/'));
    let body = http_get_text(&manifest_url)?;
    let plugins: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| format!("invalid manifest JSON: {e}"))?;
    let entry = plugins
        .iter()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(name))
        .ok_or_else(|| format!("plugin '{name}' not found in registry"))?;
    let expected_digest = digest
        .map(|s| s.to_string())
        .or_else(|| {
            entry
                .get("digest")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| {
            format!("no digest provided and registry manifest has no digest for '{name}'")
        })?;
    let artifact_url = entry
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}/{}.wasm", base.trim_end_matches('/'), name));
    let wasm_bytes = http_get_bytes(&artifact_url)?;
    let actual_digest = sha256_hex(&wasm_bytes);
    if actual_digest != expected_digest {
        return Err(format!(
            "digest mismatch: expected {expected_digest}, got {actual_digest}"
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("create dir {dir}: {e}"))?;
    let path = format!("{dir}/{name}.wasm");
    std::fs::write(&path, &wasm_bytes).map_err(|e| format!("write {path}: {e}"))?;
    Ok(InstallResult {
        name: name.to_string(),
        path,
        digest: actual_digest,
    })
}

/// HTTP GET via `curl` (external tool). Returns the response body as
/// text. Uses `curl -sS --fail` for silent-but-error-reporting
/// behavior.
fn http_get_text(url: &str) -> Result<String, String> {
    let output = std::process::Command::new("curl")
        .arg("-sS")
        .arg("--fail")
        .arg("--max-time")
        .arg("30")
        .arg(url)
        .output()
        .map_err(|e| format!("curl (is curl installed?): {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {stderr}"));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("invalid UTF-8 in response: {e}"))
}

/// HTTP GET via `curl` (external tool). Returns the response body as
/// raw bytes.
fn http_get_bytes(url: &str) -> Result<Vec<u8>, String> {
    let output = std::process::Command::new("curl")
        .arg("-sS")
        .arg("--fail")
        .arg("--max-time")
        .arg("60")
        .arg(url)
        .output()
        .map_err(|e| format!("curl (is curl installed?): {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {stderr}"));
    }
    Ok(output.stdout)
}

/// SHA-256 hex digest of the input bytes.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    use std::fmt::Write;
    for byte in result.iter() {
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    hex
}
