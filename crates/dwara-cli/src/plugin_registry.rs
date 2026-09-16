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

/// The default plugin registry URL (the dwara community registry,
/// served as a static site from the shristilabs/dwara-plugins repo;
/// registry.dwara.dev will CNAME here).
const DEFAULT_REGISTRY: &str = "https://shristilabs.github.io/dwara-plugins";

/// The result of a successful `plugin install` command.
#[derive(Debug)]
pub struct InstallResult {
    pub name: String,
    pub path: String,
    pub digest: String,
}

/// Resolve the registry URL: CLI arg > env var > default.
/// Shared with the publish tooling (`plugin_publish`), which derives
/// the default artifact URL from the same base, and with the CLI
/// binary's `plugin publish` dispatch (a separate crate, hence pub).
pub fn resolve_registry(registry: Option<&str>) -> String {
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

/// `dwara plugin install <name> [--version V] [--registry URL] [--digest HASH] [-o DIR]`
///
/// Fetches the plugin's manifest entry — the highest semantic version
/// listed for `name`, or the exact `--version` when given (see
/// [`select_entry`]) — downloads the .wasm artifact, verifies its
/// SHA-256 digest, and writes it to `<dir>/<name>.wasm`.
pub fn install(
    name: &str,
    version: Option<&str>,
    registry: Option<&str>,
    digest: Option<&str>,
    dir: &str,
) -> Result<InstallResult, String> {
    let base = resolve_registry(registry);
    let manifest_url = format!("{}/manifest.json", base.trim_end_matches('/'));
    let body = http_get_text(&manifest_url)?;
    let plugins: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| format!("invalid manifest JSON: {e}"))?;
    let entry = select_entry(&plugins, name, version)?;
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

/// Pick the manifest entry to install for `name`: the entry whose
/// `version` string equals `version` exactly when one is given,
/// otherwise the HIGHEST semantic version among the entries listed
/// for the name (a registry manifest can list several versions of
/// one plugin; the first entry with a matching name must not
/// silently win). Errors list the available versions so an exact
/// `--version` retry is one copy-paste away.
pub fn select_entry<'a>(
    plugins: &'a [serde_json::Value],
    name: &str,
    version: Option<&str>,
) -> Result<&'a serde_json::Value, String> {
    let matching: Vec<&serde_json::Value> = plugins
        .iter()
        .filter(|p| p.get("name").and_then(|v| v.as_str()) == Some(name))
        .collect();
    if matching.is_empty() {
        return Err(format!("plugin '{name}' not found in registry"));
    }
    let available: Vec<&str> = matching
        .iter()
        .filter_map(|p| p.get("version").and_then(|v| v.as_str()))
        .collect();
    if let Some(want) = version {
        return matching
            .into_iter()
            .find(|p| p.get("version").and_then(|v| v.as_str()) == Some(want))
            .ok_or_else(|| {
                format!(
                    "version '{want}' of plugin '{name}' not found in registry; available versions: {}",
                    available.join(", ")
                )
            });
    }
    let mut best: Option<(&serde_json::Value, SemVer)> = None;
    for p in matching {
        let raw = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let parsed = parse_semver(raw).map_err(|e| {
            format!(
                "cannot pick the highest version of plugin '{name}': {e}; \
                 available versions: {} (pass --version to choose one exactly)",
                available.join(", ")
            )
        })?;
        let greater = match &best {
            None => true,
            Some((_, prev)) => cmp_semver(&parsed, prev) == std::cmp::Ordering::Greater,
        };
        if greater {
            best = Some((p, parsed));
        }
    }
    best.map(|(p, _)| p)
        .ok_or_else(|| format!("plugin '{name}' not found in registry"))
}

/// A parsed semantic version. Only what ordering needs: the three
/// numeric core components and the dot-separated pre-release
/// identifiers. Build metadata (`+...`) is accepted and dropped —
/// per the semver spec it never affects precedence.
#[derive(Debug, PartialEq, Eq)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<PreId>,
}

/// One dot-separated pre-release identifier. Numeric identifiers
/// compare numerically and rank below alphanumeric ones, which
/// compare ASCII-lexically (semver spec).
#[derive(Debug, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Alpha(String),
}

/// Parse `MAJOR.MINOR.PATCH` with an optional `-prerelease` tag and
/// `+build` metadata (dropped). A minimal hand-rolled parse — the
/// registry only needs ordering, not a full semver implementation,
/// so no external semver crate enters the tree.
fn parse_semver(v: &str) -> Result<SemVer, String> {
    let core_pre = v.split('+').next().unwrap_or(v);
    let (core, pre) = match core_pre.split_once('-') {
        Some((c, p)) => (c, p),
        None => (core_pre, ""),
    };
    let mut parts = core.split('.');
    let major = parse_core_num(parts.next(), v)?;
    let minor = parse_core_num(parts.next(), v)?;
    let patch = parse_core_num(parts.next(), v)?;
    if parts.next().is_some() {
        return Err(not_semver(v));
    }
    let mut pre_ids = Vec::new();
    if !pre.is_empty() {
        for id in pre.split('.') {
            if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(not_semver(v));
            }
            pre_ids.push(if id.chars().all(|c| c.is_ascii_digit()) {
                PreId::Num(
                    id.parse::<u64>()
                        .map_err(|_| format!("'{v}' has a pre-release number out of range"))?,
                )
            } else {
                PreId::Alpha(id.to_string())
            });
        }
    }
    Ok(SemVer {
        major,
        minor,
        patch,
        pre: pre_ids,
    })
}

/// One `MAJOR.MINOR.PATCH` component: a non-empty run of digits.
fn parse_core_num(part: Option<&str>, v: &str) -> Result<u64, String> {
    let part = part.ok_or_else(|| not_semver(v))?;
    if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
        return Err(not_semver(v));
    }
    part.parse::<u64>().map_err(|_| not_semver(v))
}

fn not_semver(v: &str) -> String {
    format!("'{v}' is not a semantic version (MAJOR.MINOR.PATCH)")
}

/// Semver precedence: the numeric core fields first; a release
/// outranks any pre-release of the same core; pre-release identifier
/// lists compare pairwise, longer winning when all preceding are
/// equal.
fn cmp_semver(a: &SemVer, b: &SemVer) -> std::cmp::Ordering {
    a.major
        .cmp(&b.major)
        .then_with(|| a.minor.cmp(&b.minor))
        .then_with(|| a.patch.cmp(&b.patch))
        .then_with(|| cmp_pre(&a.pre, &b.pre))
}

/// Pre-release precedence: empty (a release) beats non-empty; equal
/// heads fall through to the remaining identifiers.
fn cmp_pre(a: &[PreId], b: &[PreId]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => cmp_pre_id(&a[0], &b[0]).then_with(|| cmp_pre(&a[1..], &b[1..])),
    }
}

fn cmp_pre_id(a: &PreId, b: &PreId) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (PreId::Num(x), PreId::Num(y)) => x.cmp(y),
        (PreId::Alpha(x), PreId::Alpha(y)) => x.cmp(y),
        (PreId::Num(_), PreId::Alpha(_)) => Ordering::Less,
        (PreId::Alpha(_), PreId::Num(_)) => Ordering::Greater,
    }
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
/// Shared with the publish tooling (`plugin_publish`), which computes
/// the registry manifest digest with the same implementation the
/// install path verifies against.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
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
