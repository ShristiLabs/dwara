//! Plugin publish tooling (DW-164, #282).
//!
//! The author-side half of the plugin registry: `dwara plugin keygen`,
//! `plugin sign`, and `plugin publish`. The reader-side (`plugin
//! search` / `plugin install`) lives in [`crate::plugin_registry`].
//!
//! - `keygen` generates an Ed25519 keypair. The public key (32 bytes,
//!   hex) goes into registry entries as `public_key`; the private key
//!   never leaves the author's machine. `--out-dir` writes
//!   `plugin.pub` (world-readable) and `plugin.key` (owner-only,
//!   0600), refusing to overwrite existing files.
//! - `sign` produces a detached Ed25519 signature (64 bytes, hex) over
//!   the artifact bytes — the exact bytes whose SHA-256 is the
//!   manifest `digest`, so digest and signature bind to the same
//!   artifact content.
//! - `publish` reads the built `.wasm` from disk, computes its
//!   SHA-256, optionally signs it, and emits a registry manifest entry
//!   (`{name, version, digest, url}` plus `signature`/`public_key`
//!   when signed) ready to paste into the registry's `manifest.json`.
//!   With `--pr` it opens the pull request itself.
//!
//! ## Manifest shape and tolerance
//!
//! The registry manifest is a JSON array of entries; the install
//! reader parses it as `Vec<serde_json::Value>`, so extra fields are
//! tolerated by construction. The typed [`ManifestEntry`] here
//! deliberately does NOT use `deny_unknown_fields`: this is an
//! external interchange format, not gateway config — strict-serde's
//! job is to catch operator typos in `dwara.yaml`, while a reader
//! that rejects unknown registry fields would break on every future
//! manifest addition. The merge path ([`merge_manifest`]) therefore
//! operates on raw JSON values, preserving unknown fields of entries
//! it does not touch.
//!
//! ## Lean-deps pattern
//!
//! Like `plugin install` (external `curl`), the `--pr` flow shells out
//! to the GitHub CLI (`gh`) instead of embedding a GitHub API client:
//! `gh api` drives the git data endpoints (blob, tree, commit, ref)
//! and `gh pr create` opens the PR. The flow is best-effort: it tries
//! a branch on the target repository first and falls back to a fork
//! (for authors without write access); on any failure the printed
//! manifest entry is still valid for a manual PR.
//!
//! ## Done-when
//!
//! An author can go from a built `.wasm` to an open registry PR with
//! one command, with a digest verified against the artifact on disk.

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The default repository hosting the registry manifest (the dwara
/// community plugin registry).
pub const DEFAULT_REGISTRY_REPO: &str = "shristilabs/dwara-plugins";

/// The manifest file inside the registry repository.
const MANIFEST_PATH: &str = "manifest.json";

/// A freshly generated Ed25519 keypair, hex-encoded.
#[derive(Debug, Clone)]
pub struct GeneratedKeypair {
    /// The public key (verifying key): 32 bytes, 64 hex chars.
    /// Safe to publish; this is the manifest's `public_key`.
    pub public_key: String,
    /// The private key (signing key seed): 32 bytes, 64 hex chars.
    /// Secret; this signs artifacts.
    pub private_key: String,
}

/// Where `keygen --out-dir` wrote the keypair.
#[derive(Debug)]
pub struct WrittenKeypair {
    /// Path of the public key file (`plugin.pub`).
    pub public_path: String,
    /// Path of the private key file (`plugin.key`, mode 0600).
    pub private_path: String,
}

/// One registry manifest entry. See the module docs for the tolerance
/// rationale (no `deny_unknown_fields`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// The plugin name (registry-wide identifier).
    pub name: String,
    /// The plugin version (the artifact this entry points at).
    pub version: String,
    /// The SHA-256 hex digest of the `.wasm` artifact bytes.
    pub digest: String,
    /// Where the artifact is hosted.
    pub url: String,
    /// Ed25519 signature (hex, 64 bytes) over the artifact bytes.
    /// Present only for signed plugins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Ed25519 public key (hex, 32 bytes) that verifies `signature`.
    /// Present only for signed plugins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// `plugin keygen`: generate a fresh Ed25519 keypair. `OsRng` cannot
/// fail (the OS entropy source is infallible), so neither can this.
pub fn keygen() -> GeneratedKeypair {
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    GeneratedKeypair {
        public_key: to_hex(signing.verifying_key().as_bytes()),
        private_key: to_hex(signing.as_bytes()),
    }
}

/// `plugin keygen --out-dir`: write the keypair to `<dir>/plugin.pub`
/// and `<dir>/plugin.key`. The private key is owner-only (0600 on
/// Unix). Existing files are never overwritten — a silent overwrite
/// could strand artifacts signed with the old key.
pub fn write_keypair(dir: &str) -> Result<WrittenKeypair, String> {
    let dir_path = std::path::Path::new(dir);
    std::fs::create_dir_all(dir_path).map_err(|e| format!("cannot create dir {dir}: {e}"))?;
    let public_path = dir_path.join("plugin.pub");
    let private_path = dir_path.join("plugin.key");
    for path in [&public_path, &private_path] {
        if path.exists() {
            return Err(format!(
                "refusing to overwrite existing {} (move it away or pick another --out-dir)",
                path.display()
            ));
        }
    }
    let kp = keygen();
    std::fs::write(&public_path, &kp.public_key)
        .map_err(|e| format!("cannot write {}: {e}", public_path.display()))?;
    std::fs::write(&private_path, &kp.private_key)
        .map_err(|e| format!("cannot write {}: {e}", private_path.display()))?;
    restrict_permissions(&private_path)?;
    Ok(WrittenKeypair {
        public_path: public_path.display().to_string(),
        private_path: private_path.display().to_string(),
    })
}

/// Restrict a file to owner-only (0600). A no-op on non-Unix platforms
/// (the CLI's deploy targets are Unix; the key content is still only
/// what the operator's umask allows).
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot set permissions on {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

/// Load a signing key from a path to a hex key file (as written by
/// `keygen --out-dir`) or from a literal hex string on the command
/// line. This keeps `--key` scriptable either way.
pub fn load_signing_key(key: &str) -> Result<SigningKey, String> {
    let hex = if std::path::Path::new(key).exists() {
        std::fs::read_to_string(key)
            .map_err(|e| format!("cannot read key file {key}: {e}"))?
            .trim()
            .to_string()
    } else {
        key.trim().to_string()
    };
    let bytes = parse_hex(&hex).map_err(|e| format!("invalid signing key: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "invalid signing key: must be 32 bytes (64 hex chars)".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// The hex public key of a signing key (what goes into the manifest's
/// `public_key` field).
pub fn public_key_hex(key: &SigningKey) -> String {
    to_hex(key.verifying_key().as_bytes())
}

/// `plugin sign`: Ed25519 signature over the artifact bytes, hex.
/// Deterministic for a given key and artifact.
pub fn sign_artifact(key: &SigningKey, artifact: &[u8]) -> String {
    to_hex(&key.sign(artifact).to_bytes())
}

/// Verify a hex signature against the artifact bytes with a hex
/// public key — the same check the gateway-side verification performs
/// on load. Ok(()) when the signature matches.
pub fn verify_artifact(
    public_key_hex: &str,
    signature_hex: &str,
    artifact: &[u8],
) -> Result<(), String> {
    let key_bytes = parse_hex(public_key_hex).map_err(|e| format!("invalid public key: {e}"))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid public key: must be 32 bytes (64 hex chars)".to_string())?;
    let verifying =
        VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("invalid public key: {e}"))?;
    let sig_bytes = parse_hex(signature_hex).map_err(|e| format!("invalid signature: {e}"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "invalid signature: must be 64 bytes (128 hex chars)".to_string())?;
    verifying
        .verify(artifact, &Signature::from_bytes(&sig_bytes))
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Build a manifest entry from the artifact bytes read from disk.
///
/// The digest is computed from `artifact` itself (the on-disk bytes —
/// the same bytes a registry download verifies), the URL defaults to
/// `<registry_base>/<name>-<version>.wasm`, and when `signing_key` is
/// given the entry carries `signature` + `public_key`, self-verified
/// against the artifact before the entry is returned so a broken
/// signature can never reach a manifest.
pub fn build_entry(
    artifact: &[u8],
    name: &str,
    version: &str,
    url: Option<&str>,
    registry_base: &str,
    signing_key: Option<&SigningKey>,
) -> Result<ManifestEntry, String> {
    if artifact.is_empty() {
        return Err("artifact is empty (did the build produce a .wasm?)".to_string());
    }
    validate_name(name)?;
    validate_version(version)?;
    let digest = crate::plugin_registry::sha256_hex(artifact);
    let url = match url {
        Some(u) => u.to_string(),
        None => format!(
            "{}/{name}-{version}.wasm",
            registry_base.trim_end_matches('/')
        ),
    };
    let (signature, public_key) = match signing_key {
        Some(key) => {
            let sig = sign_artifact(key, artifact);
            let pk = public_key_hex(key);
            verify_artifact(&pk, &sig, artifact)?;
            (Some(sig), Some(pk))
        }
        None => (None, None),
    };
    Ok(ManifestEntry {
        name: name.to_string(),
        version: version.to_string(),
        digest,
        url,
        signature,
        public_key,
    })
}

/// Serialize an entry as the ready-to-paste JSON object (pretty, one
/// field per line, keys in serde_json's default alphabetical order —
/// matching the registry manifest's formatting).
pub fn entry_json(entry: &ManifestEntry) -> Result<String, String> {
    let mut out = serde_json::to_string_pretty(entry)
        .map_err(|e| format!("cannot serialize manifest entry: {e}"))?;
    out.push('\n');
    Ok(out)
}

/// Merge an entry into a registry manifest (a JSON array).
///
/// The existing entry with the same `name` AND `version` is replaced
/// (re-publishing an identical version is an update, not a duplicate);
/// any other entry is preserved value-for-value with unknown fields
/// intact, and entry ORDER is stable (untouched entries keep their
/// positions in the array). The merge operates on raw JSON values,
/// not typed entries, so it never drops data it does not understand.
///
/// The whole manifest is re-serialized with one consistent format
/// (serde_json pretty-printed, object keys in its default sorted
/// order), so untouched entries may reindent or reorder their keys in
/// the committed file even though their values never change — values
/// are byte-identical, formatting is not. The consistent formatting
/// keeps PR diffs limited to the entries that actually changed after
/// the first such reformat. Returns the full merged manifest
/// (pretty-printed with a trailing newline).
pub fn merge_manifest(existing: &str, entry: &ManifestEntry) -> Result<String, String> {
    let mut arr: Vec<serde_json::Value> = if existing.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("registry manifest is not a JSON array: {e}"))?
    };
    let new_value =
        serde_json::to_value(entry).map_err(|e| format!("cannot serialize entry: {e}"))?;
    match arr.iter_mut().find(|v| {
        v.get("name").and_then(serde_json::Value::as_str) == Some(entry.name.as_str())
            && v.get("version").and_then(serde_json::Value::as_str) == Some(entry.version.as_str())
    }) {
        Some(slot) => *slot = new_value,
        None => arr.push(new_value),
    }
    let mut out = serde_json::to_string_pretty(&arr)
        .map_err(|e| format!("cannot serialize manifest: {e}"))?;
    out.push('\n');
    Ok(out)
}

/// The branch name for a publish PR: `plugin/<name>-<version>` with
/// characters git refs reject replaced by `-`.
pub fn branch_name(name: &str, version: &str) -> String {
    format!("plugin/{}-{}", sanitize_ref(name), sanitize_ref(version))
}

/// Map a string onto the git-ref-safe alphabet [A-Za-z0-9._+-] (`+` is
/// valid in ref names and common in semver build metadata).
fn sanitize_ref(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Registry plugin names follow the scaffold's crate-name rules so a
/// `plugin new` project can publish under its own name.
fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("plugin name cannot be empty".to_string());
    }
    if name.len() > 64 {
        return Err("plugin name cannot be longer than 64 characters".to_string());
    }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(format!(
            "plugin name must start with a letter or underscore, got '{first}'"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "plugin name can only contain letters, digits, underscores, and hyphens".to_string(),
        );
    }
    Ok(())
}

/// Versions accept the semver character set (digits, letters, `.`,
/// `+`, `-`). A full semver parse is deliberately not enforced: the
/// registry treats versions as opaque strings, and the URL derives
/// from them verbatim.
fn validate_version(version: &str) -> Result<(), String> {
    if version.is_empty() {
        return Err("version cannot be empty".to_string());
    }
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
    {
        return Err("version can only contain letters, digits, '.', '+', and '-'".to_string());
    }
    Ok(())
}

/// `OWNER/NAME` GitHub repository reference (e.g. the default
/// `shristilabs/dwara-plugins`).
fn validate_repo(repo: &str) -> Result<(), String> {
    let (owner, name) = repo.split_once('/').ok_or_else(|| {
        format!("repository must be OWNER/NAME (e.g. {DEFAULT_REGISTRY_REPO}), got '{repo}'")
    })?;
    for part in [owner, name] {
        if part.is_empty()
            || !part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(format!("invalid repository reference '{repo}'"));
        }
    }
    Ok(())
}

/// A git branch name safe to pass through `gh api` paths and args.
fn validate_branch(branch: &str) -> Result<(), String> {
    if branch.is_empty()
        || branch.starts_with('-')
        || !branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return Err(format!("invalid branch name '{branch}'"));
    }
    Ok(())
}

/// Open the registry PR for an entry, best-effort via the `gh` CLI.
///
/// Flow: fetch the registry's current `manifest.json`, merge the
/// entry, commit the merged manifest to a `plugin/<name>-<version>`
/// branch (git data API: blob -> tree -> commit -> ref), and open a
/// PR. The branch is created on the target repository first; if that
/// fails (usually no write access), the same commit lands on a fork
/// (`gh repo fork`) and the PR head becomes `<login>:<branch>`.
/// Returns the PR URL.
pub fn open_registry_pr(repo: &str, base: &str, entry: &ManifestEntry) -> Result<String, String> {
    validate_repo(repo)?;
    validate_branch(base)?;
    if !gh_available() {
        return Err(
            "the GitHub CLI (gh) is not installed or not on PATH; install it from \
             https://cli.github.com/ or open the PR manually with the printed entry"
                .to_string(),
        );
    }
    let branch = branch_name(&entry.name, &entry.version);
    let current = fetch_manifest(repo)?;
    let merged = merge_manifest(&current, entry)?;

    match commit_manifest_branch(repo, base, &branch, &merged, entry) {
        Ok(()) => create_pr(repo, &branch, base, entry),
        Err(direct_err) => {
            let fork = ensure_fork(repo).map_err(|e| {
                format!("cannot push to {repo} ({direct_err}) and cannot fork: {e}")
            })?;
            commit_manifest_branch(&fork, base, &branch, &merged, entry).map_err(|e| {
                format!("cannot push to {repo} ({direct_err}); pushing to fork {fork} failed: {e}")
            })?;
            let fork_owner = fork.split_once('/').map(|(o, _)| o).unwrap_or_default();
            let head = format!("{fork_owner}:{branch}");
            create_pr(repo, &head, base, entry)
        }
    }
}

/// Fetch the registry repository's current manifest via `gh api`
/// (raw accept header). The repository itself is probed first: a 404
/// on `repos/{repo}` means a bad (or inaccessible) `--repo` and fails
/// fast with the repo name — GitHub's stderr for a missing repo and a
/// missing manifest path is identical, and treating the former as
/// "fresh registry" would push the failure into a confusing fork
/// fallback. Only then does a 404 on the manifest path start a fresh
/// `[]` — the first publish into a new registry.
fn fetch_manifest(repo: &str) -> Result<String, String> {
    if let Err(e) = gh_api(&[&format!("repos/{repo}")], None) {
        if e.contains("404") {
            return Err(format!(
                "repository '{repo}' not found or not accessible (is --repo correct?)"
            ));
        }
        return Err(e);
    }
    match gh_api(
        &[
            &format!("repos/{repo}/contents/{MANIFEST_PATH}"),
            "-H",
            "Accept: application/vnd.github.raw",
        ],
        None,
    ) {
        Ok(body) => Ok(body),
        Err(e) if e.contains("404") => Ok("[]".to_string()),
        Err(e) => Err(e),
    }
}

/// Commit the merged manifest to a branch on `repo` using the git
/// data API (blob -> tree on top of the base tree -> commit with the
/// base as parent -> ref creation). All payloads are JSON built with
/// serde_json, so manifest content with any characters is escaped
/// safely; `encoding: utf-8` sends the JSON text without base64.
///
/// On a re-run after partial success (branch pushed, PR step failed),
/// ref creation fails with "Reference already exists"; when the
/// branch is ours (its name matches the generated one), the existing
/// ref is force-moved to the fresh commit instead — the branch is a
/// throwaway PR head this tool owns, and this keeps re-runs from
/// falling into the fork fallback. Any other ref-creation error
/// (permissions, protected refs) propagates to the caller, where the
/// fork fallback handles it.
fn commit_manifest_branch(
    repo: &str,
    base: &str,
    branch: &str,
    merged_manifest: &str,
    entry: &ManifestEntry,
) -> Result<(), String> {
    let base_sha = gh_api(
        &[
            &format!("repos/{repo}/git/ref/heads/{base}"),
            "--jq",
            ".object.sha",
        ],
        None,
    )?;
    let base_tree = gh_api(
        &[
            &format!("repos/{repo}/git/commits/{base_sha}"),
            "--jq",
            ".tree.sha",
        ],
        None,
    )?;
    let blob = serde_json::json!({"content": merged_manifest, "encoding": "utf-8"});
    let blob_sha = gh_api(
        &[
            &format!("repos/{repo}/git/blobs"),
            "--input",
            "-",
            "--jq",
            ".sha",
        ],
        Some(&blob.to_string()),
    )?;
    let tree = serde_json::json!({
        "base_tree": base_tree,
        "tree": [{
            "path": MANIFEST_PATH,
            "mode": "100644",
            "type": "blob",
            "sha": blob_sha,
        }],
    });
    let tree_sha = gh_api(
        &[
            &format!("repos/{repo}/git/trees"),
            "--input",
            "-",
            "--jq",
            ".sha",
        ],
        Some(&tree.to_string()),
    )?;
    let commit = serde_json::json!({
        "message": commit_message(entry),
        "tree": tree_sha,
        "parents": [base_sha],
    });
    let commit_sha = gh_api(
        &[
            &format!("repos/{repo}/git/commits"),
            "--input",
            "-",
            "--jq",
            ".sha",
        ],
        Some(&commit.to_string()),
    )?;
    let reference = serde_json::json!({"ref": format!("refs/heads/{branch}"), "sha": commit_sha});
    if let Err(e) = gh_api(
        &[&format!("repos/{repo}/git/refs"), "--input", "-"],
        Some(&reference.to_string()),
    ) {
        if e.contains("Reference already exists")
            && branch == branch_name(&entry.name, &entry.version)
        {
            let patch = serde_json::json!({"sha": commit_sha, "force": true});
            return gh_api(
                &[
                    &format!("repos/{repo}/git/refs/heads/{branch}"),
                    "--input",
                    "-",
                    "-X",
                    "PATCH",
                ],
                Some(&patch.to_string()),
            )
            .map(|_| ());
        }
        return Err(e);
    }
    Ok(())
}

/// Ensure a fork of `repo` exists for the authenticated user and
/// return its full name (`<login>/<name>`). `gh repo fork` is
/// idempotent (an existing fork succeeds), so this doubles as the
/// permissions fallback's setup step.
fn ensure_fork(repo: &str) -> Result<String, String> {
    gh(&["repo", "fork", repo, "--clone=false"])?;
    let login = gh(&["api", "user", "--jq", ".login"])?;
    let short = repo.split_once('/').map(|(_, n)| n).unwrap_or_default();
    Ok(format!("{login}/{short}"))
}

/// Open the pull request and return its URL.
fn create_pr(repo: &str, head: &str, base: &str, entry: &ManifestEntry) -> Result<String, String> {
    gh(&[
        "pr",
        "create",
        "--repo",
        repo,
        "--head",
        head,
        "--base",
        base,
        "--title",
        &format!("plugin: publish {} {}", entry.name, entry.version),
        "--body",
        &pr_body(entry),
    ])
}

/// The commit message for the manifest update.
fn commit_message(entry: &ManifestEntry) -> String {
    format!("plugin: publish {} {}", entry.name, entry.version)
}

/// The PR body: what a registry reviewer needs to check the entry
/// (name, version, digest, URL, signature state). No secrets.
fn pr_body(entry: &ManifestEntry) -> String {
    let signed = match (&entry.signature, &entry.public_key) {
        (Some(sig), Some(pk)) => format!("yes (Ed25519; public key {pk})\nsignature: {sig}"),
        _ => "no".to_string(),
    };
    format!(
        "Adds plugin `{name}` version `{version}` to the registry manifest.\n\n\
         | field | value |\n|---|---|\n\
         | name | `{name}` |\n| version | `{version}` |\n\
         | digest | `{digest}` |\n| url | {url} |\n| signed | {signed} |\n\n\
         Generated by `dwara-cli plugin publish`.",
        name = entry.name,
        version = entry.version,
        digest = entry.digest,
        url = entry.url,
        signed = signed,
    )
}

/// Whether the `gh` CLI is installed and runnable.
fn gh_available() -> bool {
    std::process::Command::new("gh")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Run a `gh` subcommand and return its trimmed stdout.
fn gh(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("gh")
        .args(args)
        .output()
        .map_err(|e| format!("gh (is the GitHub CLI installed?): {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "gh {} failed: {stderr}",
            args.first().unwrap_or(&"")
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run `gh api` with optional JSON request bodies piped over stdin
/// (`--input -`). Stdin is written then dropped (EOF) before the
/// output is collected; a broken pipe (gh exiting early on an API
/// error) surfaces as gh's own stderr, not a write error.
fn gh_api(args: &[&str], body: Option<&str>) -> Result<String, String> {
    let mut cmd = std::process::Command::new("gh");
    cmd.arg("api").args(args);
    let output = match body {
        None => cmd
            .output()
            .map_err(|e| format!("gh (is the GitHub CLI installed?): {e}"))?,
        Some(body) => {
            use std::io::Write as _;
            cmd.stdin(std::process::Stdio::piped());
            let mut child = cmd
                .spawn()
                .map_err(|e| format!("gh (is the GitHub CLI installed?): {e}"))?;
            {
                let mut stdin = child.stdin.take().unwrap();
                // A write failure means gh exited before reading (API
                // error); fall through so its stderr is reported.
                let _ = stdin.write_all(body.as_bytes());
            }
            child
                .wait_with_output()
                .map_err(|e| format!("gh api: {e}"))?
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("gh api failed: {stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Lowercase hex encoding of the input bytes.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("hex write is infallible");
    }
    hex
}

/// Decode a (trimmed) hex string to bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have an even number of characters".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

/// The value of a single hex digit.
fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex character '{}'", c as char)),
    }
}
