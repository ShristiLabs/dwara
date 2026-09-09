//! Config includes and file-based profiles (CFG-01, #180).
//!
//! A config document may carry a top-level `includes:` key listing file
//! paths or directory globs (relative to the config file's directory).
//! [`resolve_includes`] reads each, recursively resolves includes in
//! them, and merges the result into the base document with conflict
//! detection: the same scalar key set in two documents is an error
//! (forces the operator to be explicit), while collection keys
//! (`listeners`, `routes`, `upstreams`, ...) from an include REPLACE
//! the base's (an include is a full topology overlay, not a delta).
//!
//! File-based profiles: when `gateway.lifecycle.profiles.profiles_dir`
//! is set, the selected profile's patch is loaded from
//! `<profiles_dir>/<profile>.yaml` instead of an inline YAML string.
//! [`apply_profile_overlay`] resolves the profile (from an explicit
//! name or the `DWARA_PROFILE` env var) and merges the patch onto the
//! base. This is backward compatible: inline `profile_overrides` still
//! work when `profiles_dir` is absent.
//!
//! Both operate on raw YAML text BEFORE [`super::parse_gateway`], so
//! the `includes:` / `profiles_dir` directives are consumed and never
//! reach the strict `deny_unknown_fields` Gateway struct.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Resolve `includes:` directives in a config document. The
/// `includes:` top-level key lists file paths or directory globs
/// (relative to `base_dir`). Each is read, recursively resolved, and
/// merged into the base. The `includes:` key is removed from the
/// result. Returns the merged YAML text.
pub fn resolve_includes(text: &str, base_dir: &Path) -> Result<String, String> {
    let mut doc: Value = serde_yaml_ng::from_str(text)
        .map_err(|e| format!("includes: cannot parse config as YAML: {e}"))?;
    let includes = extract_includes(&mut doc);
    if includes.is_empty() {
        // No includes: return the original text unchanged (avoid a
        // round-trip that could reorder keys).
        return Ok(text.to_string());
    }
    for pattern in includes {
        let paths = expand_glob(&pattern, base_dir)?;
        for path in paths {
            let inc_dir = path.parent().unwrap_or(base_dir).to_path_buf();
            let inc_text = std::fs::read_to_string(&path)
                .map_err(|e| format!("includes: cannot read {}: {e}", path.display()))?;
            let inc_resolved = resolve_includes(&inc_text, &inc_dir)?;
            let inc_doc: Value = serde_yaml_ng::from_str(&inc_resolved)
                .map_err(|e| format!("includes: cannot parse {}: {e}", path.display()))?;
            doc = merge_with_conflict_detection(&doc, &inc_doc, &path.display().to_string())?;
        }
    }
    serde_yaml_ng::to_string(&doc).map_err(|e| format!("includes: serialize failed: {e}"))
}

/// Apply the selected profile's overlay onto the base config. The
/// profile is `profile` when given, else the `DWARA_PROFILE` env var.
/// When `gateway.lifecycle.profiles.profiles_dir` is set, the patch is
/// loaded from `<profiles_dir>/<profile>.yaml`; otherwise the inline
/// `profile_overrides` map is used (backward compat). The merged YAML
/// text is returned.
pub fn apply_profile_overlay(
    text: &str,
    base_dir: &Path,
    profile: Option<&str>,
) -> Result<String, String> {
    let profile = profile
        .map(|s| s.to_string())
        .or_else(|| std::env::var("DWARA_PROFILE").ok())
        .filter(|s| !s.trim().is_empty());
    let Some(profile) = profile else {
        return Ok(text.to_string());
    };
    let doc: Value = serde_yaml_ng::from_str(text)
        .map_err(|e| format!("profile: cannot parse config as YAML: {e}"))?;
    // Navigate to gateway.lifecycle.profiles.
    let profiles = doc
        .get("gateway")
        .and_then(|g| g.get("lifecycle"))
        .and_then(|l| l.get("profiles"));
    let Some(profiles) = profiles else {
        return Ok(text.to_string());
    };
    // File-based profiles take precedence when profiles_dir is set.
    if let Some(dir) = profiles.get("profiles_dir").and_then(Value::as_str) {
        let profiles_dir = resolve_path(base_dir, dir);
        let profile_file = profiles_dir.join(format!("{profile}.yaml"));
        let patch_text = std::fs::read_to_string(&profile_file).map_err(|e| {
            format!(
                "profile: cannot read {} (profiles_dir={}, profile={profile}): {e}",
                profile_file.display(),
                profiles_dir.display()
            )
        })?;
        let patch: Value = serde_yaml_ng::from_str(&patch_text)
            .map_err(|e| format!("profile: cannot parse {}: {e}", profile_file.display()))?;
        let merged = shallow_merge(&doc, &patch);
        return serde_yaml_ng::to_string(&merged)
            .map_err(|e| format!("profile: serialize failed: {e}"));
    }
    // Inline profile_overrides (backward compat).
    if let Some(overrides) = profiles.get("profile_overrides").and_then(Value::as_object) {
        if let Some(patch_yaml) = overrides.get(&profile).and_then(Value::as_str) {
            let patch: Value = serde_yaml_ng::from_str(patch_yaml)
                .map_err(|e| format!("profile: cannot parse inline patch for {profile}: {e}"))?;
            let merged = shallow_merge(&doc, &patch);
            return serde_yaml_ng::to_string(&merged)
                .map_err(|e| format!("profile: serialize failed: {e}"));
        }
    }
    // Profile selected but no patch found: return base unchanged.
    Ok(text.to_string())
}

/// Full preprocessing: resolve includes, then apply the profile.
pub fn preprocess(text: &str, base_dir: &Path, profile: Option<&str>) -> Result<String, String> {
    let with_includes = resolve_includes(text, base_dir)?;
    apply_profile_overlay(&with_includes, base_dir, profile)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Extract and remove the `includes:` key from a YAML document. Returns
/// the list of include patterns (file paths or globs).
fn extract_includes(doc: &mut Value) -> Vec<String> {
    let Some(map) = doc.as_object_mut() else {
        return Vec::new();
    };
    let Some(includes_val) = map.remove("includes") else {
        return Vec::new();
    };
    match includes_val {
        Value::String(s) => vec![s],
        Value::Array(arr) => arr
            .into_iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Expand a glob pattern relative to `base_dir`. Supports:
/// - exact file paths (`configs/base.yaml`)
/// - directory paths (`configs/` — all `*.yaml`/`*.yml` inside, sorted)
/// - simple `*` globs (`configs/*.yaml`)
///
/// Returns sorted, deduplicated paths.
fn expand_glob(pattern: &str, base_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let resolved = resolve_path(base_dir, pattern);
    // Directory: read all yaml files inside.
    if resolved.is_dir() {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&resolved)
            .map_err(|e| format!("includes: cannot read dir {}: {e}", resolved.display()))?
        {
            let entry = entry.map_err(|e| format!("includes: dir entry: {e}"))?;
            let path = entry.path();
            if path.is_file() && matches_ext(&path, "yaml", "yml") {
                paths.push(path);
            }
        }
        paths.sort();
        return Ok(paths);
    }
    // Exact file.
    if resolved.is_file() {
        return Ok(vec![resolved]);
    }
    // Glob with '*': match against the parent directory's entries.
    let pattern_str = pattern.replace('\\', "/");
    if pattern_str.contains('*') {
        return expand_wildcard(&pattern_str, base_dir);
    }
    Err(format!(
        "includes: pattern '{}' resolved to '{}' which is not a file or directory",
        pattern,
        resolved.display()
    ))
}

/// Expand a simple wildcard pattern (supports `*` for any non-separator
/// chars and `**` for any chars including separators).
fn expand_wildcard(pattern: &str, base_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let full = resolve_path(base_dir, pattern);
    let parent = full.parent().unwrap_or(base_dir);
    if !parent.is_dir() {
        return Err(format!(
            "includes: glob parent dir {} does not exist",
            parent.display()
        ));
    }
    let glob_suffix = full.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(parent)
        .map_err(|e| format!("includes: cannot read glob dir {}: {e}", parent.display()))?
    {
        let entry = entry.map_err(|e| format!("includes: glob dir entry: {e}"))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if wildcard_match(glob_suffix, &name_str)
            && entry.path().is_file()
            && matches_ext(&entry.path(), "yaml", "yml")
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    if paths.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(paths)
    }
}

/// Match a glob pattern with `*` (any chars) against a string.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    // Simple recursive wildcard match: '*' matches any sequence.
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    wildcard_match_inner(&p, 0, &t, 0)
}

fn wildcard_match_inner(p: &[char], pi: usize, t: &[char], ti: usize) -> bool {
    if pi == p.len() {
        return ti == t.len();
    }
    if p[pi] == '*' {
        // '*' matches zero or more chars.
        if wildcard_match_inner(p, pi + 1, t, ti) {
            return true;
        }
        if ti < t.len() && wildcard_match_inner(p, pi, t, ti + 1) {
            return true;
        }
        return false;
    }
    if ti < t.len() && p[pi] == t[ti] {
        return wildcard_match_inner(p, pi + 1, t, ti + 1);
    }
    false
}

/// Resolve a path that may be relative to `base_dir` or absolute.
fn resolve_path(base_dir: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

/// Check if a path has one of the given extensions.
fn matches_ext(path: &Path, ext1: &str, ext2: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e == ext1 || e == ext2)
        .unwrap_or(false)
}

/// Shallow JSON merge: patch's top-level keys overwrite base's; keys
/// only in the base are preserved. No conflict detection (the caller
/// decides whether to use [`merge_with_conflict_detection`] instead).
fn shallow_merge(base: &Value, patch: &Value) -> Value {
    match (base, patch) {
        (Value::Object(base_map), Value::Object(patch_map)) => {
            let mut out = base_map.clone();
            for (k, v) in patch_map {
                out.insert(k.clone(), v.clone());
            }
            Value::Object(out)
        }
        _ => patch.clone(),
    }
}

/// Merge two YAML documents with conflict detection: the same SCALAR
/// key present in both is an error (forces explicitness). Collection
/// keys (arrays/objects) from the patch REPLACE the base's (an include
/// is a full overlay). `source` is the include file path for error
/// context.
fn merge_with_conflict_detection(
    base: &Value,
    patch: &Value,
    source: &str,
) -> Result<Value, String> {
    match (base, patch) {
        (Value::Object(base_map), Value::Object(patch_map)) => {
            let mut out = base_map.clone();
            for (k, patch_val) in patch_map {
                if let Some(base_val) = out.get(k) {
                    // Conflict on scalar keys (neither side is a collection).
                    if !is_collection(base_val) && !is_collection(patch_val) {
                        return Err(format!(
                            "includes: conflict on key '{k}' (scalar set in both \
                             base and {source}); move it to one file or make it a \
                             collection"
                        ));
                    }
                    // Collections: patch replaces base (full overlay).
                }
                out.insert(k.clone(), patch_val.clone());
            }
            Ok(Value::Object(out))
        }
        _ => Ok(patch.clone()),
    }
}

/// Whether a JSON value is a collection (array or object).
fn is_collection(v: &Value) -> bool {
    matches!(v, Value::Array(_) | Value::Object(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(content.as_bytes()).expect("write");
        path
    }

    #[test]
    fn resolve_includes_no_includes() {
        let dir = tmpdir();
        let text = "listeners: []\nroutes: []\n";
        let out = resolve_includes(text, dir.path()).unwrap();
        assert_eq!(out, text);
    }

    #[test]
    fn resolve_includes_single_file() {
        let dir = tmpdir();
        write(
            dir.path(),
            "base.yaml",
            "listeners:\n  - name: main\n    port: 8080\n",
        );
        write(
            dir.path(),
            "routes.yaml",
            "routes:\n  - name: api\n    path: /api\n",
        );
        let text = "includes: [routes.yaml]\nlisteners:\n  - name: main\n    port: 8080\n";
        let out = resolve_includes(text, dir.path()).unwrap();
        assert!(out.contains("routes:"));
        assert!(out.contains("listeners:"));
        assert!(!out.contains("includes:"));
    }

    #[test]
    fn resolve_includes_directory() {
        let dir = tmpdir();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        write(
            dir.path(),
            "conf.d/a.yaml",
            "routes:\n  - name: a\n    path: /a\n",
        );
        write(dir.path(), "conf.d/b.yaml", "upstreams:\n  - name: u1\n");
        let text = "includes: [conf.d]\nlisteners: []\n";
        let out = resolve_includes(text, dir.path()).unwrap();
        assert!(out.contains("routes:"));
        assert!(out.contains("upstreams:"));
    }

    #[test]
    fn resolve_includes_glob() {
        let dir = tmpdir();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        write(dir.path(), "conf.d/a.yaml", "routes:\n  - name: a\n");
        write(dir.path(), "conf.d/b.yaml", "upstreams:\n  - name: u1\n");
        write(dir.path(), "conf.d/readme.txt", "ignore me\n");
        let text = "includes: [\"conf.d/*.yaml\"]\nlisteners: []\n";
        let out = resolve_includes(text, dir.path()).unwrap();
        assert!(out.contains("routes:"));
        assert!(out.contains("upstreams:"));
    }

    #[test]
    fn resolve_includes_conflict_detected() {
        let dir = tmpdir();
        write(dir.path(), "base.yaml", "version: 1\n");
        write(dir.path(), "inc.yaml", "version: 2\n");
        let text = "includes: [inc.yaml]\nversion: 1\n";
        let err = resolve_includes(text, dir.path()).unwrap_err();
        assert!(err.contains("conflict"));
        assert!(err.contains("version"));
    }

    #[test]
    fn resolve_includes_recursive() {
        let dir = tmpdir();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        write(dir.path(), "sub/c.yaml", "consumers: []\n");
        write(dir.path(), "b.yaml", "includes: [sub/c.yaml]\nroutes: []\n");
        let text = "includes: [b.yaml]\nlisteners: []\n";
        let out = resolve_includes(text, dir.path()).unwrap();
        assert!(out.contains("consumers:"));
        assert!(out.contains("routes:"));
    }

    #[test]
    fn resolve_includes_collection_replaces_not_conflict() {
        let dir = tmpdir();
        write(dir.path(), "inc.yaml", "routes:\n  - name: r2\n");
        let text = "includes: [inc.yaml]\nroutes:\n  - name: r1\n";
        let out = resolve_includes(text, dir.path()).unwrap();
        // Collection keys replace, not conflict.
        assert!(out.contains("r2"));
    }

    #[test]
    fn apply_profile_overlay_no_profiles_block() {
        let dir = tmpdir();
        let text = "listeners: []\n";
        let out = apply_profile_overlay(text, dir.path(), Some("prod")).unwrap();
        assert_eq!(out, text);
    }

    #[test]
    fn apply_profile_overlay_file_based() {
        let dir = tmpdir();
        std::fs::create_dir(dir.path().join("profiles")).unwrap();
        write(
            dir.path(),
            "profiles/prod.yaml",
            "routes:\n  - name: prod-route\n",
        );
        let text =
            "gateway:\n  lifecycle:\n    profiles:\n      profiles_dir: profiles\nroutes: []\n";
        let out = apply_profile_overlay(text, dir.path(), Some("prod")).unwrap();
        assert!(out.contains("prod-route"));
    }

    #[test]
    fn apply_profile_overlay_inline() {
        let dir = tmpdir();
        let text = "gateway:\n  lifecycle:\n    profiles:\n    base_config: |\n      routes: []\n    profile_overrides:\n      prod: |\n        routes:\n          - name: prod-route\n";
        let out = apply_profile_overlay(text, dir.path(), Some("prod")).unwrap();
        assert!(out.contains("prod-route"));
    }

    #[test]
    fn apply_profile_overlay_none_selected() {
        let dir = tmpdir();
        let text = "listeners: []\n";
        let out = apply_profile_overlay(text, dir.path(), None).unwrap();
        assert_eq!(out, text);
    }

    #[test]
    fn preprocess_combines() {
        let dir = tmpdir();
        std::fs::create_dir(dir.path().join("profiles")).unwrap();
        write(
            dir.path(),
            "profiles/prod.yaml",
            "routes:\n  - name: prod-route\n",
        );
        write(dir.path(), "inc.yaml", "upstreams: []\n");
        let text =
            "includes: [inc.yaml]\ngateway:\n  lifecycle:\n    profiles:\n      profiles_dir: profiles\nroutes: []\n";
        let out = preprocess(text, dir.path(), Some("prod")).unwrap();
        assert!(out.contains("upstreams:"));
        assert!(out.contains("prod-route"));
    }

    #[test]
    fn wildcard_match_basic() {
        assert!(wildcard_match("*.yaml", "a.yaml"));
        assert!(wildcard_match("*.yaml", "config.yaml"));
        assert!(!wildcard_match("*.yaml", "a.txt"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*", "abc"));
        assert!(!wildcard_match("a*", "bcd"));
    }
}
