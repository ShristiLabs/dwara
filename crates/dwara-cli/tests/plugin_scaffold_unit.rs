//! Unit tests for the plugin scaffolding module (`dwara_cli::plugin_scaffold`).
//!
//! These tests exercise the public `scaffold` function: generating a new
//! proxy-wasm plugin project from the default (hello-world) template or
//! from a vendored example (`--template`, DW-166 #284), verifying the
//! created files, and validating plugin name rules (empty, digit-start,
//! special characters, too long, max length, hyphens, underscores,
//! existing directory).

use dwara_cli::plugin_scaffold::scaffold;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn temp_dir() -> PathBuf {
    // Process id + wall clock + a monotonically increasing counter:
    // parallel tests within one process can observe the same clock
    // tick, and a colliding dir makes scaffold() fail with
    // "already exists" for a directory the test just made.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dwara-plugin-test-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn scaffold_creates_files() {
    let dir = temp_dir();
    let result = scaffold("my-plugin", dir.to_str().unwrap(), None).unwrap();

    assert_eq!(result.name, "my-plugin");
    assert!(result.files.iter().any(|f| f.ends_with("Cargo.toml")));
    assert!(result.files.iter().any(|f| f.ends_with("src/lib.rs")));
    assert!(result.files.iter().any(|f| f.ends_with("dwara.yaml")));
    assert!(result.files.iter().any(|f| f.ends_with("README.md")));
    assert!(result.files.iter().any(|f| f.ends_with(".gitignore")));

    // Check the files exist.
    for file in &result.files {
        assert!(Path::new(file).exists(), "file {file} should exist");
    }
}

#[test]
fn scaffold_cargo_toml_has_correct_name() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap(), None).unwrap();

    let cargo_toml = fs::read_to_string(dir.join("my-plugin/Cargo.toml")).unwrap();
    assert!(cargo_toml.contains("name = \"my-plugin\""));
    assert!(cargo_toml.contains("crate-type = [\"cdylib\"]"));
    assert!(cargo_toml.contains("proxy-wasm"));
}

#[test]
fn scaffold_lib_rs_has_phase_callbacks() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap(), None).unwrap();

    let lib_rs = fs::read_to_string(dir.join("my-plugin/src/lib.rs")).unwrap();
    assert!(lib_rs.contains("on_http_request_headers"));
    assert!(lib_rs.contains("on_http_response_headers"));
    assert!(lib_rs.contains("proxy_wasm"));
}

#[test]
fn scaffold_dwara_yaml_references_plugin() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap(), None).unwrap();

    let yaml = fs::read_to_string(dir.join("my-plugin/dwara.yaml")).unwrap();
    assert!(yaml.contains("my-plugin"));
    assert!(yaml.contains("request_headers"));
    assert!(yaml.contains("wasm32-wasip1"));
}

#[test]
fn scaffold_dwara_yaml_validates_as_generated() {
    // The generated manifest must pass the full CLI validate pipeline
    // (parse + validate + compile dry-run) without edits: a real
    // `action: { type: proxy }` on a sane prefix with its
    // service/upstream chain. Validation deliberately does not check
    // that the .wasm file exists yet.
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap(), None).unwrap();

    let yaml = fs::read_to_string(dir.join("my-plugin/dwara.yaml")).unwrap();
    match dwara_cli::validate_config_text(&yaml) {
        dwara_cli::ValidateOutcome::Valid { routes } => assert_eq!(routes, 1),
        dwara_cli::ValidateOutcome::Invalid(issues) => {
            panic!("as-generated dwara.yaml must validate, got: {issues:?}")
        }
    }
}

#[test]
fn scaffold_readme_has_build_instructions() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap(), None).unwrap();

    let readme = fs::read_to_string(dir.join("my-plugin/README.md")).unwrap();
    assert!(readme.contains("wasm32-wasip1"));
    assert!(readme.contains("cargo build --release --target wasm32-wasip1"));
}

#[test]
fn scaffold_rejects_empty_name() {
    let err = scaffold("", "/tmp", None).unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn scaffold_rejects_name_starting_with_digit() {
    let err = scaffold("123plugin", "/tmp", None).unwrap_err();
    assert!(err.contains("letter or underscore"));
}

#[test]
fn scaffold_rejects_name_with_special_chars() {
    let err = scaffold("my.plugin", "/tmp", None).unwrap_err();
    assert!(err.contains("letters, digits"));
}

#[test]
fn scaffold_rejects_existing_directory() {
    let dir = temp_dir();
    fs::create_dir_all(dir.join("existing")).unwrap();
    let err = scaffold("existing", dir.to_str().unwrap(), None).unwrap_err();
    assert!(err.contains("already exists"));
}

#[test]
fn scaffold_accepts_name_with_hyphen() {
    let dir = temp_dir();
    let result = scaffold("my-cool-plugin", dir.to_str().unwrap(), None).unwrap();
    assert_eq!(result.name, "my-cool-plugin");
}

#[test]
fn scaffold_accepts_name_with_underscore() {
    let dir = temp_dir();
    let result = scaffold("my_plugin", dir.to_str().unwrap(), None).unwrap();
    assert_eq!(result.name, "my_plugin");
}

#[test]
fn scaffold_rejects_name_too_long() {
    let long_name = "a".repeat(65);
    let err = scaffold(&long_name, "/tmp", None).unwrap_err();
    assert!(err.contains("64 characters"));
}

#[test]
fn scaffold_accepts_max_length_name() {
    let dir = temp_dir();
    let name = "a".repeat(64);
    let result = scaffold(&name, dir.to_str().unwrap(), None).unwrap();
    assert_eq!(result.name, name);
}

// --- --template (DW-166 #284): vendored example scaffolds ------------

/// Every file under `dir`, recursively (scaffolded projects are two
/// levels deep at most).
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn template_scaffold_creates_example_files() {
    let dir = temp_dir();
    let result = scaffold("my-plugin", dir.to_str().unwrap(), Some("static-auth")).unwrap();

    // The example's whole crate: source, shared binding layer, config
    // reader, and both host-runnable test files, plus the scaffold's
    // own wiring files.
    for rel in [
        "Cargo.toml",
        ".gitignore",
        "README.md",
        "dwara.yaml",
        "src/lib.rs",
        "src/abi.rs",
        "src/json.rs",
        "tests/logic.rs",
        "tests/callbacks.rs",
    ] {
        let path = dir.join("my-plugin").join(rel);
        assert!(path.exists(), "template scaffold must create {rel}");
        assert!(
            result
                .files
                .iter()
                .any(|f| f == &path.display().to_string()),
            "{rel} missing from result.files"
        );
    }
}

#[test]
fn template_substitutes_the_crate_name_everywhere() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap(), Some("static-auth")).unwrap();

    let cargo_toml = fs::read_to_string(dir.join("my-plugin/Cargo.toml")).unwrap();
    assert!(cargo_toml.contains("name = \"my-plugin\""));
    assert!(cargo_toml.contains("crate-type = [\"cdylib\", \"rlib\"]"));

    // The host-runnable tests import the crate by its underscored lib
    // name: substitution must have rewritten the `use` lines.
    let logic = fs::read_to_string(dir.join("my-plugin/tests/logic.rs")).unwrap();
    assert!(logic.contains("use my_plugin::"));

    // No file may still carry the template's own names (a missed spot
    // would leave the scaffold un-buildable or self-referential).
    for path in walk(&dir.join("my-plugin")) {
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("static-auth") && !text.contains("static_auth"),
            "{} still references the template crate name",
            path.display()
        );
    }
}

#[test]
fn template_unknown_name_lists_available_templates() {
    let dir = temp_dir();
    let err = scaffold("x", dir.to_str().unwrap(), Some("no-such-template")).unwrap_err();
    assert!(err.contains("unknown template 'no-such-template'"), "{err}");
    for name in dwara_cli::plugin_templates::names() {
        assert!(err.contains(name), "error must list '{name}': {err}");
    }
    // Nothing was scaffolded for the failed lookup.
    assert!(!dir.join("x").exists());
}

#[test]
fn all_templates_scaffold_and_validate() {
    for template in dwara_cli::plugin_templates::names() {
        let dir = temp_dir();
        let result = scaffold("my-plugin", dir.to_str().unwrap(), Some(template))
            .unwrap_or_else(|e| panic!("template {template}: {e}"));
        assert!(
            !result.files.is_empty(),
            "template {template} wrote no files"
        );

        // The generated gateway config validates as generated, with
        // the template's phases and config wired in.
        let yaml = fs::read_to_string(dir.join("my-plugin/dwara.yaml")).unwrap();
        match dwara_cli::validate_config_text(&yaml) {
            dwara_cli::ValidateOutcome::Valid { routes } => assert_eq!(routes, 1),
            dwara_cli::ValidateOutcome::Invalid(issues) => panic!(
                "template {template}: dwara.yaml must validate as generated, got: {issues:?}"
            ),
        }

        // And no template-name leftovers in any scaffolded file.
        let under = template.replace('-', "_");
        for path in walk(&dir.join("my-plugin")) {
            let text = fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains(template) && !text.contains(&under),
                "template {template}: {} still references the template crate name",
                path.display()
            );
        }
    }
}

#[test]
fn template_rejects_existing_directory() {
    let dir = temp_dir();
    fs::create_dir_all(dir.join("existing")).unwrap();
    let err = scaffold("existing", dir.to_str().unwrap(), Some("static-auth")).unwrap_err();
    assert!(err.contains("already exists"));
}
