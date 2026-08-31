//! Unit tests for the plugin scaffolding module (`dwara_cli::plugin_scaffold`).
//!
//! These tests exercise the public `scaffold` function: generating a new
//! proxy-wasm plugin project from a template, verifying the created
//! files, and validating plugin name rules (empty, digit-start, special
//! characters, too long, max length, hyphens, underscores, existing
//! directory).

use dwara_cli::plugin_scaffold::scaffold;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dwara-plugin-test-{}-{}",
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
    let result = scaffold("my-plugin", dir.to_str().unwrap()).unwrap();

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
    scaffold("my-plugin", dir.to_str().unwrap()).unwrap();

    let cargo_toml = fs::read_to_string(dir.join("my-plugin/Cargo.toml")).unwrap();
    assert!(cargo_toml.contains("name = \"my-plugin\""));
    assert!(cargo_toml.contains("crate-type = [\"cdylib\"]"));
    assert!(cargo_toml.contains("proxy-wasm"));
}

#[test]
fn scaffold_lib_rs_has_phase_callbacks() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap()).unwrap();

    let lib_rs = fs::read_to_string(dir.join("my-plugin/src/lib.rs")).unwrap();
    assert!(lib_rs.contains("on_http_request_headers"));
    assert!(lib_rs.contains("on_http_response_headers"));
    assert!(lib_rs.contains("proxy_wasm"));
}

#[test]
fn scaffold_dwara_yaml_references_plugin() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap()).unwrap();

    let yaml = fs::read_to_string(dir.join("my-plugin/dwara.yaml")).unwrap();
    assert!(yaml.contains("my-plugin"));
    assert!(yaml.contains("request_headers"));
    assert!(yaml.contains("wasm32-wasip1"));
}

#[test]
fn scaffold_readme_has_build_instructions() {
    let dir = temp_dir();
    scaffold("my-plugin", dir.to_str().unwrap()).unwrap();

    let readme = fs::read_to_string(dir.join("my-plugin/README.md")).unwrap();
    assert!(readme.contains("wasm32-wasip1"));
    assert!(readme.contains("cargo build --release --target wasm32-wasip1"));
}

#[test]
fn scaffold_rejects_empty_name() {
    let err = scaffold("", "/tmp").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn scaffold_rejects_name_starting_with_digit() {
    let err = scaffold("123plugin", "/tmp").unwrap_err();
    assert!(err.contains("letter or underscore"));
}

#[test]
fn scaffold_rejects_name_with_special_chars() {
    let err = scaffold("my.plugin", "/tmp").unwrap_err();
    assert!(err.contains("letters, digits"));
}

#[test]
fn scaffold_rejects_existing_directory() {
    let dir = temp_dir();
    fs::create_dir_all(dir.join("existing")).unwrap();
    let err = scaffold("existing", dir.to_str().unwrap()).unwrap_err();
    assert!(err.contains("already exists"));
}

#[test]
fn scaffold_accepts_name_with_hyphen() {
    let dir = temp_dir();
    let result = scaffold("my-cool-plugin", dir.to_str().unwrap()).unwrap();
    assert_eq!(result.name, "my-cool-plugin");
}

#[test]
fn scaffold_accepts_name_with_underscore() {
    let dir = temp_dir();
    let result = scaffold("my_plugin", dir.to_str().unwrap()).unwrap();
    assert_eq!(result.name, "my_plugin");
}

#[test]
fn scaffold_rejects_name_too_long() {
    let long_name = "a".repeat(65);
    let err = scaffold(&long_name, "/tmp").unwrap_err();
    assert!(err.contains("64 characters"));
}

#[test]
fn scaffold_accepts_max_length_name() {
    let dir = temp_dir();
    let name = "a".repeat(64);
    let result = scaffold(&name, dir.to_str().unwrap()).unwrap();
    assert_eq!(result.name, name);
}
