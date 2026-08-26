//! Unit tests for `extensions::config_source` (relocated from src).

use dwara_core::extensions::config_source::*;
use dwara_core::extensions::ExtensionsError;

#[tokio::test]
async fn loads_gateway_from_yaml_file() {
    let dir = std::env::temp_dir().join("dwara-dw004-config-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gw.yaml");
    std::fs::write(&path, "listeners: []\n").unwrap();
    let source = FileConfigSource::new(&path);
    let gateway = source.load().await.unwrap();
    assert!(gateway.listeners.is_empty());
}

const VALID_MINIMAL_YAML: &str = include_str!("../../tests/fixtures/valid_minimal.yaml");
const INVALID_UNKNOWN_FIELD_YAML: &str =
    include_str!("../../tests/fixtures/invalid_unknown_field.yaml");

fn unique_temp_file(name: &str) -> std::path::PathBuf {
    let unique = format!(
        "dwara-dw004-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

#[tokio::test]
async fn loads_minimal_fixture_gateway_from_yaml_file() {
    let path = unique_temp_file("valid.yaml");
    std::fs::write(&path, VALID_MINIMAL_YAML).unwrap();
    let source = FileConfigSource::new(&path);
    let gateway = source.load().await;
    std::fs::remove_file(&path).ok();
    let gateway = gateway.unwrap();
    assert_eq!(
        gateway.listeners.len(),
        1,
        "minimal fixture has one listener"
    );
    assert_eq!(gateway.listeners[0].name, "main");
}

#[tokio::test]
async fn nonexistent_path_maps_to_io_error_carrying_path() {
    let path = unique_temp_file("missing.yaml");
    let err = FileConfigSource::new(&path).load().await.unwrap_err();
    std::fs::remove_file(&path).ok();
    assert!(
        matches!(err, ExtensionsError::Io(ref m) if m.contains(&path.display().to_string())),
        "expected Io variant carrying the path, got: {err}"
    );
}

#[tokio::test]
async fn invalid_yaml_maps_to_invalid_error_with_parse_detail() {
    let path = unique_temp_file("invalid.yaml");
    std::fs::write(&path, INVALID_UNKNOWN_FIELD_YAML).unwrap();
    let err = FileConfigSource::new(&path).load().await.unwrap_err();
    std::fs::remove_file(&path).ok();
    match err {
        ExtensionsError::Invalid(m) => assert!(
            m.contains("unknown field") || m.contains("protocool"),
            "message should carry the parse detail, got: {m}"
        ),
        other => panic!("expected Invalid variant, got: {other}"),
    }
}
