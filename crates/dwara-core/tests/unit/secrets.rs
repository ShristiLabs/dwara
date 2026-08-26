//! Unit tests for `extensions::secrets` (relocated from src).

use dwara_core::extensions::secrets::*;

#[tokio::test]
async fn static_source_resolves_known_and_reports_miss() {
    let source = StaticSecretSource::new().with("upstream-token", "s3cr3t");
    let hit = source.resolve("upstream-token").await.unwrap().unwrap();
    assert_eq!(hit.expose(), "s3cr3t");
    assert!(source.resolve("unknown").await.unwrap().is_none());
}

#[tokio::test]
async fn env_source_resolves_set_variable_and_misses_unset() {
    // Unique name so this test can never collide with a real variable.
    let name = "DWARA_TEST_SECRET_DW004_9f3a";
    std::env::set_var(name, "env-value");
    let hit = EnvSecretSource.resolve(name).await.unwrap().unwrap();
    assert_eq!(hit.expose(), "env-value");
    let miss = EnvSecretSource
        .resolve("DWARA_TEST_SECRET_DW004_unset_1c77")
        .await
        .unwrap();
    assert!(miss.is_none());
    std::env::remove_var(name);
}

#[test]
fn secret_debug_output_is_redacted() {
    let secret = Secret::new("super-secret-value-dw004");
    let rendered = format!("{secret:?}");
    assert!(
        !rendered.contains("super-secret-value-dw004"),
        "Debug must not leak the value, got: {rendered}"
    );
    assert!(rendered.contains("redacted"));
    // Leak check also holds for composite Debug output.
    let wrapper = vec![secret.clone()];
    assert!(!format!("{wrapper:?}").contains("super-secret-value-dw004"));
}

#[tokio::test]
async fn static_source_builder_replaces_existing_key() {
    let source = StaticSecretSource::new()
        .with("k", "first")
        .with("k", "second");
    let value = source.resolve("k").await.unwrap().unwrap();
    assert_eq!(value.expose(), "second");
}
