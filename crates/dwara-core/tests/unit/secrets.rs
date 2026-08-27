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

// ---- FileSecretSource (DW-045) ---------------------------------------------

fn temp_secret_file(tag: &str, contents: &str) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "dwara-dw045-src-{}-{n}-{tag}.secret",
        std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    path.display().to_string()
}

#[tokio::test]
async fn file_source_reads_at_resolve_time_and_trims_one_newline() {
    let path = temp_secret_file("hot", "file-secret-a\n");
    let hit = FileSecretSource.resolve(&path).await.unwrap().unwrap();
    assert_eq!(hit.expose(), "file-secret-a");
    // No caching: a rotation is visible on the NEXT resolve (the
    // hot-reload contract — secrets files are re-read per publish).
    std::fs::write(&path, "file-secret-b\n").unwrap();
    let rotated = FileSecretSource.resolve(&path).await.unwrap().unwrap();
    assert_eq!(rotated.expose(), "file-secret-b");
}

#[tokio::test]
async fn file_source_fails_closed_on_missing_or_empty() {
    // The name IS the location for this source: a missing file is a
    // fail-closed Io error naming the path, never a silent miss.
    let missing = FileSecretSource
        .resolve("/nonexistent/dwara-dw045/none.secret")
        .await
        .unwrap_err();
    assert!(
        matches!(missing, dwara_core::extensions::ExtensionsError::Io(ref m)
            if m.contains("/nonexistent/dwara-dw045/none.secret")),
        "Io error naming the path, got: {missing:?}"
    );
    let empty = temp_secret_file("empty", "\n");
    let err = FileSecretSource.resolve(&empty).await.unwrap_err();
    assert!(
        matches!(err, dwara_core::extensions::ExtensionsError::Io(ref m) if m.contains("empty")),
        "empty file is an error, got: {err:?}"
    );
}

#[tokio::test]
async fn file_source_fails_closed_on_an_unreadable_path() {
    // A directory is deterministically unreadable as a secret file on
    // every platform (EISDIR, root included) — pins the mid-run
    // "file became unreadable" shape for the extension seam, not just
    // the config grammar's copy of the rule.
    let dir = std::env::temp_dir().display().to_string();
    let err = FileSecretSource.resolve(&dir).await.unwrap_err();
    assert!(
        matches!(err, dwara_core::extensions::ExtensionsError::Io(ref m) if m.contains("cannot be read")),
        "Io error naming the unreadable path, got: {err:?}"
    );
}
