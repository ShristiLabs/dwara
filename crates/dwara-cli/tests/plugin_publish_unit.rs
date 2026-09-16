//! Unit tests for the plugin publish tooling
//! (`dwara_cli::plugin_publish`): entry generation (digest
//! correctness, field shape, unsigned vs signed), signature
//! round-trips, manifest-merge tolerance for extra fields, key
//! handling, and the binary wiring for `plugin keygen`/`sign`/
//! `publish` (no network: the `--pr` flow's gh calls are not
//! exercised here; its pure halves — merge, branch names, PR text —
//! are).

use dwara_cli::plugin_publish;
use ed25519_dalek::SigningKey;

fn temp_dir() -> std::path::PathBuf {
    // Process id + wall clock + a monotonically increasing counter:
    // parallel tests within one process can observe the same clock
    // tick (same pattern as plugin_scaffold_unit.rs).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dwara-plugin-publish-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A deterministic fake .wasm artifact (bytes are arbitrary; the
/// digest/signature logic is content-agnostic).
fn artifact() -> Vec<u8> {
    b"\x00asm\x01\x00\x00\x00fake-plugin-module-bytes".to_vec()
}

fn sha256_direct(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize().iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

const BASE: &str = "https://shristilabs.github.io/dwara-plugins";

// --- entry generation ------------------------------------------------------

#[test]
fn digest_matches_sha2_over_the_artifact_bytes() {
    let bytes = artifact();
    let entry =
        plugin_publish::build_entry(&bytes, "my-plugin", "1.2.0", None, BASE, None).unwrap();
    assert_eq!(entry.digest, sha256_direct(&bytes));
    assert_eq!(entry.digest.len(), 64);
}

#[test]
fn digest_changes_when_the_artifact_changes() {
    let mut bytes = artifact();
    let a = plugin_publish::build_entry(&bytes, "p", "1.0.0", None, BASE, None).unwrap();
    bytes.push(0x00);
    let b = plugin_publish::build_entry(&bytes, "p", "1.0.0", None, BASE, None).unwrap();
    assert_ne!(a.digest, b.digest);
}

#[test]
fn unsigned_entry_has_exactly_the_client_fields() {
    let entry =
        plugin_publish::build_entry(&artifact(), "my-plugin", "1.2.0", None, BASE, None).unwrap();
    let json = serde_json::to_value(&entry).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 4, "unsigned entry must have exactly 4 fields");
    for key in ["name", "version", "digest", "url"] {
        assert!(obj.contains_key(key), "missing field {key}");
    }
    assert!(!obj.contains_key("signature"));
    assert!(!obj.contains_key("public_key"));
    assert_eq!(entry.signature, None);
    assert_eq!(entry.public_key, None);
}

#[test]
fn signed_entry_carries_signature_and_public_key() {
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let entry =
        plugin_publish::build_entry(&artifact(), "my-plugin", "1.2.0", None, BASE, Some(&key))
            .unwrap();
    let json = serde_json::to_value(&entry).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 6, "signed entry must have exactly 6 fields");
    let sig = entry.signature.as_deref().unwrap();
    let pk = entry.public_key.as_deref().unwrap();
    assert_eq!(sig.len(), 128, "Ed25519 signature is 64 bytes hex");
    assert!(sig
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(pk.len(), 64, "Ed25519 public key is 32 bytes hex");
    assert!(pk
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn url_defaults_to_registry_name_version_wasm() {
    let entry =
        plugin_publish::build_entry(&artifact(), "my-plugin", "1.2.0", None, BASE, None).unwrap();
    assert_eq!(entry.url, format!("{BASE}/my-plugin-1.2.0.wasm"));
}

#[test]
fn explicit_url_overrides_the_default() {
    let entry = plugin_publish::build_entry(
        &artifact(),
        "my-plugin",
        "1.2.0",
        Some("https://example.com/hosted/my-plugin.wasm"),
        BASE,
        None,
    )
    .unwrap();
    assert_eq!(entry.url, "https://example.com/hosted/my-plugin.wasm");
}

#[test]
fn empty_artifact_is_rejected() {
    let err = plugin_publish::build_entry(&[], "p", "1.0.0", None, BASE, None).unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn name_validation_rejects_bad_names() {
    for bad in ["", "1starts-with-digit", "has/slash", "has space", "a.b"] {
        let err =
            plugin_publish::build_entry(&artifact(), bad, "1.0.0", None, BASE, None).unwrap_err();
        assert!(!err.is_empty(), "name '{bad}' must be rejected");
    }
}

#[test]
fn version_validation_rejects_bad_versions() {
    for bad in ["", "1 0", "1/0"] {
        let err = plugin_publish::build_entry(&artifact(), "p", bad, None, BASE, None).unwrap_err();
        assert!(!err.is_empty(), "version '{bad}' must be rejected");
    }
}

#[test]
fn entry_json_is_pretty_and_parses_back() {
    let entry =
        plugin_publish::build_entry(&artifact(), "my-plugin", "1.2.0", None, BASE, None).unwrap();
    let json = plugin_publish::entry_json(&entry).unwrap();
    assert!(json.contains("\n  \"name\""));
    let parsed: plugin_publish::ManifestEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, entry);
}

// --- signatures ------------------------------------------------------------

#[test]
fn signature_round_trip_verifies() {
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let bytes = artifact();
    let sig = plugin_publish::sign_artifact(&key, &bytes);
    let pk = plugin_publish::public_key_hex(&key);
    plugin_publish::verify_artifact(&pk, &sig, &bytes).unwrap();
}

#[test]
fn signature_fails_on_tampered_artifact() {
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let sig = plugin_publish::sign_artifact(&key, &artifact());
    let mut tampered = artifact();
    tampered[0] ^= 0xff;
    let pk = plugin_publish::public_key_hex(&key);
    let err = plugin_publish::verify_artifact(&pk, &sig, &tampered).unwrap_err();
    assert!(err.contains("verification failed"));
}

#[test]
fn signature_fails_with_wrong_public_key() {
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    let other = SigningKey::generate(&mut rand_core::OsRng);
    let sig = plugin_publish::sign_artifact(&signer, &artifact());
    let wrong_pk = plugin_publish::public_key_hex(&other);
    assert!(plugin_publish::verify_artifact(&wrong_pk, &sig, &artifact()).is_err());
}

#[test]
fn signing_is_deterministic_for_key_and_artifact() {
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let bytes = artifact();
    assert_eq!(
        plugin_publish::sign_artifact(&key, &bytes),
        plugin_publish::sign_artifact(&key, &bytes)
    );
}

#[test]
fn signed_entry_signature_verifies_against_the_entry_fields() {
    // The entry's own signature/public_key pair must verify against
    // the artifact bytes — the exact check the gateway performs.
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let bytes = artifact();
    let entry = plugin_publish::build_entry(&bytes, "p", "1.0.0", None, BASE, Some(&key)).unwrap();
    plugin_publish::verify_artifact(
        entry.public_key.as_deref().unwrap(),
        entry.signature.as_deref().unwrap(),
        &bytes,
    )
    .unwrap();
}

#[test]
fn verify_rejects_malformed_hex() {
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let pk = plugin_publish::public_key_hex(&key);
    let err = plugin_publish::verify_artifact(&pk, "zz", &artifact()).unwrap_err();
    assert!(err.contains("invalid signature"));
    let err = plugin_publish::verify_artifact("abcd", &pk, &artifact()).unwrap_err();
    assert!(err.contains("invalid public key"));
}

#[test]
fn verify_rejects_wrong_lengths() {
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let sig = plugin_publish::sign_artifact(&key, &artifact());
    let short_pk = "00".repeat(31);
    let short_sig = "00".repeat(63);
    assert!(
        plugin_publish::verify_artifact(&short_pk, &sig, &artifact())
            .unwrap_err()
            .contains("32 bytes")
    );
    assert!(plugin_publish::verify_artifact(
        &plugin_publish::public_key_hex(&key),
        &short_sig,
        &artifact()
    )
    .unwrap_err()
    .contains("64 bytes"));
}

// --- keys ------------------------------------------------------------------

#[test]
fn keygen_keys_have_expected_hex_lengths_and_differ() {
    let a = plugin_publish::keygen();
    assert_eq!(a.public_key.len(), 64);
    assert_eq!(a.private_key.len(), 64);
    assert_ne!(a.public_key, a.private_key);
    let b = plugin_publish::keygen();
    assert_ne!(a.private_key, b.private_key, "keygen must not repeat keys");
}

#[test]
fn load_signing_key_accepts_path_and_literal_hex() {
    let dir = temp_dir();
    let key_path = dir.join("plugin.key");
    let key_hex = plugin_publish::keygen().private_key;
    std::fs::write(&key_path, &key_hex).unwrap();

    let from_file = plugin_publish::load_signing_key(key_path.to_str().unwrap()).unwrap();
    let from_hex = plugin_publish::load_signing_key(&key_hex).unwrap();
    let bytes = artifact();
    assert_eq!(
        plugin_publish::sign_artifact(&from_file, &bytes),
        plugin_publish::sign_artifact(&from_hex, &bytes),
        "file and literal hex forms must load the same key"
    );
    assert_eq!(
        plugin_publish::public_key_hex(&from_file),
        plugin_publish::public_key_hex(&from_hex)
    );
}

#[test]
fn load_signing_key_rejects_bad_input() {
    assert!(plugin_publish::load_signing_key("not-hex!").is_err());
    assert!(plugin_publish::load_signing_key("abcd").is_err());
    let dir = temp_dir();
    let odd = dir.join("odd.key");
    std::fs::write(&odd, "abc").unwrap();
    assert!(plugin_publish::load_signing_key(odd.to_str().unwrap()).is_err());
}

#[test]
fn write_keypair_writes_files_and_refuses_overwrite() {
    let dir = temp_dir();
    let written = plugin_publish::write_keypair(dir.to_str().unwrap()).unwrap();
    assert!(written.public_path.ends_with("plugin.pub"));
    assert!(written.private_path.ends_with("plugin.key"));
    let pub_hex = std::fs::read_to_string(&written.public_path).unwrap();
    let priv_hex = std::fs::read_to_string(&written.private_path).unwrap();
    assert_eq!(pub_hex.len(), 64);
    assert_eq!(priv_hex.len(), 64);
    // Round-trip: the written key must sign artifacts.
    let key = plugin_publish::load_signing_key(&written.private_path).unwrap();
    let bytes = artifact();
    plugin_publish::verify_artifact(
        &pub_hex,
        &plugin_publish::sign_artifact(&key, &bytes),
        &bytes,
    )
    .unwrap();
    // A second keygen into the same dir must refuse.
    let err = plugin_publish::write_keypair(dir.to_str().unwrap()).unwrap_err();
    assert!(err.contains("refusing to overwrite"));
}

#[cfg(unix)]
#[test]
fn write_keypair_sets_private_key_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = temp_dir();
    let written = plugin_publish::write_keypair(dir.to_str().unwrap()).unwrap();
    let mode = std::fs::metadata(&written.private_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "plugin.key must be 0600");
    let pub_mode = std::fs::metadata(&written.public_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(pub_mode & 0o777, 0o644, "plugin.pub is world-readable");
}

// --- manifest merge (read-path tolerance) ----------------------------------

#[test]
fn manifest_entry_parses_with_extra_fields() {
    // Registry entries carry fields this CLI does not know about; the
    // reader must tolerate them (no deny_unknown_fields — see the
    // module docs).
    let json = r#"{
        "name": "my-plugin",
        "version": "1.2.0",
        "digest": "aa",
        "url": "https://example.com/p.wasm",
        "signature": "bb",
        "public_key": "cc",
        "notes": "added by a future registry schema"
    }"#;
    let entry: plugin_publish::ManifestEntry = serde_json::from_str(json).unwrap();
    assert_eq!(entry.name, "my-plugin");
    assert_eq!(entry.signature.as_deref(), Some("bb"));
}

#[test]
fn manifest_entry_parses_unsigned_shape() {
    let json = r#"{"name":"p","version":"1.0.0","digest":"aa","url":"u"}"#;
    let entry: plugin_publish::ManifestEntry = serde_json::from_str(json).unwrap();
    assert_eq!(entry.signature, None);
    assert_eq!(entry.public_key, None);
}

#[test]
fn merge_appends_to_an_empty_manifest() {
    let entry =
        plugin_publish::build_entry(&artifact(), "my-plugin", "1.2.0", None, BASE, None).unwrap();
    let merged = plugin_publish::merge_manifest("[]", &entry).unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&merged).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "my-plugin");
}

#[test]
fn merge_replaces_same_name_and_version() {
    let old = plugin_publish::build_entry(&artifact(), "p", "1.0.0", None, BASE, None).unwrap();
    let other = plugin_publish::build_entry(&artifact(), "q", "2.0.0", None, BASE, None).unwrap();
    let existing = serde_json::to_string_pretty(&vec![
        serde_json::to_value(&old).unwrap(),
        serde_json::to_value(&other).unwrap(),
    ])
    .unwrap();
    // Re-publish p@1.0.0 with a different artifact (digest changes).
    let mut bytes = artifact();
    bytes.extend_from_slice(b"v2");
    let updated = plugin_publish::build_entry(&bytes, "p", "1.0.0", None, BASE, None).unwrap();
    let merged = plugin_publish::merge_manifest(&existing, &updated).unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&merged).unwrap();
    assert_eq!(
        arr.len(),
        2,
        "same name+version is a replacement, not an append"
    );
    let p = arr.iter().find(|v| v["name"] == "p").unwrap();
    assert_eq!(
        p["digest"],
        serde_json::Value::String(updated.digest.clone())
    );
    assert_ne!(p["digest"], serde_json::Value::String(old.digest.clone()));
}

#[test]
fn merge_appends_a_new_version_of_the_same_name() {
    // Registry manifests can list several versions of one plugin (the
    // search command prints them all); a new version appends.
    let v1 = plugin_publish::build_entry(&artifact(), "p", "1.0.0", None, BASE, None).unwrap();
    let existing = serde_json::to_string(&vec![serde_json::to_value(&v1).unwrap()]).unwrap();
    let mut bytes = artifact();
    bytes.push(1);
    let v2 = plugin_publish::build_entry(&bytes, "p", "1.1.0", None, BASE, None).unwrap();
    let merged = plugin_publish::merge_manifest(&existing, &v2).unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&merged).unwrap();
    assert_eq!(arr.len(), 2);
}

#[test]
fn merge_preserves_unknown_fields_of_untouched_entries() {
    let existing = r#"[
        {"name":"other","version":"0.9.0","digest":"dd","url":"u","notes":"keep me","vendor":"acme"}
    ]"#;
    let entry = plugin_publish::build_entry(&artifact(), "p", "1.0.0", None, BASE, None).unwrap();
    let merged = plugin_publish::merge_manifest(existing, &entry).unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&merged).unwrap();
    let other = arr.iter().find(|v| v["name"] == "other").unwrap();
    assert_eq!(other["notes"], "keep me");
    assert_eq!(other["vendor"], "acme");
}

#[test]
fn merge_rejects_a_non_array_manifest() {
    let entry = plugin_publish::build_entry(&artifact(), "p", "1.0.0", None, BASE, None).unwrap();
    let err = plugin_publish::merge_manifest("{\"not\":\"an array\"}", &entry).unwrap_err();
    assert!(err.contains("JSON array"));
}

#[test]
fn merge_treats_blank_manifest_as_empty() {
    let entry = plugin_publish::build_entry(&artifact(), "p", "1.0.0", None, BASE, None).unwrap();
    let merged = plugin_publish::merge_manifest("   \n", &entry).unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&merged).unwrap();
    assert_eq!(arr.len(), 1);
}

#[test]
fn merged_manifest_is_what_a_signed_publish_round_trips_through() {
    // End to end (offline): signed entry -> merge into an existing
    // manifest -> re-parse: the signature survives the JSON cycle.
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let bytes = artifact();
    let entry = plugin_publish::build_entry(&bytes, "p", "1.0.0", None, BASE, Some(&key)).unwrap();
    let merged = plugin_publish::merge_manifest("[]", &entry).unwrap();
    let arr: Vec<plugin_publish::ManifestEntry> = serde_json::from_str(&merged).unwrap();
    assert_eq!(arr.len(), 1);
    plugin_publish::verify_artifact(
        arr[0].public_key.as_deref().unwrap(),
        arr[0].signature.as_deref().unwrap(),
        &bytes,
    )
    .unwrap();
}

// --- PR helpers ------------------------------------------------------------

#[test]
fn branch_name_is_ref_safe() {
    let branch = plugin_publish::branch_name("my-plugin", "1.0.0+build.2");
    assert_eq!(branch, "plugin/my-plugin-1.0.0+build.2");
    // Characters git refs reject are mapped onto '-'.
    let weird = plugin_publish::branch_name("we ird", "1.0.0");
    assert!(!weird.contains(' '), "branch '{weird}' must be ref-safe");
    assert!(weird.starts_with("plugin/"));
}

// --- binary wiring (no network) ---------------------------------------------

fn run_cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_dwara-cli"))
        .args(args)
        .output()
        .expect("runs dwara-cli")
}

#[test]
fn binary_keygen_stdout_prints_both_keys() {
    let out = run_cli(&["plugin", "keygen"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let pub_line = text
        .lines()
        .find(|l| l.starts_with("public_key: "))
        .expect("public_key line");
    let priv_line = text
        .lines()
        .find(|l| l.starts_with("private_key: "))
        .expect("private_key line");
    assert_eq!(pub_line.len(), "public_key: ".len() + 64);
    assert_eq!(priv_line.len(), "private_key: ".len() + 64);
}

#[test]
fn binary_keygen_out_dir_writes_files() {
    let dir = temp_dir();
    let out = run_cli(&["plugin", "keygen", "--out-dir", dir.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.join("plugin.pub").exists());
    assert!(dir.join("plugin.key").exists());
    // Second run refuses to clobber.
    let again = run_cli(&["plugin", "keygen", "--out-dir", dir.to_str().unwrap()]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("refusing to overwrite"));
}

#[test]
fn binary_sign_prints_hex_signature_for_the_artifact() {
    let dir = temp_dir();
    let keygen = run_cli(&["plugin", "keygen", "--out-dir", dir.to_str().unwrap()]);
    assert!(keygen.status.success());
    let wasm = dir.join("fake.wasm");
    std::fs::write(&wasm, artifact()).unwrap();
    let out = run_cli(&[
        "plugin",
        "sign",
        wasm.to_str().unwrap(),
        "--key",
        dir.join("plugin.key").to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sig = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(sig.len(), 128);
    assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn binary_sign_rejects_a_missing_key() {
    let dir = temp_dir();
    let wasm = dir.join("fake.wasm");
    std::fs::write(&wasm, artifact()).unwrap();
    let out = run_cli(&[
        "plugin",
        "sign",
        wasm.to_str().unwrap(),
        "--key",
        "/nonexistent/plugin.key",
    ]);
    assert!(!out.status.success());
}

#[test]
fn binary_sign_missing_wasm_reports_only_the_read_error() {
    // An unreadable artifact must not ALSO print the follow-on
    // "artifact is empty" message (early return on the read failure).
    let dir = temp_dir();
    let out = run_cli(&[
        "plugin",
        "sign",
        dir.join("missing.wasm").to_str().unwrap(),
        "--key",
        "/nonexistent/plugin.key",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot read"), "{stderr}");
    assert!(!stderr.contains("artifact is empty"), "{stderr}");
}

#[test]
fn binary_sign_empty_artifact_is_rejected() {
    let dir = temp_dir();
    let keygen = run_cli(&["plugin", "keygen", "--out-dir", dir.to_str().unwrap()]);
    assert!(keygen.status.success());
    let wasm = dir.join("empty.wasm");
    std::fs::write(&wasm, b"").unwrap();
    let out = run_cli(&[
        "plugin",
        "sign",
        wasm.to_str().unwrap(),
        "--key",
        dir.join("plugin.key").to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("artifact is empty"));
}

#[test]
fn binary_publish_prints_a_correct_unsigned_entry() {
    let dir = temp_dir();
    let wasm = dir.join("fake.wasm");
    let bytes = artifact();
    std::fs::write(&wasm, &bytes).unwrap();
    let out = run_cli(&[
        "plugin",
        "publish",
        wasm.to_str().unwrap(),
        "--name",
        "my-plugin",
        "--version",
        "1.2.0",
        "--url",
        "https://example.com/my-plugin-1.2.0.wasm",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("digest: "));
    assert!(
        text.contains(&sha256_direct(&bytes)),
        "digest must come from the artifact on disk"
    );
    assert!(text.contains("manifest entry:"));
    assert!(text.contains("\"name\": \"my-plugin\""));
    assert!(text.contains("\"url\": \"https://example.com/my-plugin-1.2.0.wasm\""));
    assert!(
        !text.contains("\"signature\""),
        "unsigned publish has no signature field"
    );
    assert!(text.contains("paste the entry above"));
}

#[test]
fn binary_publish_signed_entry_verifies() {
    let dir = temp_dir();
    let keygen = run_cli(&["plugin", "keygen", "--out-dir", dir.to_str().unwrap()]);
    assert!(keygen.status.success());
    let wasm = dir.join("fake.wasm");
    let bytes = artifact();
    std::fs::write(&wasm, &bytes).unwrap();
    let out = run_cli(&[
        "plugin",
        "publish",
        wasm.to_str().unwrap(),
        "--name",
        "my-plugin",
        "--version",
        "1.2.0",
        "--key",
        dir.join("plugin.key").to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    // Extract signature/public_key lines and verify against the bytes.
    let sig = text
        .lines()
        .find(|l| l.starts_with("signature: "))
        .unwrap()
        .trim_start_matches("signature: ")
        .to_string();
    let pk = text
        .lines()
        .find(|l| l.starts_with("public_key: "))
        .unwrap()
        .trim_start_matches("public_key: ")
        .to_string();
    plugin_publish::verify_artifact(&pk, &sig, &bytes).unwrap();
}

#[test]
fn binary_publish_rejects_a_missing_artifact() {
    let out = run_cli(&[
        "plugin",
        "publish",
        "/nonexistent/artifact.wasm",
        "--name",
        "p",
        "--version",
        "1.0.0",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
}
