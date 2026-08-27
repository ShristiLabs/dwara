//! Secrets handling end to end (DW-045): `${...}` secret references in
//! config, fail-closed validation, typed redaction of config echoes,
//! authn against resolved file secrets, and the re-read-on-reload
//! contract.

mod support;

use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::{gateway_to_yaml, parse_gateway};
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::validate;
use dwara_core::store::{sync_consumers_from_config, StateStore};
use http_body_util::Full;
use hyper::Request;
use support::state_from;

/// A canary secret: unique, greppable bytes that must NEVER appear in a
/// redacted surface. If it shows up in a dump, log, or store, redaction
/// is broken.
const CANARY: &str = "sk-live-canary-dw045-a41f76bc";

fn temp_secret_file(tag: &str, contents: &str) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "dwara-dw045-e2e-{}-{n}-{tag}.secret",
        std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    path.display().to_string()
}

/// A `${file:...}` reference to `path`.
fn file_ref(path: &str) -> String {
    format!("${{file:{path}}}")
}

/// A minimal valid config with one consumer whose api key is `key`
/// (inline literal or `${...}` reference).
fn config_with_key(key: &str) -> String {
    format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9
consumers:
  - name: acme
    credentials:
      - type: api_key
        key: {key}
"
    )
}

/// Validate and return ALL issues on `credentials[0]` for one key value.
fn credential_issues(key: &str) -> Vec<String> {
    let gateway = parse_gateway(&config_with_key(key)).unwrap();
    validate(&gateway)
        .into_iter()
        .filter(|i| i.entity == "consumer" && i.field == "credentials[0]")
        .map(|i| i.message)
        .collect()
}

// ---- validation fails closed ----------------------------------------------

#[test]
fn missing_env_reference_fails_validation_naming_the_variable() {
    let issues = credential_issues("${DWARA_TEST_SECRET_DW045_MISSING_7c2e}");
    assert_eq!(issues.len(), 1, "exactly one issue, got: {issues:?}");
    assert!(
        issues[0].contains("DWARA_TEST_SECRET_DW045_MISSING_7c2e") && issues[0].contains("not set"),
        "issue names the variable and reason: {}",
        issues[0]
    );
}

#[test]
fn missing_and_empty_secret_files_fail_validation_naming_the_path() {
    let missing = credential_issues("${file:/nonexistent/dwara-dw045/absent.secret}");
    assert!(
        missing.len() == 1
            && missing[0].contains("/nonexistent/dwara-dw045/absent.secret")
            && missing[0].contains("cannot be read"),
        "missing file named precisely: {missing:?}"
    );
    let empty = temp_secret_file("empty", "\n");
    let issues = credential_issues(&file_ref(&empty));
    assert!(
        issues.len() == 1 && issues[0].contains("empty") && issues[0].contains(&empty),
        "empty file rejected naming its path: {issues:?}"
    );
}

#[test]
fn malformed_reference_shapes_fail_validation_instead_of_becoming_literals() {
    for malformed in [
        "${lower_case}",
        "${file:}",
        "${1BAD}",
        "${redactedx:foo}",
        // #46 review: a reference that is never closed is malformed
        // garbage — a validation error, never a literal key.
        "${unclosed",
        "${file:/run/token",
    ] {
        let issues = credential_issues(malformed);
        assert_eq!(
            issues.len(),
            1,
            "reference-shaped garbage must be one precise issue: {malformed} -> {issues:?}"
        );
    }
}

#[test]
fn redaction_placeholder_in_a_config_is_rejected_fail_closed() {
    // The GET-then-PATCH footgun: a placeholder carried back through a
    // publishing surface must be REJECTED, never installed as a key.
    let issues = credential_issues("${redacted:sha256:e3b0c442}");
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert!(
        issues[0].contains("redaction placeholder"),
        "issue explains the placeholder: {}",
        issues[0]
    );
}

#[test]
fn resolvable_references_and_inline_keys_pass_validation() {
    let file = temp_secret_file("valid", "file-secret-ok\n");
    assert!(
        credential_issues(&file_ref(&file)).is_empty(),
        "a resolvable file reference is valid"
    );
    assert!(
        credential_issues(CANARY).is_empty(),
        "inline keys stay accepted (redacted, not banned)"
    );
}

// ---- typed redaction of config echoes ---------------------------------------

#[test]
fn redacted_gateway_carries_no_inline_canary_but_keeps_references() {
    let file = temp_secret_file("echo", "ref-secret\n");
    let reference = file_ref(&file);
    // One config holding both shapes: an inline canary and a reference.
    let yaml = format!(
        "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9
consumers:
  - name: inline-consumer
    credentials:
      - type: api_key
        key: {CANARY}
  - name: ref-consumer
    credentials:
      - type: api_key
        key: {reference}
"
    );
    let gateway = parse_gateway(&yaml).unwrap();

    // Meaningfulness anchor: the UNredacted dump does carry the canary
    // (this is exactly the pre-DW-045 exposure being closed).
    let live = gateway_to_yaml(&gateway).unwrap();
    assert!(live.contains(CANARY));

    // The redacted dump never carries it; the reference passes through.
    let redacted = gateway_to_yaml(&gateway.redacted()).unwrap();
    assert!(
        !redacted.contains(CANARY),
        "canary must not survive redaction: {redacted}"
    );
    assert!(
        redacted.contains("${redacted:sha256:"),
        "inline key becomes the fingerprinted placeholder: {redacted}"
    );
    assert!(
        redacted.contains(&reference),
        "references echo as references (a path is not secret bytes): {redacted}"
    );
    // The redacted document is still a parseable gateway document.
    parse_gateway(&redacted).expect("redacted dump parses as config");
}

#[test]
fn config_debug_output_never_carries_inline_keys() {
    let gateway = parse_gateway(&config_with_key(CANARY)).unwrap();
    let rendered = format!("{gateway:?}");
    assert!(
        !rendered.contains(CANARY),
        "Debug of the config tree must not leak the key: {rendered}"
    );
    assert!(rendered.contains("[redacted]"));
}

// ---- authn against resolved references --------------------------------------

/// One request through the dataplane with an X-API-Key header; 401 means
/// the key did not authenticate, anything else means it did.
async fn api_key_status(dp: &DataPlane, key: &str) -> hyper::StatusCode {
    let req = Request::builder()
        .uri("/x")
        .header("x-api-key", key)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = dwara_core::proxy::handle(dp, std::net::IpAddr::from([10, 0, 0, 1]), req).await;
    resp.into_parts().0.status
}

#[tokio::test]
async fn file_referenced_api_key_authenticates_with_the_resolved_value() {
    let file = temp_secret_file("authn", "file-key-generation-one\n");
    let dp = support::dataplane_from(&config_with_key(&file_ref(&file)));
    // The resolved value authenticates (502 = reached the dead upstream).
    assert_eq!(
        api_key_status(&dp, "file-key-generation-one").await,
        hyper::StatusCode::BAD_GATEWAY
    );
    // The reference TEXT itself must NOT be a working key: it hashed the
    // resolved bytes, not the literal config string.
    assert_eq!(
        api_key_status(&dp, &file_ref(&file)).await,
        hyper::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn reload_rereads_secret_files_and_rotates_the_working_key() {
    // The hot-reload contract (DW-045): file secrets are read at
    // config-compile time, so a rotation lands on the next publish —
    // publish + refresh is exactly the binary's reload path.
    let file = temp_secret_file("rotate", "rotated-key-alpha\n");
    let state = state_from(&config_with_key(&file_ref(&file)));
    let dp = DataPlane::new(Arc::clone(&state));
    assert_eq!(
        api_key_status(&dp, "rotated-key-alpha").await,
        hyper::StatusCode::BAD_GATEWAY
    );

    std::fs::write(&file, "rotated-key-beta\n").unwrap();
    state
        .compile_and_publish(&parse_gateway(&config_with_key(&file_ref(&file))).unwrap())
        .expect("rotated config republishes");
    dp.refresh();

    assert_eq!(
        api_key_status(&dp, "rotated-key-beta").await,
        hyper::StatusCode::BAD_GATEWAY,
        "the new key authenticates after reload"
    );
    assert_eq!(
        api_key_status(&dp, "rotated-key-alpha").await,
        hyper::StatusCode::UNAUTHORIZED,
        "the old key stops authenticating after reload"
    );
}

// ---- store seeding hashes the RESOLVED value -------------------------------

#[test]
fn store_seeding_hashes_resolved_secret_not_the_reference_text() {
    let file = temp_secret_file("seed", "seeded-key-value\n");
    let gateway = parse_gateway(&config_with_key(&file_ref(&file))).unwrap();
    let store = StateStore::open_in_memory().unwrap();
    sync_consumers_from_config(&store, &gateway, None).unwrap();

    // Selector of the RESOLVED value is seeded...
    let resolved = dwara_core::config::credentials::credential_selector("seeded-key-value");
    assert!(
        !store
            .lookup_credentials_by_selector(&resolved)
            .unwrap()
            .is_empty(),
        "the resolved secret's selector must be seeded"
    );
    // ...and the selector of the reference TEXT is not (proving
    // resolution happened before hashing; the raw reference would never
    // authenticate anything).
    let reference = dwara_core::config::credentials::credential_selector(&file_ref(&file));
    assert!(
        store
            .lookup_credentials_by_selector(&reference)
            .unwrap()
            .is_empty(),
        "the reference text itself must not be seeded as a key"
    );
}

// ---- no partial publish, whole-document rejection ---------------------------

#[tokio::test]
async fn unresolvable_env_reference_blocks_republish_and_keeps_the_old_generation_serving() {
    // The reload contract's fail-closed side: a secret that stops
    // resolving between generations (here: the env var is unset after
    // gen 1) fails the WHOLE republish. Nothing partial is published,
    // the generation counter does not advance, and the previous
    // generation keeps authenticating its already-resolved key.
    let var = format!("DWARA_TEST_SECRET_DW045_UNSET_{}", std::process::id());
    std::env::set_var(&var, "env-key-generation-one");
    let yaml = config_with_key(&format!("${{{var}}}"));
    let state = state_from(&yaml);
    let dp = DataPlane::new(Arc::clone(&state));
    assert_eq!(
        api_key_status(&dp, "env-key-generation-one").await,
        hyper::StatusCode::BAD_GATEWAY
    );

    // The variable disappears from the environment (the operator's
    // systemd unit changed, the k8s env was dropped, ...).
    std::env::remove_var(&var);
    let err = state
        .compile_and_publish(&parse_gateway(&yaml).unwrap())
        .expect_err("republish must fail while the reference cannot resolve");
    match err {
        dwara_core::snapshot::CompileError::Validation(issues) => {
            assert!(
                issues.iter().any(|i| i.message.contains(&var)),
                "the validation issue names the now-unset variable: {issues:?}"
            );
        }
        other => panic!("expected a validation failure, got: {other:?}"),
    }

    // No partial publish: generation untouched, and — exactly like the
    // binary's reload path, which refreshes the dataplane only AFTER a
    // successful publish — the live dataplane is left alone and keeps
    // authenticating the key resolved at generation 1.
    assert_eq!(
        state.snapshot().generation(),
        1,
        "a failed republish must not advance the generation"
    );
    assert_eq!(
        api_key_status(&dp, "env-key-generation-one").await,
        hyper::StatusCode::BAD_GATEWAY,
        "the previous generation keeps serving after a failed republish"
    );
}

#[tokio::test]
async fn dataplane_refresh_fails_closed_when_a_snapshot_reference_stops_resolving() {
    // The validate-vs-build race backstop (DW-045), pinned
    // deterministically: the authn registry re-resolves references at
    // build time. If a reference stops resolving between the publish
    // that validated it and a later registry rebuild, the credential
    // is SKIPPED loudly (config_api_key_unresolvable) — the gateway
    // fails CLOSED (that key stops authenticating) rather than falling
    // back to cached plaintext.
    let var = format!("DWARA_TEST_SECRET_DW045_RACE_{}", std::process::id());
    std::env::set_var(&var, "race-key-generation-one");
    let state = state_from(&config_with_key(&format!("${{{var}}}")));
    let dp = DataPlane::new(Arc::clone(&state));
    assert_eq!(
        api_key_status(&dp, "race-key-generation-one").await,
        hyper::StatusCode::BAD_GATEWAY
    );

    // The secret source breaks AFTER the generation was published...
    std::env::remove_var(&var);
    // ...and a registry rebuild happens anyway (the refresh that
    // follows any later publish).
    dp.refresh();
    assert_eq!(
        api_key_status(&dp, "race-key-generation-one").await,
        hyper::StatusCode::UNAUTHORIZED,
        "an unresolvable reference must fail CLOSED at rebuild, never \
         authenticate from stale plaintext"
    );
}

#[tokio::test]
async fn store_backed_credential_whose_source_breaks_fails_closed_on_reseed() {
    // The STORE-backed twin of the test above (#46 review finding):
    // with DWARA_STATE_DB the registry serves store rows, not config,
    // so the seed path's loud-skip must also RETIRE the row a previous
    // generation of the same reference seeded — otherwise the OLD key
    // keeps authenticating, the opposite of the fail-closed skip the
    // log line claims. The linkage is `credentials.source_ref`
    // (schema v4); the re-seed here is the store-side rebuild that
    // follows a republish.
    let file = temp_secret_file("store-skip", "store-key-generation-one\n");
    let yaml = config_with_key(&file_ref(&file));
    let gateway = parse_gateway(&yaml).unwrap();
    let store = Arc::new(StateStore::open_in_memory().unwrap());
    sync_consumers_from_config(&store, &gateway, None).unwrap();
    let state = state_from(&yaml);
    let dp = DataPlane::new(Arc::clone(&state));
    dp.set_state_store(Arc::clone(&store));
    assert_eq!(
        api_key_status(&dp, "store-key-generation-one").await,
        hyper::StatusCode::BAD_GATEWAY,
        "the resolved generation-one key authenticates via the store"
    );

    // The source breaks; the next seed loud-skips AND revokes the
    // previous-generation row, so the old key gets 401.
    std::fs::remove_file(&file).unwrap();
    sync_consumers_from_config(&store, &gateway, None).unwrap();
    dp.refresh();
    assert_eq!(
        api_key_status(&dp, "store-key-generation-one").await,
        hyper::StatusCode::UNAUTHORIZED,
        "a skipped store seed must retire the previous generation's row: \
         the old key fails closed, never keeps authenticating"
    );

    // A healed source re-seeds a FRESH row (revocation never blocks
    // config re-seeding) and the new key authenticates again.
    std::fs::write(&file, "store-key-generation-two\n").unwrap();
    sync_consumers_from_config(&store, &gateway, None).unwrap();
    dp.refresh();
    assert_eq!(
        api_key_status(&dp, "store-key-generation-two").await,
        hyper::StatusCode::BAD_GATEWAY,
        "a healed source re-seeds and the new key authenticates"
    );
    assert_eq!(
        api_key_status(&dp, "store-key-generation-one").await,
        hyper::StatusCode::UNAUTHORIZED,
        "the revoked old key stays revoked after re-seeding"
    );
}

#[test]
fn a_placeholder_alongside_valid_credentials_fails_the_whole_document_naming_the_offender() {
    // The partial round trip: an operator re-enters ONE key but leaves
    // another field still carrying its `${redacted:...}` placeholder.
    // Validation must reject the WHOLE document and flag exactly the
    // placeholder field — a partially updated config never publishes.
    let yaml = "listeners: []
routes:
  - name: r
    service: svc
    match:
      path: { type: regex, value: /.* }
    action: { type: proxy }
services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 9
consumers:
  - name: good
    credentials:
      - type: api_key
        key: a-freshly-reentered-key
  - name: bad
    credentials:
      - type: api_key
        key: ${redacted:sha256:e3b0c442}
"
    .to_string();
    let gateway = parse_gateway(&yaml).unwrap();
    let issues: Vec<_> = validate(&gateway)
        .into_iter()
        .filter(|i| i.entity == "consumer" && i.field.starts_with("credentials["))
        .collect();
    assert_eq!(
        issues.len(),
        1,
        "exactly the placeholder field is flagged: {issues:?}"
    );
    assert_eq!(
        issues[0].name, "bad",
        "the issue names the offending consumer"
    );
    assert_eq!(issues[0].field, "credentials[0]");
    assert!(
        issues[0].message.contains("redaction placeholder"),
        "the message says what is wrong: {}",
        issues[0].message
    );
}

#[test]
fn file_reference_paths_resolve_as_given_including_dotdot_segments() {
    // Posture pin (DW-045): secret-file references are operator-trusted
    // config, exactly like every other path the schema takes (cert
    // files, trusted-CA bundles) — there is no path confinement or
    // normalization. `..` segments are resolved by the filesystem as
    // given; a future sandbox must be a deliberate change, not drift.
    let dir = std::env::temp_dir().join(format!("dwara-dw045-dotdot-{}", std::process::id()));
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("key.secret"), "dotdot-resolved-key\n").unwrap();
    // DIR/sub/../sub/key.secret — readable, via a redundant `..`.
    let dotted = sub.join("..").join("sub").join("key.secret");
    assert!(
        credential_issues(&format!("${{file:{}}}", dotted.display())).is_empty(),
        "a readable file via a `..`-containing path resolves (operator-trust posture)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
