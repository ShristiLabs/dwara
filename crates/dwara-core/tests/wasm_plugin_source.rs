//! Registry plugin source resolution integration tests (DW-165).
//!
//! Exercises the gateway-side pipeline end to end: `source:` plugins
//! resolve through the digest-named cache BEFORE the wasm load step,
//! verify the mandatory SHA-256 digest and any configured Ed25519
//! signature, load and run through the real dispatch path, and fail
//! CLOSED (Crashed at publish, routes 500 `plugin_unavailable`) on a
//! tampered cache, a wrong key, a missing signature where the registry
//! pins keys, or an unresolvable artifact with no cache.
//!
//! Fixture approach (tests/proxy_plugins.rs): proxy-wasm modules are
//! compiled from WAT at test time; the "registry" is the local cache
//! directory, so no test needs network access. The download path is
//! exercised through its FAILURE mode (a dead port answers instantly
//! with connection-refused), which also pins the exact operator-facing
//! error for an uncached artifact on an unreachable registry — and the
//! restart-safety test proves a cached artifact resolves with the URL
//! pointed at a dead port (offline operation).
//!
//! The download's VERIFICATION leg runs against injected bytes: the
//! fetcher is HTTPS-only (public webpki roots), so a local plaintext
//! server cannot serve it. The least-invasive seam chosen for tests is
//! an injected download step (`resolve_sources_with_fetch`) — the real
//! digest/signature/cache-write pipeline executes on bytes a test
//! provides, with the TLS transport swapped out and nothing else. The
//! framing parsers (`parse_response` / `decode_chunked`) are pinned as
//! pure functions, including the hostile chunk-size lines from the
//! review (overflow, over-cap, malformed hex, missing CRLF).

use std::path::Path;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::config::ssrf::SsrfFilter;
use dwara_core::dataplane::plugin_dispatch::{PluginStatusEntry, PluginStatusState};
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::validate;
use dwara_core::wasm::source::{
    decode_chunked, parse_response, resolve_sources_with_fetch, SourceError, MAX_ARTIFACT_BYTES,
    RESOLUTION_BUDGET,
};
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};

mod support;

use support::{
    dataplane_from, dead_port, h1_client, spawn_backend, spawn_gateway, state_from, uri,
};

// --- fixtures --------------------------------------------------------------

/// Compile a WAT source string to .wasm bytes (the wasm_host.rs /
/// proxy_plugins.rs approach: minimal proxy-wasm modules at test time).
fn wat_to_wasm(wat: &str) -> Vec<u8> {
    use wast::parser::{parse, ParseBuffer};
    let buf = ParseBuffer::new(wat).expect("WAT parse buffer");
    let mut wat: wast::Wat = parse(&buf).expect("WAT parse");
    wat.encode().expect("WAT encode")
}

/// A minimal proxy-wasm filter that adds `x-wasm-filter: {value}` to
/// the request headers (proxy_plugins.rs' add_header_wat).
fn add_header_wat(value: &str) -> String {
    let value_len = value.len();
    format!(
        r#"(module
  (import "env" "proxy_add_header_map_value"
    (func $add_header (param i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  (data (i32.const 65536) "x-wasm-filter") (data (i32.const 65560) "{value}")
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param $ctx i32) (param $a i32) (param $b i32) (result i32)
    (drop (call $add_header (i32.const 0) (i32.const 65536) (i32.const 13)
         (i32.const 65560) (i32.const {value_len})))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#
    )
}

/// SHA-256 hex of `bytes` (lowercase; the digest spelling the config
/// pins and the status surface reports).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sign `msg` with the Ed25519 key derived from `seed`; returns the
/// hex signature. Deterministic (RFC 8032 nonces), no RNG involved.
fn sign_hex(seed: &[u8; 32], msg: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    hex(&sk.sign(msg).to_bytes())
}

/// The hex public key (verifying key) for the Ed25519 key from `seed`.
fn public_hex(seed: &[u8; 32]) -> String {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    hex(sk.verifying_key().as_bytes())
}

/// Write `bytes` into the content-addressed cache slot for `digest`
/// under `cache_dir` and return the digest.
fn cache_artifact(cache_dir: &Path, bytes: &[u8]) -> String {
    let digest = sha256_hex(bytes);
    std::fs::create_dir_all(cache_dir).unwrap();
    std::fs::write(cache_dir.join(format!("{digest}.wasm")), bytes).unwrap();
    digest
}

/// A gateway YAML with `plugin_registry.cache_dir` set to `cache_dir`,
/// one `source:` plugin, and (optionally) pinned registry keys.
fn source_gateway_yaml(
    cache_dir: &Path,
    url: &str,
    digest: &str,
    signature: Option<&str>,
    public_key: Option<&str>,
    pinned_keys: &[&str],
) -> String {
    let mut yaml = format!("plugin_registry:\n  cache_dir: {}\n", cache_dir.display());
    if !pinned_keys.is_empty() {
        yaml.push_str("  public_keys:\n");
        for k in pinned_keys {
            yaml.push_str(&format!("    - {k}\n"));
        }
    }
    yaml.push_str(&format!(
        "routes:\n\
         - name: plugged\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v1\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         \x20 plugins: [remote]\n\
         - name: clean\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /v2\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 1\n\
         plugins:\n\
         - name: remote\n\
         \x20 source:\n\
         \x20   url: {url}\n\
         \x20   digest: {digest}\n"
    ));
    if let Some(sig) = signature {
        yaml.push_str(&format!("    signature: {sig}\n"));
    }
    if let Some(pk) = public_key {
        yaml.push_str(&format!("    public_key: {pk}\n"));
    }
    yaml.push_str("  phases: [request_headers]\n");
    yaml
}

/// The single `remote` plugin's status entry from a built dataplane.
fn remote_status(dp: &DataPlane) -> PluginStatusEntry {
    dp.plugin_statuses()
        .into_iter()
        .find(|s| s.name == "remote")
        .expect("remote plugin declared")
}

/// A never-fetchable registry URL (dead port: instant refusal, no
/// network dependency, and proof the cache path is taken when used
/// with a cached artifact).
fn dead_url() -> String {
    format!("https://127.0.0.1:{}/remote.wasm", dead_port())
}

// --- cached-artifact resolution + digest verification ----------------------

#[tokio::test]
async fn cached_source_artifact_loads_and_runs_through_dispatch() {
    // The acceptance path: a `source:` plugin resolves from the
    // digest-named cache, reads Healthy on the status surface with the
    // pinned digest, and its effect is visible at the upstream through
    // the real dispatch path.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let url = dead_url();
    let yaml = source_gateway_yaml(dir.path(), &url, &digest, None, None, &[]);

    let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = seen.clone();
    let backend = support::spawn_backend_async(move |req| {
        let recorder = recorder.clone();
        async move {
            {
                let mut g = recorder.lock().unwrap();
                for (k, v) in req.headers() {
                    g.push((k.to_string(), v.to_str().unwrap_or("").to_string()));
                }
            }
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }
    })
    .await;
    let yaml = yaml.replace("port: 1\n", &format!("port: {backend}\n"));
    let dp = dataplane_from(&yaml);

    let status = remote_status(&dp);
    assert_eq!(status.kind, "registry", "kind stays registry: {status:?}");
    assert_eq!(status.source, url);
    assert_eq!(status.sha256, digest, "the reported digest is the pin");
    assert_eq!(status.state, PluginStatusState::Healthy, "{status:?}");

    let port = spawn_gateway(dp).await;
    let resp = h1_client().get(uri(port, "/v1/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|(k, v)| k == "x-wasm-filter" && v == "registry"),
        "the registry-sourced plugin's header must reach the upstream, saw: {:?}",
        seen.lock().unwrap()
    );
}

#[test]
fn tampered_cache_artifact_fails_publish() {
    // A cached file that does not hash to its pinned digest is a
    // tampered/corrupt entry: the plugin is Crashed with a
    // step-naming error and the tampered bytes NEVER load (empty
    // checksum). The routed fail-closed behavior is pinned by the
    // companion test below.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    // Tamper: overwrite the digest-named slot with different bytes.
    std::fs::write(
        dir.path().join(format!("{digest}.wasm")),
        wat_to_wasm(&add_header_wat("tampered")),
    )
    .unwrap();
    let yaml = source_gateway_yaml(dir.path(), &dead_url(), &digest, None, None, &[]);
    let dp = dataplane_from(&yaml);

    let status = remote_status(&dp);
    match &status.state {
        PluginStatusState::Crashed { error, .. } => {
            assert!(
                error.contains("digest verification failed"),
                "error names the step: {error}"
            );
            assert!(
                error.contains("cached"),
                "error names the artifact origin: {error}"
            );
            assert!(
                error.contains(&digest),
                "error names the pinned digest: {error}"
            );
        }
        other => panic!("expected Crashed, got {other:?}"),
    }
    assert_eq!(status.sha256, "", "tampered bytes are never loaded");
}

#[tokio::test]
async fn tampered_source_route_fails_closed_while_clean_route_serves() {
    // The routed companion of the tamper test: same tampered cache,
    // real backend, real gateway: `/v1` (plugged) answers 500
    // `plugin_unavailable`, `/v2` (clean) proxies through.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    std::fs::write(
        dir.path().join(format!("{digest}.wasm")),
        b"these are not the bytes you pinned",
    )
    .unwrap();
    let yaml = source_gateway_yaml(dir.path(), &dead_url(), &digest, None, None, &[]);

    let (backend, _hits) = spawn_backend(
        |_n, _m, _p, _b| Response::new(Full::new(Bytes::from_static(b"ok"))),
        std::time::Duration::ZERO,
    )
    .await;
    // Point the upstream at the backend (port 1 placeholder above).
    let yaml = yaml.replace("port: 1\n", &format!("port: {backend}\n"));
    let port = spawn_gateway(dataplane_from(&yaml)).await;

    let resp = h1_client().get(uri(port, "/v1/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(support::envelope_code(&body), "plugin_unavailable");

    let resp = h1_client().get(uri(port, "/v2/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- signature verification ------------------------------------------------

#[test]
fn signed_cached_artifact_verifies_and_loads() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let seed = [7u8; 32];
    let yaml = source_gateway_yaml(
        dir.path(),
        &dead_url(),
        &digest,
        Some(&sign_hex(&seed, &artifact)),
        Some(&public_hex(&seed)),
        &[],
    );
    let dp = dataplane_from(&yaml);
    let status = remote_status(&dp);
    assert_eq!(status.state, PluginStatusState::Healthy, "{status:?}");
}

#[test]
fn wrong_key_signature_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let signing_seed = [7u8; 32];
    let other_seed = [9u8; 32];
    let yaml = source_gateway_yaml(
        dir.path(),
        &dead_url(),
        &digest,
        Some(&sign_hex(&signing_seed, &artifact)),
        Some(&public_hex(&other_seed)), // not the signing key
        &[],
    );
    let dp = dataplane_from(&yaml);
    let status = remote_status(&dp);
    match &status.state {
        PluginStatusState::Crashed { error, .. } => {
            assert!(
                error.contains("signature"),
                "error names the signature step: {error}"
            );
            assert!(
                error.contains("source.public_key"),
                "error names the key field: {error}"
            );
        }
        other => panic!("expected Crashed, got {other:?}"),
    }
}

#[test]
fn missing_signature_with_pinned_registry_keys_rejected() {
    // The registry pins keys; an unsigned plugin is rejected even
    // though its digest matches the cached artifact.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let pinned_seed = [11u8; 32];
    let yaml = source_gateway_yaml(
        dir.path(),
        &dead_url(),
        &digest,
        None,
        None,
        &[&public_hex(&pinned_seed)],
    );
    let dp = dataplane_from(&yaml);
    let status = remote_status(&dp);
    match &status.state {
        PluginStatusState::Crashed { error, .. } => {
            assert!(
                error.contains("plugin_registry.public_keys"),
                "error names the pinned keys: {error}"
            );
        }
        other => panic!("expected Crashed, got {other:?}"),
    }
}

#[test]
fn pinned_registry_key_signature_accepted() {
    // Positive control for the pinned-key path: the plugin is signed
    // by a pinned registry key (no per-plugin key) and loads.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let pinned_seed = [11u8; 32];
    let yaml = source_gateway_yaml(
        dir.path(),
        &dead_url(),
        &digest,
        Some(&sign_hex(&pinned_seed, &artifact)),
        None,
        &[&public_hex(&pinned_seed)],
    );
    let dp = dataplane_from(&yaml);
    let status = remote_status(&dp);
    assert_eq!(status.state, PluginStatusState::Healthy, "{status:?}");
}

#[test]
fn signature_by_unpinned_key_rejected_under_pinned_registry() {
    // Pinned keys + a signature that matches NONE of them (even with a
    // valid per-plugin key) fails: the registry pin is an additional
    // requirement, not an alternative.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let pinned_seed = [11u8; 32];
    let rogue_seed = [13u8; 32];
    let yaml = source_gateway_yaml(
        dir.path(),
        &dead_url(),
        &digest,
        Some(&sign_hex(&rogue_seed, &artifact)),
        Some(&public_hex(&rogue_seed)), // per-plugin key verifies...
        &[&public_hex(&pinned_seed)],   // ...but the registry pin does not
    );
    let dp = dataplane_from(&yaml);
    let status = remote_status(&dp);
    match &status.state {
        PluginStatusState::Crashed { error, .. } => {
            assert!(
                error.contains("pinned"),
                "error names the registry pin: {error}"
            );
        }
        other => panic!("expected Crashed, got {other:?}"),
    }
}

// --- cache-only-miss behavior ----------------------------------------------

#[test]
fn cache_miss_download_failure_names_the_step_and_hint() {
    // No cached artifact, unreachable registry: the exact error names
    // the plugin, the URL, the download step, and the pre-fetch
    // remediation.
    let dir = tempfile::tempdir().unwrap();
    let url = dead_url();
    let yaml = source_gateway_yaml(dir.path(), &url, &"a".repeat(64), None, None, &[]);
    let dp = dataplane_from(&yaml);
    let status = remote_status(&dp);
    match &status.state {
        PluginStatusState::Crashed { error, .. } => {
            assert!(error.contains("remote"), "names the plugin: {error}");
            assert!(error.contains(&url), "names the URL: {error}");
            assert!(
                error.contains("download"),
                "names the download step: {error}"
            );
            assert!(
                error.contains("dwara-cli plugin install"),
                "names the pre-fetch remediation: {error}"
            );
        }
        other => panic!("expected Crashed, got {other:?}"),
    }
    // And nothing was written into the cache dir.
    assert!(
        !dir.path().join(format!("{}.wasm", "a".repeat(64))).exists(),
        "no artifact cached for a failed resolution"
    );
}

// --- restart safety ---------------------------------------------------------

#[test]
fn cached_artifact_resolves_after_restart_without_network() {
    // Restart-safety: a SECOND gateway (fresh process equivalent:
    // fresh lifecycle, fresh resolver) resolves the same cached
    // artifact with the registry URL pointed at a dead port — cache
    // hit only, no network dependency, healthy from the first request.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let yaml = source_gateway_yaml(dir.path(), &dead_url(), &digest, None, None, &[]);

    let first = dataplane_from(&yaml);
    assert_eq!(remote_status(&first).state, PluginStatusState::Healthy);
    drop(first);

    let second = dataplane_from(&yaml);
    let status = remote_status(&second);
    assert_eq!(status.state, PluginStatusState::Healthy, "{status:?}");
    assert_eq!(status.sha256, digest);
}

#[test]
fn reload_reuses_cached_artifact_and_stays_healthy() {
    // Hot-reload of identical content: the plugin stays healthy with a
    // stable checksum (cache hit on every publish).
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let yaml = source_gateway_yaml(dir.path(), &dead_url(), &digest, None, None, &[]);

    let gateway = parse_gateway(&yaml).unwrap();
    let state = state_from(&yaml);
    let dp = DataPlane::new(state.clone());
    assert_eq!(remote_status(&dp).state, PluginStatusState::Healthy);

    // Re-publish identical content (a forced reload) and refresh.
    state.compile_and_publish(&gateway).unwrap();
    dp.refresh();
    let status = remote_status(&dp);
    assert_eq!(status.state, PluginStatusState::Healthy, "{status:?}");
    assert_eq!(status.sha256, digest, "checksum stable across reloads");
}

// --- config validation ------------------------------------------------------

/// Zero-route validation configs must opt in explicitly.
fn validation_yaml(source_block: &str, registry_block: &str) -> String {
    format!(
        "allow_empty_routes: true\n{registry_block}plugins:\n  - name: remote\n{source_block}    phases: [request_headers]\n"
    )
}

#[test]
fn validation_rejects_oci_source() {
    let yaml = validation_yaml(
        "    source:\n      url: oci://registry.example.com/remote:1.0\n      digest: a1\n",
        "",
    );
    let issues = validate(&parse_gateway(&yaml).unwrap());
    assert!(
        issues.iter().any(|i| i.entity == "plugin"
            && i.name == "remote"
            && i.field == "source.url"
            && i.message.contains("oci://")
            && i.message.contains("not supported")),
        "expected oci rejection, got {issues:?}"
    );
}

#[test]
fn validation_rejects_non_https_source_url() {
    let yaml = validation_yaml(
        "    source:\n      url: http://registry.example.com/remote.wasm\n      digest: a1\n",
        "",
    );
    let issues = validate(&parse_gateway(&yaml).unwrap());
    assert!(
        issues
            .iter()
            .any(|i| i.field == "source.url" && i.message.contains("https")),
        "expected https-only rejection, got {issues:?}"
    );
}

#[test]
fn validation_rejects_malformed_digest() {
    let yaml = validation_yaml(
        "    source:\n      url: https://r.example.com/remote.wasm\n      digest: zzzz\n",
        "",
    );
    let issues = validate(&parse_gateway(&yaml).unwrap());
    assert!(
        issues.iter().any(|i| i.field == "source.digest"
            && i.message.contains("SHA-256")
            && i.message.contains("4 chars")),
        "expected digest-length rejection naming the length, got {issues:?}"
    );
}

#[test]
fn validation_rejects_malformed_public_key_and_signature() {
    let yaml = validation_yaml(
        "    source:\n      url: https://r.example.com/remote.wasm\n      digest: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n      signature: abcdef\n      public_key: 1234\n",
        "",
    );
    let issues = validate(&parse_gateway(&yaml).unwrap());
    assert!(
        issues
            .iter()
            .any(|i| i.field == "source.public_key" && i.message.contains("32-byte")),
        "expected public_key rejection, got {issues:?}"
    );
    assert!(
        issues
            .iter()
            .any(|i| i.field == "source.signature" && i.message.contains("64-byte")),
        "expected signature rejection, got {issues:?}"
    );
}

#[test]
fn validation_accepts_well_formed_source() {
    let yaml = validation_yaml(
        &format!(
            "    source:\n      url: https://r.example.com/remote.wasm\n      digest: {}\n",
            "ab".repeat(32)
        ),
        "",
    );
    let issues = validate(&parse_gateway(&yaml).unwrap());
    assert!(
        !issues.iter().any(|i| i.entity == "plugin"),
        "expected no plugin issues, got {issues:?}"
    );
}

// --- resolver unit surface (no dataplane) ------------------------------------

#[test]
fn resolve_sources_reports_steps_for_every_source_plugin() {
    // The resolver output covers every source plugin (the lifecycle
    // depends on this to fail closed rather than skip silently).
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = cache_artifact(dir.path(), &artifact);
    let yaml = source_gateway_yaml(dir.path(), &dead_url(), &digest, None, None, &[]);
    let gateway = parse_gateway(&yaml).unwrap();
    let resolutions = dwara_core::wasm::source::resolve_sources(&gateway);
    assert_eq!(resolutions.len(), 1, "one source plugin resolved");
    let path = resolutions.get("remote").unwrap().as_ref().unwrap();
    assert_eq!(
        path,
        &dir.path().join(format!("{digest}.wasm")),
        "content-addressed cache path"
    );
}

// --- HTTP framing parsers (pure functions) -----------------------------------
//
// The downloader's response parsing is pinned here as pure functions:
// status acceptance, framing (Content-Length / chunked / EOF), the
// artifact cap, and the hostile chunk-size lines from the review
// (a `ffffffffffffffff` size line used to wrap the cap check and
// panic on the slice).

#[test]
fn parse_response_rejects_non_200_status() {
    let raw = b"HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\n\r\nhi";
    let err = parse_response(raw).unwrap_err();
    assert!(err.contains("404"), "names the status: {err}");
}

#[test]
fn parse_response_rejects_redirect_without_following() {
    let raw = b"HTTP/1.1 302 Found\r\nlocation: https://other.example.com/a.wasm\r\ncontent-length: 0\r\n\r\n";
    let err = parse_response(raw).unwrap_err();
    assert!(err.contains("302"), "names the status: {err}");
    assert!(
        err.contains("not followed"),
        "states the no-follow posture: {err}"
    );
}

#[test]
fn parse_response_rejects_content_length_larger_than_body() {
    let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhi";
    let err = parse_response(raw).unwrap_err();
    assert!(err.contains("truncated body"), "{err}");
    assert!(err.contains("10"), "names the claim: {err}");
    assert!(err.contains("2"), "names what arrived: {err}");
}

#[test]
fn parse_response_rejects_content_length_over_cap() {
    let over_cap = MAX_ARTIFACT_BYTES + 1;
    let raw = format!("HTTP/1.1 200 OK\r\ncontent-length: {over_cap}\r\n\r\nhi");
    let err = parse_response(raw.as_bytes()).unwrap_err();
    assert!(err.contains("exceeds"), "names the cap: {err}");
    assert!(err.contains("artifact cap"), "{err}");
}

#[test]
fn parse_response_accepts_read_to_eof_body_without_framing() {
    // Connection: close with no framing header: the body is what
    // arrived (positive control for the third framing mode).
    let raw = b"HTTP/1.1 200 OK\r\nserver: static-host\r\n\r\nartifact-bytes";
    assert_eq!(parse_response(raw).unwrap(), b"artifact-bytes".to_vec());
}

#[test]
fn decode_chunked_decodes_valid_framing_with_extension_and_trailers() {
    // Classic Wikipedia vector, plus a chunk extension and a trailer
    // section (both accepted and ignored).
    let body = b"4;name=first\r\nWiki\r\n5\r\npedia\r\n0\r\nx-checksum: ignored\r\n\r\n";
    assert_eq!(decode_chunked(body).unwrap(), b"Wikipedia".to_vec());
    // Through parse_response as well (the Transfer-Encoding branch).
    let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    assert_eq!(parse_response(raw).unwrap(), b"Wikipedia".to_vec());
}

#[test]
fn decode_chunked_rejects_overflow_chunk_size_line() {
    // THE review finding: a 16-hex-digit size line parses to a value
    // near usize::MAX and used to wrap `out.len() + size` past the cap
    // check (then panic on `&body[..size]`). Every spelling must come
    // back as an error, never a panic.
    for size_line in ["ffffffffffffffff", "7fffffffffffffff", "1ffffffffffffffff"] {
        let body = format!("{size_line}\r\nAAAAAAAA");
        let err = decode_chunked(body.as_bytes()).unwrap_err();
        assert!(
            !err.is_empty(),
            "size line {size_line} must be rejected, not decoded"
        );
        assert!(
            err.contains("chunk") || err.contains("cap"),
            "error names the chunked step: {err}"
        );
    }
}

#[test]
fn decode_chunked_rejects_chunk_size_over_cap() {
    // 0x4000001 is exactly MAX_ARTIFACT_BYTES + 1: a single chunk
    // over the cap is rejected outright, before any arithmetic.
    let body = format!("{:x}\r\nAAAA", MAX_ARTIFACT_BYTES + 1);
    let err = decode_chunked(body.as_bytes()).unwrap_err();
    assert!(err.contains("exceeds"), "{err}");
    assert!(err.contains("artifact cap"), "{err}");
}

#[test]
fn decode_chunked_rejects_aggregate_over_cap() {
    // Two chunks whose SUM exceeds the cap: the checked add fires the
    // cap error before any slicing (small bodies — no allocation of
    // cap-sized buffers needed to hit the aggregate check).
    let body = format!("3\r\nabc\r\n{:x}\r\nAAAA", MAX_ARTIFACT_BYTES);
    let err = decode_chunked(body.as_bytes()).unwrap_err();
    assert!(err.contains("exceeds"), "{err}");
    assert!(err.contains("artifact cap"), "{err}");
}

#[test]
fn decode_chunked_rejects_malformed_hex_size() {
    let err = decode_chunked(b"zz\r\nAAAA").unwrap_err();
    assert!(err.contains("bad chunk size"), "{err}");
    // Empty size line is malformed too.
    let err = decode_chunked(b"\r\nAAAA").unwrap_err();
    assert!(err.contains("bad chunk size"), "{err}");
}

#[test]
fn decode_chunked_rejects_missing_crlf() {
    // A size line with no CRLF terminator at all.
    let err = decode_chunked(b"4").unwrap_err();
    assert!(err.contains("missing chunk size line"), "{err}");
    // Chunk data present but its trailing CRLF missing.
    let err = decode_chunked(b"4\r\nWiki").unwrap_err();
    assert!(err.contains("truncated chunk"), "{err}");
}

// --- download-side verification via the injected transport --------------------

thread_local! {
    /// Bytes the injected fetch serves (fn pointers cannot capture).
    static FETCH_BYTES: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Injected fetch: serves the stashed bytes (the test's "registry").
fn fetch_serving_stashed(
    _url: &str,
    _ssrf: &SsrfFilter,
    _deadline: std::time::Instant,
) -> Result<Vec<u8>, String> {
    Ok(FETCH_BYTES.with(|b| b.borrow().clone()))
}

/// Injected fetch: any call is a test failure (the pipeline must stop
/// before the download step). Errors surfacing as `DownloadFailed`
/// make an unexpected call visible in the assertion output.
fn fetch_must_not_be_called(
    _url: &str,
    _ssrf: &SsrfFilter,
    _deadline: std::time::Instant,
) -> Result<Vec<u8>, String> {
    Err("fetch must not be called in this test".to_string())
}

/// Injected fetch: serves fixed tampered bytes.
fn fetch_serving_tampered(
    _url: &str,
    _ssrf: &SsrfFilter,
    _deadline: std::time::Instant,
) -> Result<Vec<u8>, String> {
    Ok(b"these are not the bytes you pinned".to_vec())
}

fn far_deadline() -> std::time::Instant {
    std::time::Instant::now() + RESOLUTION_BUDGET
}

#[test]
fn tampered_download_fails_digest_verification_and_caches_nothing() {
    // The tampered-DOWNLOAD companion of the tampered-cache tests: the
    // "registry" (injected fetch) serves bytes that do not hash to the
    // pin. The resolution fails naming the DOWNLOADED origin and both
    // digests, and nothing is written to the cache.
    let dir = tempfile::tempdir().unwrap();
    let good = wat_to_wasm(&add_header_wat("registry"));
    let digest = sha256_hex(&good);
    let yaml = source_gateway_yaml(dir.path(), &dead_url(), &digest, None, None, &[]);
    let gateway = parse_gateway(&yaml).unwrap();

    let resolutions = resolve_sources_with_fetch(&gateway, fetch_serving_tampered, far_deadline());
    match resolutions.get("remote").unwrap() {
        Err(SourceError::DigestMismatch {
            origin,
            expected,
            actual,
            ..
        }) => {
            assert_eq!(*origin, "downloaded", "names the download origin");
            assert_eq!(expected, &digest);
            assert_eq!(actual, &sha256_hex(b"these are not the bytes you pinned"));
        }
        other => panic!("expected a downloaded-origin digest mismatch, got {other:?}"),
    }
    // Nothing was cached for a failed resolution.
    let cached: Vec<_> = std::fs::read_dir(dir.path())
        .map(|rd| rd.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();
    assert!(cached.is_empty(), "no artifact cached: {cached:?}");
}

#[test]
fn successful_download_verifies_and_caches_for_offline_load() {
    // The positive download leg: the injected registry serves the
    // pinned bytes, they verify, land in the digest-named cache slot,
    // and a dataplane built afterwards resolves them from the cache
    // (no network) into a Healthy plugin.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = sha256_hex(&artifact);
    let yaml = source_gateway_yaml(dir.path(), &dead_url(), &digest, None, None, &[]);
    let gateway = parse_gateway(&yaml).unwrap();

    FETCH_BYTES.with(|b| *b.borrow_mut() = artifact.clone());
    let resolutions = resolve_sources_with_fetch(&gateway, fetch_serving_stashed, far_deadline());
    let path = resolutions.get("remote").unwrap().as_ref().unwrap().clone();
    assert_eq!(path, dir.path().join(format!("{digest}.wasm")));
    assert!(path.is_file(), "the verified artifact is cached");
    assert_eq!(
        sha256_hex(&std::fs::read(&path).unwrap()),
        digest,
        "cached bytes are the verified bytes"
    );

    // Offline load from the fresh cache through the real dataplane.
    let dp = dataplane_from(&yaml);
    let status = remote_status(&dp);
    assert_eq!(status.state, PluginStatusState::Healthy, "{status:?}");
    assert_eq!(status.sha256, digest);
}

#[test]
fn resolution_budget_exhaustion_fails_uncached_plugin_but_not_cached() {
    // An exhausted per-publish budget fails the plugins that still
    // need the network, step-named, while cache hits (no network)
    // keep resolving. The fetcher is wired to a must-not-be-called
    // fn: the budget gate must stop the pipeline BEFORE any fetch.
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("kept"));
    let kept_digest = cache_artifact(dir.path(), &artifact);
    let missed_digest = "b".repeat(64);
    let yaml = format!(
        "allow_empty_routes: true\n\
         plugin_registry:\n  cache_dir: {}\n\
         plugins:\n\
         - name: kept\n\
         \x20 source:\n\
         \x20   url: https://127.0.0.1:{}/kept.wasm\n\
         \x20   digest: {kept_digest}\n\
         \x20 phases: [request_headers]\n\
         - name: missed\n\
         \x20 source:\n\
         \x20   url: https://127.0.0.1:{}/missed.wasm\n\
         \x20   digest: {missed_digest}\n\
         \x20 phases: [request_headers]\n",
        dir.path().display(),
        dead_port(),
        dead_port(),
    );
    let gateway = parse_gateway(&yaml).unwrap();

    // A deadline already in the past: the budget is exhausted.
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let resolutions = resolve_sources_with_fetch(&gateway, fetch_must_not_be_called, past);

    let kept = resolutions.get("kept").unwrap();
    assert!(kept.is_ok(), "a cache hit needs no budget: {kept:?}");

    match resolutions.get("missed").unwrap() {
        Err(SourceError::ResolutionBudgetExceeded {
            plugin,
            budget_secs,
        }) => {
            assert_eq!(plugin, "missed");
            assert_eq!(*budget_secs, RESOLUTION_BUDGET.as_secs());
        }
        other => panic!("expected budget exhaustion, got {other:?}"),
    }
    let msg = format!(
        "{}",
        SourceError::ResolutionBudgetExceeded {
            plugin: "missed".to_string(),
            budget_secs: RESOLUTION_BUDGET.as_secs(),
        }
    );
    assert!(msg.contains("missed"), "names the plugin: {msg}");
    assert!(msg.contains("budget"), "names the step: {msg}");
}

#[test]
fn resolver_rejects_escaping_and_absolute_cache_paths() {
    // Containment (review finding): cache_path is where the resolver
    // creates directories and writes bytes — it must stay inside the
    // cache dir. Rejected before any cache lookup or download (the
    // fetcher is wired to a must-not-be-called fn).
    for (path, why) in [
        ("../../escape.wasm", "parent segments"),
        ("/etc/dwara/escape.wasm", "absolute"),
        ("", "empty"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let yaml = format!(
            "allow_empty_routes: true\n\
             plugin_registry:\n  cache_dir: {}\n\
             plugins:\n\
             - name: remote\n\
             \x20 source:\n\
             \x20   url: https://127.0.0.1:{}/p.wasm\n\
             \x20   digest: {}\n\
             \x20   cache_path: \"{path}\"\n\
             \x20 phases: [request_headers]\n",
            dir.path().display(),
            dead_port(),
            "c".repeat(64),
        );
        let gateway = parse_gateway(&yaml).unwrap();
        let resolutions =
            resolve_sources_with_fetch(&gateway, fetch_must_not_be_called, far_deadline());
        match resolutions.get("remote").unwrap() {
            Err(SourceError::InvalidCachePath {
                path: p, reason, ..
            }) => {
                assert_eq!(p, path, "names the path ({why})");
                assert!(
                    reason.contains(why),
                    "reason names the violation '{why}': {reason}"
                );
            }
            other => panic!("expected InvalidCachePath for '{path}', got {other:?}"),
        }
    }
}

#[test]
fn resolver_accepts_nested_relative_cache_path() {
    // Positive control: a relative path with subdirectories but no
    // parent segments is fine (and the artifact lands there).
    let dir = tempfile::tempdir().unwrap();
    let artifact = wat_to_wasm(&add_header_wat("registry"));
    let digest = sha256_hex(&artifact);
    let yaml = format!(
        "allow_empty_routes: true\n\
         plugin_registry:\n  cache_dir: {}\n\
         plugins:\n\
         - name: remote\n\
         \x20 source:\n\
         \x20   url: https://127.0.0.1:{}/p.wasm\n\
         \x20   digest: {digest}\n\
         \x20   cache_path: nested/dir/override.wasm\n\
         \x20 phases: [request_headers]\n",
        dir.path().display(),
        dead_port(),
    );
    let gateway = parse_gateway(&yaml).unwrap();
    FETCH_BYTES.with(|b| *b.borrow_mut() = artifact);
    let resolutions = resolve_sources_with_fetch(&gateway, fetch_serving_stashed, far_deadline());
    let path = resolutions.get("remote").unwrap().as_ref().unwrap().clone();
    assert_eq!(
        path,
        dir.path().join("nested/dir/override.wasm"),
        "the override path is used and stays under the cache dir"
    );
    assert!(path.is_file(), "the verified artifact was written there");
}

// --- digest parity re-check at load (verify -> read window) --------------------

#[test]
fn load_rechecks_pinned_digest_against_loaded_bytes() {
    // Review nit: the resolver verifies the bytes IT read; the load
    // re-reads the file. If the artifact is swapped in that window
    // (simulated here by handing the lifecycle a resolution for a
    // path whose bytes no longer hash to the pin), the plugin must
    // fail closed, never load the unverified bytes.
    let dir = tempfile::tempdir().unwrap();
    let good = wat_to_wasm(&add_header_wat("good"));
    let pinned = sha256_hex(&good);
    let swapped = dir.path().join("swapped.wasm");
    std::fs::write(&swapped, b"bytes swapped after verification").unwrap();

    let config = dwara_core::config::PluginConfig {
        name: "remote".to_string(),
        wasm: None,
        native: None,
        source: Some(dwara_core::config::PluginSourceConfig {
            url: "https://registry.example.com/p.wasm".to_string(),
            digest: pinned.clone(),
            signature: None,
            public_key: None,
            cache_path: None,
        }),
        phases: vec![dwara_core::config::PluginPhase::RequestHeaders],
        config: None,
        limits: None,
    };
    let mut sources = std::collections::HashMap::new();
    sources.insert("remote".to_string(), Ok(swapped.clone()));
    let lifecycle = dwara_core::wasm::lifecycle::PluginLifecycle::new();
    lifecycle
        .load(&[config], &sources)
        .expect("per-plugin isolation keeps the load Ok");

    let plugin = lifecycle.get_plugin("remote").unwrap();
    match &plugin.health {
        dwara_core::wasm::lifecycle::PluginHealth::Crashed { error, .. } => {
            assert!(
                error.contains("digest re-check failed"),
                "names the re-check step: {error}"
            );
            assert!(error.contains(&pinned), "names the pinned digest: {error}");
        }
        other => panic!("expected Crashed after the swap, got {other:?}"),
    }
    assert_eq!(
        plugin.checksum, "",
        "the swapped bytes never count as loaded"
    );
}

// --- validation: containment + key-without-signature --------------------------

#[test]
fn validation_rejects_public_key_without_signature() {
    // Review finding: a key without a signature used to be silently
    // ignored; it is a config mistake and must be rejected.
    let key = "9f".repeat(32); // well-formed 64-hex key
    let yaml = validation_yaml(
        &format!(
            "    source:\n      url: https://r.example.com/remote.wasm\n      digest: {}\n      public_key: {key}\n",
            "ab".repeat(32)
        ),
        "",
    );
    let issues = validate(&parse_gateway(&yaml).unwrap());
    assert!(
        issues.iter().any(|i| i.entity == "plugin"
            && i.name == "remote"
            && i.field == "source.signature"
            && i.message.contains("without a signature")),
        "expected the key-without-signature rejection, got {issues:?}"
    );
}

#[test]
fn validation_rejects_cache_paths_escaping_the_cache_dir() {
    for (path, why) in [
        ("../../escape.wasm", "parent segments"),
        ("/var/lib/escape.wasm", "absolute"),
    ] {
        let yaml = validation_yaml(
            &format!(
                "    source:\n      url: https://r.example.com/remote.wasm\n      digest: {}\n      cache_path: \"{path}\"\n",
                "ab".repeat(32)
            ),
            "",
        );
        let issues = validate(&parse_gateway(&yaml).unwrap());
        assert!(
            issues.iter().any(|i| i.entity == "plugin"
                && i.field == "source.cache_path"
                && i.message.contains(why)
                && i.message.contains("relative path")),
            "expected a containment rejection for '{path}' naming '{why}', got {issues:?}"
        );
    }
}

#[test]
fn validation_accepts_nested_relative_cache_path() {
    let yaml = validation_yaml(
        &format!(
            "    source:\n      url: https://r.example.com/remote.wasm\n      digest: {}\n      cache_path: vendor/remote-1.2.0.wasm\n",
            "ab".repeat(32)
        ),
        "",
    );
    let issues = validate(&parse_gateway(&yaml).unwrap());
    assert!(
        !issues
            .iter()
            .any(|i| i.entity == "plugin" && i.field == "source.cache_path"),
        "a nested relative path is valid, got {issues:?}"
    );
}
