//! Unit tests for the plugin registry reader
//! (`dwara_cli::plugin_registry`): manifest entry selection for
//! `plugin install` (highest-version default, exact `--version`,
//! error listings) plus the install path end-to-end against a
//! loopback HTTP server — the same `curl` fetch the command uses, no
//! external network. `plugin search` and the `--pr` flow's gh calls
//! are not exercised here.

use dwara_cli::plugin_registry;
use sha2::Digest;

fn temp_dir() -> std::path::PathBuf {
    // Process id + wall clock + a monotonically increasing counter:
    // parallel tests within one process can observe the same clock
    // tick (same pattern as plugin_publish_unit.rs).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dwara-plugin-install-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A manifest entry with a distinguishable URL per version.
fn entry(name: &str, version: &str, digest: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "version": version,
        "digest": digest,
        "url": format!("/{name}-{version}.wasm"),
    })
}

/// A manifest (JSON array) from (name, version, digest) tuples.
fn manifest(entries: &[(&str, &str, &str)]) -> String {
    let values: Vec<serde_json::Value> = entries.iter().map(|(n, v, d)| entry(n, v, d)).collect();
    serde_json::to_string(&values).unwrap()
}

fn parse(manifest: &str) -> Vec<serde_json::Value> {
    serde_json::from_str(manifest).unwrap()
}

fn sha256_direct(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize().iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// --- selection: highest version by default ---------------------------------

#[test]
fn multi_version_manifest_selects_the_highest() {
    // The OLD (lower) version is listed first: first-match must not
    // win, and 1.10.0 > 1.9.0 must compare numerically, not as text.
    let plugins = parse(&manifest(&[
        ("p", "1.9.0", "d190"),
        ("p", "1.10.0", "d1100"),
        ("p", "0.9.9", "d099"),
    ]));
    let selected = plugin_registry::select_entry(&plugins, "p", None).unwrap();
    assert_eq!(selected["version"], "1.10.0");
}

#[test]
fn other_names_are_ignored_when_selecting() {
    let plugins = parse(&manifest(&[
        ("other", "9.9.9", "dother"),
        ("p", "1.0.0", "dp1"),
        ("p", "2.0.0", "dp2"),
    ]));
    let selected = plugin_registry::select_entry(&plugins, "p", None).unwrap();
    assert_eq!(selected["name"], "p");
    assert_eq!(selected["version"], "2.0.0");
}

#[test]
fn release_outranks_its_pre_releases() {
    let plugins = parse(&manifest(&[
        ("p", "2.0.0-rc.10", "d1"),
        ("p", "2.0.0-rc.2", "d2"),
        ("p", "2.0.0", "d3"),
    ]));
    let selected = plugin_registry::select_entry(&plugins, "p", None).unwrap();
    assert_eq!(selected["version"], "2.0.0");
}

#[test]
fn pre_release_identifiers_order_per_semver_basics() {
    // alpha < alpha.1 < alpha.beta < beta (numeric vs alphanumeric
    // identifiers, longer lists winning on equal prefixes).
    let plugins = parse(&manifest(&[
        ("p", "1.0.0-alpha", "d1"),
        ("p", "1.0.0-alpha.1", "d2"),
        ("p", "1.0.0-alpha.beta", "d3"),
        ("p", "1.0.0-beta", "d4"),
    ]));
    let selected = plugin_registry::select_entry(&plugins, "p", None).unwrap();
    assert_eq!(selected["version"], "1.0.0-beta");
}

#[test]
fn build_metadata_never_affects_precedence() {
    // +build tags are dropped for ordering; precedence-equal versions
    // resolve deterministically to the first listed.
    let plugins = parse(&manifest(&[
        ("p", "1.0.0+build.2", "d1"),
        ("p", "1.0.0+build.10", "d2"),
    ]));
    let selected = plugin_registry::select_entry(&plugins, "p", None).unwrap();
    assert_eq!(selected["version"], "1.0.0+build.2");
}

#[test]
fn single_version_manifest_still_selects() {
    let plugins = parse(&manifest(&[("p", "1.0.0", "d1")]));
    let selected = plugin_registry::select_entry(&plugins, "p", None).unwrap();
    assert_eq!(selected["version"], "1.0.0");
}

// --- selection: exact --version ---------------------------------------------

#[test]
fn version_flag_picks_the_exact_entry() {
    let plugins = parse(&manifest(&[("p", "1.0.0", "d1"), ("p", "2.0.0", "d2")]));
    let selected = plugin_registry::select_entry(&plugins, "p", Some("1.0.0")).unwrap();
    assert_eq!(selected["version"], "1.0.0");
    assert_eq!(selected["digest"], "d1");
}

#[test]
fn version_flag_picks_an_exact_pre_release() {
    let plugins = parse(&manifest(&[
        ("p", "2.0.0-rc.1", "d1"),
        ("p", "2.0.0", "d2"),
    ]));
    let selected = plugin_registry::select_entry(&plugins, "p", Some("2.0.0-rc.1")).unwrap();
    assert_eq!(selected["version"], "2.0.0-rc.1");
}

#[test]
fn nonexistent_version_error_lists_available_versions() {
    let plugins = parse(&manifest(&[
        ("p", "1.0.0", "d1"),
        ("p", "2.0.0-rc.1", "d2"),
    ]));
    let err = plugin_registry::select_entry(&plugins, "p", Some("3.0.0")).unwrap_err();
    assert!(
        err.contains("3.0.0"),
        "error names the requested version: {err}"
    );
    assert!(err.contains("available versions"), "{err}");
    assert!(err.contains("1.0.0") && err.contains("2.0.0-rc.1"), "{err}");
}

// --- selection: errors ------------------------------------------------------

#[test]
fn unparseable_version_is_rejected_with_available_versions() {
    let plugins = parse(&manifest(&[("p", "1.0.0", "d1"), ("p", "latest", "d2")]));
    let err = plugin_registry::select_entry(&plugins, "p", None).unwrap_err();
    assert!(err.contains("latest"), "error names the bad version: {err}");
    assert!(err.contains("not a semantic version"), "{err}");
    assert!(
        err.contains("available versions") && err.contains("1.0.0"),
        "{err}"
    );
    assert!(
        err.contains("--version"),
        "error steers to --version: {err}"
    );
}

#[test]
fn malformed_core_versions_are_rejected() {
    for bad in ["1.0", "1.0.x", "v1.0.0", "1.0.0.4", ""] {
        let plugins = parse(&manifest(&[("p", "1.0.0", "d1"), ("p", bad, "d2")]));
        let err = plugin_registry::select_entry(&plugins, "p", None).unwrap_err();
        assert!(err.contains("not a semantic version"), "'{bad}': {err}");
    }
}

#[test]
fn unknown_name_still_reports_not_found() {
    let plugins = parse(&manifest(&[("p", "1.0.0", "d1")]));
    let err = plugin_registry::select_entry(&plugins, "nope", None).unwrap_err();
    assert!(err.contains("not found"), "{err}");
}

// --- install end-to-end over a loopback HTTP server -------------------------

/// Bind an ephemeral loopback port; the base URL is known before the
/// routes are built so manifest entries can carry absolute artifact
/// URLs (the install path fetches `entry.url` verbatim).
fn bind_loopback() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    (listener, format!("http://{addr}"))
}

/// Serve fixed byte routes on the bound listener. A single accepting
/// thread is enough — an install makes two sequential requests
/// (manifest + artifact). Unknown paths get a 404 so digest/URL bugs
/// surface as curl failures rather than hangs.
fn serve(listener: std::net::TcpListener, routes: Vec<(String, Vec<u8>)>) {
    use std::io::Read;
    use std::io::Write as _;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let Ok(n) = stream.read(&mut buf) else {
                continue;
            };
            let path = String::from_utf8_lossy(&buf[..n])
                .split(' ')
                .nth(1)
                .unwrap_or("")
                .to_string();
            match routes.iter().find(|(p, _)| *p == path) {
                Some((_, body)) => {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body);
                }
                None => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        }
    });
}

/// A registry serving `p` at 1.0.0 and 2.0.0 with distinct artifacts
/// (1.0.0 listed FIRST, so a first-match regression installs the old
/// one and fails the digest assertion).
fn multi_version_registry() -> (String, Vec<u8>, Vec<u8>) {
    let v1: Vec<u8> = b"\x00asm\x01\x00\x00\x00plugin-v1".to_vec();
    let v2: Vec<u8> = b"\x00asm\x01\x00\x00\x00plugin-v2".to_vec();
    let (listener, base) = bind_loopback();
    let manifest = serde_json::json!([
        {
            "name": "p",
            "version": "1.0.0",
            "digest": sha256_direct(&v1),
            "url": format!("{base}/p-1.0.0.wasm"),
        },
        {
            "name": "p",
            "version": "2.0.0",
            "digest": sha256_direct(&v2),
            "url": format!("{base}/p-2.0.0.wasm"),
        },
    ]);
    serve(
        listener,
        vec![
            (
                "/manifest.json".to_string(),
                manifest.to_string().into_bytes(),
            ),
            ("/p-1.0.0.wasm".to_string(), v1.clone()),
            ("/p-2.0.0.wasm".to_string(), v2.clone()),
        ],
    );
    (base, v1, v2)
}

#[test]
fn multi_version_manifest_installs_the_highest() {
    let (base, _v1, v2) = multi_version_registry();
    let dir = temp_dir();
    let result =
        plugin_registry::install("p", None, Some(&base), None, dir.to_str().unwrap()).unwrap();
    assert_eq!(result.digest, sha256_direct(&v2));
    let installed = std::fs::read(&result.path).unwrap();
    assert_eq!(installed, v2, "the 2.0.0 artifact must land on disk");
}

#[test]
fn install_version_flag_installs_the_exact_artifact() {
    let (base, v1, _v2) = multi_version_registry();
    let dir = temp_dir();
    let result =
        plugin_registry::install("p", Some("1.0.0"), Some(&base), None, dir.to_str().unwrap())
            .unwrap();
    assert_eq!(result.digest, sha256_direct(&v1));
    let installed = std::fs::read(&result.path).unwrap();
    assert_eq!(installed, v1);
}

#[test]
fn install_nonexistent_version_errors_without_downloading() {
    let (base, _v1, _v2) = multi_version_registry();
    let dir = temp_dir();
    let err =
        plugin_registry::install("p", Some("3.0.0"), Some(&base), None, dir.to_str().unwrap())
            .unwrap_err();
    assert!(
        err.contains("3.0.0") && err.contains("available versions"),
        "{err}"
    );
    assert!(
        err.contains("1.0.0") && err.contains("2.0.0"),
        "available versions are listed: {err}"
    );
    assert!(
        std::fs::read_dir(&dir).unwrap().next().is_none(),
        "nothing is written on a failed selection"
    );
}
