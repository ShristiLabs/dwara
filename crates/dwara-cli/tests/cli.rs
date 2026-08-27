//! CLI tests (DW-022): the library halves (validate/fmt/diff/lint) plus
//! binary exit codes for the load-bearing contract (validate = 1 on
//! issues, lint = 2 on warnings).

use dwara_cli::{
    diff_configs, format_config_text, lint_config, validate_config_text, ValidateOutcome,
};

const VALID: &str = "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: 18080\n\
     routes:\n  - name: r1\n    service: svc\n\
     \x20   match:\n      path:\n        type: prefix\n        value: /api\n\
     \x20   action:\n      type: proxy\n\
     services:\n  - name: svc\n    upstream: echo\n\
     upstreams:\n  - name: echo\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n";

// --- validate -------------------------------------------------------------

#[test]
fn validate_accepts_a_good_config() {
    match validate_config_text(VALID) {
        ValidateOutcome::Valid { routes } => assert_eq!(routes, 1),
        ValidateOutcome::Invalid(issues) => panic!("expected valid, got {issues:?}"),
    }
}

#[test]
fn validate_reports_schema_error_with_path() {
    let bad = "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: not-a-port\n";
    match validate_config_text(bad) {
        ValidateOutcome::Invalid(issues) => {
            assert!(issues.iter().any(|i| i.contains("listeners[0].port")));
        }
        ValidateOutcome::Valid { .. } => panic!("expected invalid"),
    }
}

#[test]
fn validate_reports_semantic_issues_all_at_once() {
    // Unknown service reference AND duplicate upstream name in one doc.
    let bad = VALID.to_string()
        + "  - name: echo\n    endpoints:\n      - { address: 127.0.0.1, port: 2 }\n";
    match validate_config_text(&bad) {
        ValidateOutcome::Invalid(issues) => {
            assert!(issues.iter().any(|i| i.contains("duplicate")));
        }
        ValidateOutcome::Valid { .. } => panic!("expected invalid"),
    }
}

#[test]
fn validate_reports_the_zero_route_guard_unless_opted_in() {
    // #129: a zero-route config (the torn-write shape) is invalid and the
    // issue names the offending field and the allow_empty_routes remedy;
    // the explicit opt-in validates and reports zero routes.
    match validate_config_text("listeners: []\n") {
        ValidateOutcome::Invalid(issues) => {
            assert!(
                issues.iter().any(|i| i.contains("routes is empty")),
                "issues must name the empty routes guard: {issues:?}"
            );
            assert!(
                issues
                    .iter()
                    .any(|i| i.contains("allow_empty_routes: true")),
                "issues must name the opt-in remedy: {issues:?}"
            );
        }
        ValidateOutcome::Valid { .. } => panic!("expected invalid"),
    }
    match validate_config_text("allow_empty_routes: true\n") {
        ValidateOutcome::Valid { routes } => assert_eq!(routes, 0),
        ValidateOutcome::Invalid(issues) => panic!("opted-in shape is valid, got {issues:?}"),
    }
}

// --- fmt --------------------------------------------------------------------

#[test]
fn fmt_round_trips_and_is_stable() {
    let once = format_config_text(VALID).expect("formats");
    let twice = format_config_text(&once).expect("round-trips");
    assert_eq!(once, twice, "normalization must be idempotent");
    // The round-trip parses to the same shape.
    assert!(matches!(
        validate_config_text(&once),
        ValidateOutcome::Valid { .. }
    ));
}

// --- diff -------------------------------------------------------------------

#[test]
fn diff_reports_route_upstream_consumer_deltas() {
    let mut changed = VALID.to_string();
    changed.push_str("  - name: extra\n    endpoints:\n      - { address: 127.0.0.1, port: 3 }\n");
    let out = diff_configs(VALID, &changed).expect("diffs");
    assert!(out.contains("+ upstream extra"), "out: {out}");
    assert!(!out.contains("- route"), "out: {out}");
    let reverse = diff_configs(&changed, VALID).expect("diffs");
    assert!(reverse.contains("- upstream extra"), "out: {reverse}");
    let same = diff_configs(VALID, VALID).expect("diffs");
    assert!(same.contains("no route/upstream/consumer differences"));
}

#[test]
fn diff_rejects_an_invalid_side() {
    let bad = "listeners:\n  - name: x\n    address: 1.2.3.4\n    port: 0\n";
    assert!(diff_configs(VALID, bad).is_err());
}

// --- lint -------------------------------------------------------------------

#[test]
fn lint_flags_unused_consumer_policy_and_unreferenced_upstream() {
    let doc = format!(
        "{VALID}consumers:\n  - name: lonely\npolicies:\n  - name: dead-policy\n    rate_limit: {{ requests: 1, window_seconds: 1 }}\n"
    );
    let gateway = dwara_core::config::parse_gateway(&doc).expect("parses");
    let warnings = lint_config(&gateway);
    let texts: Vec<String> = warnings.iter().map(|w| w.to_string()).collect();
    assert!(
        texts.iter().any(|t| t.contains("consumer/lonely")),
        "warnings: {texts:?}"
    );
    assert!(
        texts.iter().any(|t| t.contains("policy/dead-policy")),
        "warnings: {texts:?}"
    );
    // `echo` IS referenced by svc; no upstream warning expected.
    assert!(
        !texts.iter().any(|t| t.contains("upstream/echo")),
        "warnings: {texts:?}"
    );
}

#[test]
fn lint_counts_the_new_attachment_levels_as_usage() {
    // #123: a policy attached ONLY at the listener or gateway (global)
    // level is used, and a consumer referenced only by an authorization
    // rule at any level (here: the gateway's) is used — neither may be
    // flagged. The policy is attached at BOTH new levels to pin that
    // each counts.
    let doc = "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: 18080\n    policies: [baseline]\n\
         global_policies: [baseline]\n\
         policies:\n  - name: baseline\n    rate_limit: { requests: 1, window_seconds: 1 }\n\
         consumers:\n  - name: acme\n    credentials:\n      - { type: api_key, key: k }\n\
         authorization:\n  denied_consumers: [acme]\n\
         routes:\n  - name: r1\n    service: svc\n\
         \x20   match:\n      path:\n        type: prefix\n        value: /api\n\
         \x20   action:\n      type: proxy\n\
         services:\n  - name: svc\n    upstream: echo\n\
         upstreams:\n  - name: echo\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n";
    let gateway = dwara_core::config::parse_gateway(doc).expect("parses");
    let warnings = lint_config(&gateway);
    let texts: Vec<String> = warnings.iter().map(|w| w.to_string()).collect();
    assert!(
        !texts.iter().any(|t| t.contains("policy/")),
        "baseline is attached (listener + global): {texts:?}"
    );
    assert!(
        !texts.iter().any(|t| t.contains("consumer/acme")),
        "acme is referenced by the global authorization: {texts:?}"
    );
}

#[test]
fn lint_flags_regex_shadowed_by_exact_and_duplicate_prefix() {
    let doc = "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: 18080\n\
         routes:\n\
         \x20 - name: p1\n    service: svc\n\
         \x20   match:\n      path:\n        type: prefix\n        value: /api\n\
         \x20   action:\n      type: proxy\n\
         \x20 - name: exact-hit\n    service: svc\n\
         \x20   match:\n      path:\n        type: exact\n        value: /api/v1\n\
         \x20   action:\n      type: proxy\n\
         \x20 - name: re\n    service: svc\n\
         \x20   match:\n      path:\n        type: regex\n        value: /api/.*\n\
         \x20   action:\n      type: proxy\n\
         \x20 - name: p2\n    service: svc\n\
         \x20   match:\n      path:\n        type: prefix\n        value: /api\n\
         \x20   action:\n      type: proxy\n\
         services:\n  - name: svc\n    upstream: echo\n\
         upstreams:\n  - name: echo\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n";
    let gateway = dwara_core::config::parse_gateway(doc).expect("parses");
    let warnings = lint_config(&gateway);
    let texts: Vec<String> = warnings.iter().map(|w| w.to_string()).collect();
    assert!(
        texts
            .iter()
            .any(|t| t.contains("route/re") && t.contains("shadowed")),
        "warnings: {texts:?}"
    );
    // One /api prefix (r1) plus another /api prefix (p2): the later one
    // is a duplicate pattern.
    assert!(
        texts
            .iter()
            .any(|t| t.contains("route/p2") && t.contains("duplicate prefix")),
        "warnings: {texts:?}"
    );
}

#[test]
fn lint_clean_config_has_no_warnings() {
    let gateway = dwara_core::config::parse_gateway(VALID).expect("parses");
    assert!(lint_config(&gateway).is_empty());
}

// --- binary exit codes -------------------------------------------------------

fn run_cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_dwara-cli"))
        .args(args)
        .output()
        .expect("runs dwara-cli")
}

#[test]
fn binary_validate_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.yaml");
    std::fs::write(&good, VALID).unwrap();
    let out = run_cli(&["validate", good.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "listeners: 42\n").unwrap();
    let out = run_cli(&["validate", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stderr.is_empty(), "issues must be printed");
}

#[test]
fn binary_lint_exits_two_on_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let doc = format!(
        "{VALID}consumers:\n  - name: lonely\npolicies:\n  - name: dead-policy\n    rate_limit: {{ requests: 1, window_seconds: 1 }}\n"
    );
    let file = dir.path().join("linty.yaml");
    std::fs::write(&file, doc).unwrap();
    let out = run_cli(&["lint", file.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A clean config lints to 0.
    let clean = dir.path().join("clean.yaml");
    std::fs::write(&clean, VALID).unwrap();
    let out = run_cli(&["lint", clean.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));

    // An invalid config lints to 1 (fix validation first).
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "listeners: 42\n").unwrap();
    let out = run_cli(&["lint", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn binary_fmt_rewrites_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("messy.yaml");
    // Same config with a no-op-on-purpose difference: extra blank lines
    // the normalizer drops.
    let messy = format!("\n\n{VALID}\n");
    std::fs::write(&file, messy).unwrap();
    let out = run_cli(&["fmt", file.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = std::fs::read_to_string(&file).unwrap();
    assert_eq!(after, format_config_text(VALID).unwrap());
}

// --- DW-026: schema subcommand ---------------------------------------------

/// `dwara-cli schema` prints valid, pretty JSON for the gateway config:
/// exit 0, parses, carries a title and $defs, and is byte-stable across
/// invocations (the CI freshness check diffs the committed reference
/// against a second run of this stream).
#[test]
fn binary_schema_prints_valid_stable_json_schema() {
    let out = run_cli(&["schema"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let first_run = out.stdout.clone();
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("schema output is JSON");
    assert!(
        json.get("title").is_some(),
        "schema must carry a title: top-level keys {:?}",
        json.as_object().map(|m| m.keys().collect::<Vec<_>>())
    );
    assert!(
        json.get("$defs").is_some(),
        "schema must carry $defs (schemars flavor)"
    );
    // The config model surfaces listeners/routes at the top level.
    assert!(json
        .get("properties")
        .and_then(|p| p.get("listeners"))
        .is_some());
    assert!(json
        .get("properties")
        .and_then(|p| p.get("routes"))
        .is_some());

    // Determinism: a second run is byte-identical.
    let again = run_cli(&["schema"]);
    assert_eq!(first_run, again.stdout, "schema output must be stable");
}

/// The committed config reference (config-reference.json at the repo
/// root, per the CI freshness step) is exactly what the subcommand
/// emits — the local half of that check.
#[test]
fn binary_schema_matches_committed_config_reference() {
    let reference =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config-reference.json");
    let committed =
        std::fs::read(&reference).unwrap_or_else(|e| panic!("read {}: {e}", reference.display()));
    let out = run_cli(&["schema"]);
    assert_eq!(out.status.code(), Some(0));
    // Both sides end in a trailing newline (println).
    let emitted = out.stdout;
    let emitted = if emitted.ends_with(b"\n") {
        &emitted[..emitted.len() - 1]
    } else {
        &emitted[..]
    };
    let committed = if committed.ends_with(b"\n") {
        &committed[..committed.len() - 1]
    } else {
        &committed[..]
    };
    assert_eq!(
        emitted, committed,
        "committed config-reference.json is stale; regenerate with `dwara-cli schema`"
    );
}

// --- DW-022 follow-ups: exit-code separation, diff depth, fmt bytes ---

/// Exit-code contract end to end on ONE file evolving: schema error ->
/// validate 1; fixed schema but a lint warning -> validate 0, lint 2;
/// messages distinguish the two classes.
#[test]
fn validate_and_lint_exit_codes_distinguish_error_from_warning() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("evolving.yaml");

    // Stage 1: schema error (port not a number) AND a lint-worthy
    // consumer: validate must fail with exit 1 on the schema problem.
    let stage1 =
        format!("{VALID}consumers:\n  - name: lonely\n").replace("port: 18080", "port: not-a-port");
    std::fs::write(&file, stage1).unwrap();
    let out = run_cli(&["validate", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let v_err = String::from_utf8_lossy(&out.stderr).to_string();

    // Stage 2: schema fixed; the unused consumer remains -> lint-only.
    let stage2 = format!("{VALID}consumers:\n  - name: lonely\n");
    std::fs::write(&file, stage2).unwrap();
    let out = run_cli(&["validate", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "schema fixed must validate");
    let out = run_cli(&["lint", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    let l_err = String::from_utf8_lossy(&out.stderr).to_string();

    // The messages separate the classes: validate reported the field
    // path; lint reports the advisory consumer finding.
    assert!(v_err.contains("port"), "validate stderr: {v_err}");
    assert!(l_err.contains("consumer/lonely"), "lint stderr: {l_err}");
    assert!(!l_err.contains("port: not-a-port"), "lint stderr: {l_err}");
}

/// diff detects an added AND a removed route in one comparison.
#[test]
fn diff_detects_added_and_removed_route() {
    // B: r1 replaced by r2 (added + removed route), everything else same.
    let b = VALID.replace("routes:\n  - name: r1", "routes:\n  - name: r2");
    let out = diff_configs(VALID, &b).expect("diffs");
    assert!(out.contains("+ route r2"), "out: {out}");
    assert!(out.contains("- route r1"), "out: {out}");
}

/// #125: a CHANGED upstream — same name, different endpoint — is
/// reported as `~ upstream <name>`; it is neither added nor removed.
#[test]
fn diff_reports_same_name_upstream_endpoint_change() {
    // The endpoint mapping is the only `port: 1 }` in VALID; the
    // listener's `port: 18080` does not contain the trailing brace.
    let b = VALID.replace("port: 1 }", "port: 2 }");
    let out = diff_configs(VALID, &b).expect("diffs");
    assert!(out.contains("~ upstream echo"), "out: {out}");
    assert!(!out.contains("+ upstream"), "out: {out}");
    assert!(!out.contains("- upstream"), "out: {out}");
}

/// #125: a same-name upstream whose TIMEOUT knob changed is reported
/// (endpoint changes are not the only visible content delta), and it
/// is the only reported delta.
#[test]
fn diff_reports_same_name_upstream_timeout_change() {
    let a = format!("{VALID}    timeouts: {{ connect_ms: 100, read_ms: 1000 }}\n");
    let b = format!("{VALID}    timeouts: {{ connect_ms: 200, read_ms: 1000 }}\n");
    let out = diff_configs(&a, &b).expect("diffs");
    assert_eq!(out.trim(), "~ upstream echo", "exactly one delta: {out}");
}

/// #125: same-name content changes are reported for routes and
/// consumers too, not just upstreams.
#[test]
fn diff_reports_same_name_route_and_consumer_content_changes() {
    let route_b = VALID.replace("value: /api\n", "value: /api/v2\n");
    let out = diff_configs(VALID, &route_b).expect("diffs");
    assert!(out.contains("~ route r1"), "out: {out}");
    assert!(!out.contains("+ route"), "out: {out}");
    assert!(!out.contains("- route"), "out: {out}");

    let consumer = |key: &str| {
        format!("{VALID}consumers:\n  - name: acme\n    credentials:\n      - {{ type: api_key, key: {key} }}\n")
    };
    let out = diff_configs(&consumer("k1"), &consumer("k2")).expect("diffs");
    assert!(out.contains("~ consumer acme"), "out: {out}");
    assert!(!out.contains("+ consumer"), "out: {out}");
    assert!(!out.contains("- consumer"), "out: {out}");
}

/// Normalization makes source key order irrelevant: the same config
/// with mapping keys written in a different order produces identical
/// per-entity hashes and reports no differences (the hash is over the
/// normalized serialization, not the raw text).
#[test]
fn diff_ignores_source_key_order() {
    let reordered = VALID.replace(
        "- { address: 127.0.0.1, port: 1 }",
        "- { port: 1, address: 127.0.0.1 }",
    );
    let out = diff_configs(VALID, &reordered).expect("diffs");
    assert!(
        out.contains("no route/upstream/consumer differences"),
        "key order must not matter: {out}"
    );
}

/// #125 secrets discipline: when a same-name consumer's CREDENTIAL
/// changes, the report is the name only — neither the old nor the new
/// credential VALUE (nor any fragment of them) may appear in the diff
/// output.
#[test]
fn diff_changed_consumer_report_keeps_credential_values_out() {
    let consumer = |key: &str| {
        format!(
            "{VALID}consumers:\n  - name: acme\n    credentials:\n      - {{ type: api_key, key: {key} }}\n"
        )
    };
    let a = consumer("sk-live-9f1c2d3b4a");
    let b = consumer("sk-live-0e5f6a7b8c");
    let out = diff_configs(&a, &b).expect("diffs");
    assert_eq!(out.trim(), "~ consumer acme", "name-only report: {out}");
    assert!(
        !out.contains("sk-live"),
        "credential values must never print: {out}"
    );
}

/// #125: the diff SUBCOMMAND's exit-code contract — 0 whenever both
/// sides compile, including a changed-ONLY diff (`~` lines with no
/// adds/removes — the same exit code any other differences get today),
/// and 1 when a side is invalid. Deltas print on stdout.
#[test]
fn binary_diff_changed_only_keeps_differences_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.yaml");
    let b = dir.path().join("b.yaml");
    std::fs::write(&a, VALID).unwrap();
    // The only delta is the same-name endpoint change: `~ upstream echo`.
    std::fs::write(&b, VALID.replace("port: 1 }", "port: 2 }")).unwrap();
    let out = run_cli(&["diff", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a changed-only diff is still a differences result (exit 0): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("~ upstream echo"), "stdout: {stdout}");
    assert!(
        !stdout.contains("no route/upstream/consumer differences"),
        "a change must count as a difference: {stdout}"
    );

    // Identical sides: also 0, carrying the no-differences line.
    let out = run_cli(&["diff", a.to_str().unwrap(), a.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("no route/upstream/consumer differences"));

    // An invalid side remains the only diff failure mode: 1.
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "listeners: 42\n").unwrap();
    let out = run_cli(&["diff", a.to_str().unwrap(), bad.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The fmt BINARY is byte-idempotent: running it twice leaves the file
/// byte-identical to running it once.
#[test]
fn binary_fmt_twice_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("twice.yaml");
    std::fs::write(&file, format!("\n\n{VALID}\n\n")).unwrap();
    let out = run_cli(&["fmt", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let once = std::fs::read(&file).unwrap();
    let out = run_cli(&["fmt", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let twice = std::fs::read(&file).unwrap();
    assert_eq!(once, twice, "second fmt must not change a single byte");
}

/// Lint false-positive check: a regex route next to an exact route the
/// regex does NOT fully match stays clean (only true shadowing flags).
#[test]
fn lint_regex_not_shadowed_by_different_exact_path_stays_clean() {
    // Regex /special/.* and exact /api/v1: disjoint — no shadow warning.
    let doc = "listeners:\n  - name: main\n    address: 127.0.0.1\n    port: 18080\n\
         routes:\n\
         \x20 - name: re\n    service: svc\n\
         \x20   match:\n      path:\n        type: regex\n        value: /special/.*\n\
         \x20   action:\n      type: proxy\n\
         \x20 - name: exact-hit\n    service: svc\n\
         \x20   match:\n      path:\n        type: exact\n        value: /api/v1\n\
         \x20   action:\n      type: proxy\n\
         services:\n  - name: svc\n    upstream: echo\n\
         upstreams:\n  - name: echo\n    endpoints:\n      - { address: 127.0.0.1, port: 1 }\n";
    let gateway = dwara_core::config::parse_gateway(doc).expect("parses");
    assert!(
        lint_config(&gateway).is_empty(),
        "disjoint exact/regex routes must not warn"
    );
}
