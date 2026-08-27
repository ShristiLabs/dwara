//! Unit tests for the `${...}` secret-reference grammar and the
//! redaction helpers in `config::credentials` (DW-045).

use dwara_core::config::credentials::{
    parse_secret_reference, read_secret_file, redact_inline_secret, resolve_configured_secret,
    SecretRef, MAX_SECRET_FILE_BYTES,
};

fn temp_secret_file(tag: &str, contents: &str) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "dwara-dw045-cred-{}-{n}-{tag}.secret",
        std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    path.display().to_string()
}

// ---- parse ---------------------------------------------------------------

#[test]
fn plain_values_and_lone_dollars_are_literals() {
    assert!(parse_secret_reference("sk-live-abcdef").is_none());
    assert!(parse_secret_reference("").is_none());
    // Only a value STARTING with `${` is reference-shaped; a lone `$`
    // (and anything else without the prefix) stays a literal.
    assert!(parse_secret_reference("$HOME").is_none());
}

#[test]
fn env_file_and_redacted_forms_parse() {
    assert_eq!(
        parse_secret_reference("${MY_SECRET_KEY}"),
        Some(Ok(SecretRef::Env {
            name: "MY_SECRET_KEY".to_string()
        }))
    );
    assert_eq!(
        parse_secret_reference("${_LEADING_UNDERSCORE_OK1}"),
        Some(Ok(SecretRef::Env {
            name: "_LEADING_UNDERSCORE_OK1".to_string()
        }))
    );
    assert_eq!(
        parse_secret_reference("${file:/etc/dwara/keys/acme}"),
        Some(Ok(SecretRef::File {
            path: "/etc/dwara/keys/acme".to_string()
        }))
    );
    assert_eq!(
        parse_secret_reference("${file:relative/secret.txt}"),
        Some(Ok(SecretRef::File {
            path: "relative/secret.txt".to_string()
        }))
    );
    assert_eq!(
        parse_secret_reference("${redacted:sha256:e3b0c442}"),
        Some(Ok(SecretRef::Redacted {
            fingerprint: "sha256:e3b0c442".to_string()
        }))
    );
    // Bare ${redacted} (what a hand-typed round trip may carry).
    assert_eq!(
        parse_secret_reference("${redacted}"),
        Some(Ok(SecretRef::Redacted {
            fingerprint: String::new()
        }))
    );
}

#[test]
fn malformed_reference_shapes_are_errors_not_literals() {
    assert!(parse_secret_reference("${file:}").unwrap().is_err());
    assert!(parse_secret_reference("${1STARTS_WITH_DIGIT}")
        .unwrap()
        .is_err());
    assert!(parse_secret_reference("${has-dash}").unwrap().is_err());
    assert!(parse_secret_reference("${has space}").unwrap().is_err());
    assert!(parse_secret_reference("${redactedx:foo}").unwrap().is_err());
}

#[test]
fn unclosed_reference_shapes_fail_closed_instead_of_becoming_literals() {
    // #46 review: a value that OPENS a reference but is not a
    // well-formed whole-value reference — never closed
    // (`${unclosed`, `${file:/run/token`), or closed only mid-string
    // (`${KEY}extra`) — is reference-shaped garbage: a validation
    // ERROR, never a silently installed literal key. (Values that do
    // not START with `${` stay literals; mid-string shapes are pinned
    // above.)
    for value in [
        "${unclosed",
        "${file:/run/token",
        "${MY_SECRET extra}",
        "${KEY}extra",
        "${",
    ] {
        let parsed = parse_secret_reference(value)
            .unwrap_or_else(|| panic!("an opening `${{` is reference-shaped: {value}"));
        assert!(parsed.is_err(), "unclosed shape must fail closed: {value}");
        let err = resolve_configured_secret(value)
            .err()
            .unwrap_or_else(|| panic!("unclosed shape must never resolve: {value}"));
        assert!(
            err.contains(value),
            "error names the offending reference text: {err}"
        );
    }
}

#[test]
fn lowercase_env_names_parse_as_env_references() {
    // Case is free: `file:` / `redacted` are reserved prefixes matched
    // first, so a lowercase variable name cannot collide with them.
    assert_eq!(
        parse_secret_reference("${my_secret}"),
        Some(Ok(SecretRef::Env {
            name: "my_secret".to_string()
        }))
    );
}

#[test]
fn mid_string_reference_shapes_are_literals_not_interpolation() {
    // Full-string references only (DW-045): a `${...}` that does not
    // span the WHOLE value is not shell-style interpolation. It stays a
    // literal — a config writer cannot get silent partial expansion —
    // and is therefore redacted like any other inline value.
    for value in ["pre${MY_SECRET_KEY}post", "x${file:/etc/dwara/keys/acme}y"] {
        assert!(
            parse_secret_reference(value).is_none(),
            "mid-string shapes must not parse as references: {value}"
        );
        assert_eq!(
            resolve_configured_secret(value).unwrap(),
            value,
            "no partial expansion: the bytes pass through untouched"
        );
        let redacted = redact_inline_secret(value);
        assert_ne!(redacted, value, "a literal is redacted, not echoed");
        assert!(
            redacted.starts_with("${redacted:sha256:"),
            "placeholder shape: {redacted}"
        );
    }
}

#[test]
fn empty_and_nested_reference_shapes_fail_closed() {
    // `${}` names no variable; a reference inside a reference is not a
    // thing. Both are reference-shaped, so both are ERRORS — never
    // silently installed as literal keys.
    assert!(parse_secret_reference("${}").unwrap().is_err());
    assert!(parse_secret_reference("${${NESTED}}").unwrap().is_err());
}

#[test]
fn nested_references_inside_file_paths_are_not_expanded() {
    // There is no recursive expansion: `${file:${X}}` names a file
    // LITERALLY called `${X}`. The failure names that literal path,
    // proving the inner text was never substituted.
    let err = resolve_configured_secret("${file:${DW045_NO_SUCH_VAR}}")
        .expect_err("the literal path `${DW045_NO_SUCH_VAR}` does not exist");
    assert!(
        err.contains("${DW045_NO_SUCH_VAR}") && err.contains("cannot be read"),
        "error names the LITERAL (unexpanded) path: {err}"
    );
}

#[test]
fn zero_byte_secret_file_fails_closed() {
    // The true lower boundary: a completely empty file (the pinned
    // empty case is newline-only) resolves to nothing, which is not a
    // secret.
    let empty = temp_secret_file("zero-byte", "");
    let message = resolve_configured_secret(&format!("${{file:{empty}}}"))
        .expect_err("a zero-byte secret file must fail closed");
    assert!(
        message.contains("empty"),
        "message names the problem: {message}"
    );
}

#[test]
fn exactly_one_trailing_newline_is_trimmed_the_rest_is_key_material() {
    // The trim is ONE newline, by mounted-secret convention — not
    // "all trailing whitespace". A second newline survives INTO the
    // resolved value (and therefore into the hashed key material);
    // this pins the boundary so a well-meaning `trim_end()` cannot
    // silently change deployed keys.
    let two = temp_secret_file("two-nl", "key-material\n\n");
    assert_eq!(
        resolve_configured_secret(&format!("${{file:{two}}}")).unwrap(),
        "key-material\n",
        "only ONE trailing \\n is trimmed; the second is key material"
    );
    let crlf_pair = temp_secret_file("crlf-pair", "key-material\r\n\r\n");
    assert_eq!(
        resolve_configured_secret(&format!("${{file:{crlf_pair}}}")).unwrap(),
        "key-material\r\n",
        "one CRLF pair is trimmed; the second survives"
    );
}

#[test]
fn oversized_secret_files_fail_closed_at_a_bounded_read() {
    // #46 review: the `${file:/dev/zero}` shape — NUL bytes are valid
    // UTF-8, so an unbounded read runs until the allocator dies and
    // takes the process with it, on every reload. The read is bounded
    // at MAX_SECRET_FILE_BYTES; set_len builds a >1 MiB SPARSE file so
    // the test never writes a megabyte (/dev/zero itself is not
    // portable-safe to reference from a test).
    let dir = tempfile::tempdir().unwrap();
    let over = dir.path().join("oversized.secret");
    let f = std::fs::File::create(&over).unwrap();
    f.set_len(MAX_SECRET_FILE_BYTES as u64 + 1).unwrap();
    drop(f);
    let err = read_secret_file(&over.display().to_string()).unwrap_err();
    assert!(
        err.contains(&over.display().to_string()) && err.contains("1 MiB"),
        "error names the path and the limit: {err}"
    );
    // Exactly AT the cap the read is bounded but legal (the boundary
    // is inclusive): a cap-sized file of NUL bytes is a valid, if
    // silly, secret — the limit guards memory, not content.
    let at = dir.path().join("at-cap.secret");
    let f = std::fs::File::create(&at).unwrap();
    f.set_len(MAX_SECRET_FILE_BYTES as u64).unwrap();
    drop(f);
    assert_eq!(
        read_secret_file(&at.display().to_string()).unwrap().len(),
        MAX_SECRET_FILE_BYTES,
        "a file at exactly the cap reads whole"
    );
}

#[test]
fn unreadable_paths_fail_closed_naming_the_path() {
    // A directory is deterministically unreadable as a secret file on
    // every platform (EISDIR, root included) — the "file became
    // unreadable mid-run" shape without permission gymnastics.
    let dir = std::env::temp_dir();
    let err = read_secret_file(&dir.display().to_string()).unwrap_err();
    assert!(
        err.contains("cannot be read") && err.contains(&dir.display().to_string()),
        "error names the unreadable path and reason: {err}"
    );
}

#[cfg(unix)]
#[test]
fn non_unicode_env_value_fails_closed() {
    use std::os::unix::ffi::OsStringExt as _;
    // 0xff is never valid UTF-8: the variable resolves to NotUnicode.
    // The reference must fail closed naming the VARIABLE — the invalid
    // bytes are potential key material and must not reach the message.
    let name = format!("DWARA_TEST_SECRET_DW045_BYTES_{}", std::process::id());
    let raw = std::ffi::OsString::from_vec(vec![0xff, 0xfe, b's']);
    std::env::set_var(&name, &raw);
    let err = resolve_configured_secret(&format!("${{{name}}}"))
        .expect_err("non-Unicode env values must fail closed");
    assert!(
        err.contains(&name) && err.contains("not valid Unicode"),
        "error names the variable and reason, never the bytes: {err}"
    );
    std::env::remove_var(&name);
}

// ---- resolve ---------------------------------------------------------------

#[test]
fn literals_pass_through_resolution_untouched() {
    assert_eq!(
        resolve_configured_secret("plain-literal-key").unwrap(),
        "plain-literal-key"
    );
}

#[test]
fn env_references_resolve_at_call_time() {
    // Unique per-run name so parallel tests can never collide.
    let name = format!("DWARA_TEST_SECRET_DW045_{}", std::process::id());
    std::env::set_var(&name, "env-resolved-value");
    assert_eq!(
        resolve_configured_secret(&format!("${{{name}}}")).unwrap(),
        "env-resolved-value"
    );
    std::env::remove_var(&name);

    let missing = resolve_configured_secret("${DWARA_TEST_SECRET_DW045_MISSING_1c77}");
    let message = missing.expect_err("unset variable must fail closed");
    assert!(
        message.contains("DWARA_TEST_SECRET_DW045_MISSING_1c77") && message.contains("not set"),
        "error must name the variable and reason: {message}"
    );

    std::env::set_var(&name, "");
    let empty = resolve_configured_secret(&format!("${{{name}}}"));
    assert!(
        empty
            .expect_err("empty variable must fail closed")
            .contains("empty"),
        "empty resolved secrets are rejected"
    );
    std::env::remove_var(&name);
}

#[test]
fn file_references_trim_one_trailing_newline_and_reject_empty() {
    let with_newline = temp_secret_file("nl", "file-secret-1\n");
    assert_eq!(
        resolve_configured_secret(&format!("${{file:{with_newline}}}")).unwrap(),
        "file-secret-1"
    );
    // A single trailing newline is trimmed; interior newlines survive.
    let crlf = temp_secret_file("crlf", "file-secret-2\r\n");
    assert_eq!(
        resolve_configured_secret(&format!("${{file:{crlf}}}")).unwrap(),
        "file-secret-2"
    );
    let two = temp_secret_file("two", "line-one\nline-two\n");
    assert_eq!(
        resolve_configured_secret(&format!("${{file:{two}}}")).unwrap(),
        "line-one\nline-two"
    );
    let empty = temp_secret_file("empty", "\n");
    let message = resolve_configured_secret(&format!("${{file:{empty}}}"))
        .expect_err("empty secret file must fail closed");
    assert!(
        message.contains("empty"),
        "message names the problem: {message}"
    );

    let missing = resolve_configured_secret("${file:/nonexistent/dwara-dw045/nope.secret}");
    let message = missing.expect_err("missing secret file must fail closed");
    assert!(
        message.contains("/nonexistent/dwara-dw045/nope.secret"),
        "error names the path: {message}"
    );
}

#[test]
fn redaction_placeholders_never_resolve() {
    let err = resolve_configured_secret("${redacted:sha256:e3b0c442}")
        .expect_err("placeholder must fail closed");
    assert!(
        err.contains("redaction placeholder"),
        "error explains the placeholder: {err}"
    );
}

#[test]
fn read_secret_file_reports_missing_paths_precisely() {
    let err = read_secret_file("/nonexistent/dwara-dw045/dir/other.secret").unwrap_err();
    assert!(
        err.contains("/nonexistent/dwara-dw045/dir/other.secret") && err.contains("cannot be read"),
        "error names the path and reason: {err}"
    );
}

// ---- redaction ---------------------------------------------------------------

#[test]
fn inline_values_redact_to_fingerprinted_placeholders() {
    let canary = "sk-live-canary-dw045-9b1c";
    let redacted = redact_inline_secret(canary);
    assert!(
        !redacted.contains(canary),
        "redaction must remove the value: {redacted}"
    );
    assert!(
        redacted.starts_with("${redacted:sha256:"),
        "placeholder shape: {redacted}"
    );
    // The fingerprint is a short sha256 prefix: stable per value, and
    // DIFFERENT values produce different placeholders (operators can
    // compare which key a generation carries).
    assert_eq!(redacted, redact_inline_secret(canary));
    assert_ne!(redacted, redact_inline_secret("another-key"));
}

#[test]
fn reference_shaped_values_pass_redaction_through_unchanged() {
    for value in [
        "${MY_SECRET_KEY}",
        "${file:/etc/dwara/keys/acme}",
        "${redacted:sha256:e3b0c442}",
    ] {
        assert_eq!(redact_inline_secret(value), value);
    }
}

#[test]
fn redacted_placeholders_round_trip_to_a_parseable_but_unresolvable_form() {
    // The GET-then-PATCH footgun: a placeholder carried back through a
    // publishing surface must PARSE (so validation reaches it and can
    // name the field) but never RESOLVE (so placeholder bytes can never
    // become a live key).
    let placeholder = redact_inline_secret("some-inline-key");
    let parsed = parse_secret_reference(&placeholder).unwrap().unwrap();
    assert!(matches!(parsed, SecretRef::Redacted { .. }));
    assert!(parsed.resolve().is_err());
}
