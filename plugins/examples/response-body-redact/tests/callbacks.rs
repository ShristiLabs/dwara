//! Callback-level unit tests: drive the real `proxy_on_*` exports.
//!
//! Same pattern as `static-auth`'s `tests/callbacks.rs`: `src/abi.rs`
//! compiles a fake host on non-wasm targets, so `cargo test` on the
//! development machine runs the actual proxy-wasm entrypoints. This
//! file pins the shim wiring (config -> root state -> buffer read ->
//! redact -> buffer write), not the redaction math (`tests/logic.rs`
//! does that).
//!
//! The scenarios run sequentially in one test (the one-test rule):
//! the per-instance root state is a process-wide static (mirroring
//! the wasm module's linear-memory static), so one scenario's
//! `test_reset()` between another scenario's `configure` and
//! `response_body` would race and flake if the scenarios ran as
//! parallel `#[test]` fns.

use response_body_redact::{
    abi::{fake, ACTION_CONTINUE},
    proxy_on_configure, proxy_on_response_body, proxy_on_vm_start, test_reset,
};

const CONFIG: &[u8] = br#"{"literals":["sk-live-12345"]}"#;

#[test]
fn callback_scenarios() {
    redacted_body_is_written_back();
    unchanged_body_is_not_written_back();
    malformed_config_refuses_to_activate();
}

fn redacted_body_is_written_back() {
    test_reset();
    fake::set_config(CONFIG);
    assert_eq!(proxy_on_vm_start(1, 0), 1);
    assert_eq!(proxy_on_configure(1, CONFIG.len() as i32), 1);

    let body = b"{\"card\":\"4111-1111-1111-1111\",\"key\":\"sk-live-12345\"}";
    fake::set_response_body(body);
    assert_eq!(
        proxy_on_response_body(2, body.len() as i32, 1),
        ACTION_CONTINUE
    );

    let written = fake::take_set_response_body().expect("changed body must be written back");
    let text = String::from_utf8(written).expect("body stays UTF-8");
    assert!(text.contains("****-****-****-1111"), "card masked: {text}");
    assert!(text.contains("************"), "literal starred: {text}");
    assert_eq!(text.len(), body.len(), "masking preserves length");
}

fn unchanged_body_is_not_written_back() {
    test_reset();
    fake::set_config(CONFIG);
    assert_eq!(proxy_on_configure(1, CONFIG.len() as i32), 1);

    let body = b"{\"message\":\"nothing sensitive here\"}";
    fake::set_response_body(body);
    assert_eq!(
        proxy_on_response_body(2, body.len() as i32, 1),
        ACTION_CONTINUE
    );
    assert!(
        fake::take_set_response_body().is_none(),
        "an unchanged body must not trigger a write"
    );
}

fn malformed_config_refuses_to_activate() {
    test_reset();
    fake::set_config(b"{oops");
    assert_eq!(
        proxy_on_configure(1, 6),
        0,
        "unparsable config fails closed"
    );
}
