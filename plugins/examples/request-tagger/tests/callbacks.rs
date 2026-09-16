//! Unit and callback-level tests for request-tagger.
//!
//! Level 1 of the plugin testing guide: the pure correlation rule,
//! then the real `proxy_on_*` exports against the fake host from
//! `src/abi.rs` (`cargo test` on the development machine).
//!
//! The callback scenarios run sequentially in one test: the
//! per-instance HTTP context is a process-wide static (mirroring the
//! wasm module's linear-memory static), so scenarios must not
//! interleave.

use request_tagger::{
    abi::{fake, ACTION_CONTINUE},
    correlation_id, proxy_on_request_headers, proxy_on_response_headers, proxy_on_vm_start,
    test_reset, CORRELATION_HEADER, NAME_HEADER, PLUGIN_NAME, REQUEST_ID_HEADER,
};

#[test]
fn correlation_rule() {
    assert_eq!(correlation_id(Some("abc-123")), "abc-123");
    assert_eq!(correlation_id(Some("")), "unset");
    assert_eq!(correlation_id(None), "unset");
}

#[test]
fn callback_scenarios() {
    test_reset();
    assert_eq!(proxy_on_vm_start(1, 0), 1);

    // --- with an inbound request id: both directions carry it -----
    fake::set_request_headers(&[
        (":method", "GET"),
        (":path", "/v1/things"),
        (REQUEST_ID_HEADER, "req-42"),
    ]);
    assert_eq!(proxy_on_request_headers(2, 3, 1), ACTION_CONTINUE);
    let stamped = fake::take_added_request_headers();
    assert!(stamped.contains(&(NAME_HEADER.to_string(), PLUGIN_NAME.to_string())));
    assert!(
        stamped.contains(&(CORRELATION_HEADER.to_string(), "req-42".to_string())),
        "request stamps: {stamped:?}"
    );

    // Response phase: the SAME id is stamped on the response headers
    // (what the client would see).
    assert_eq!(proxy_on_response_headers(2, 1, 1), ACTION_CONTINUE);
    let stamped = fake::take_added_response_headers();
    assert!(stamped.contains(&(CORRELATION_HEADER.to_string(), "req-42".to_string())));
    assert!(
        fake::take_local_response().is_none(),
        "the tagger never answers for the request"
    );

    // --- without an inbound request id: the literal "unset" -------
    test_reset();
    fake::set_request_headers(&[(":method", "GET"), (":path", "/v1/things")]);
    assert_eq!(proxy_on_request_headers(2, 2, 1), ACTION_CONTINUE);
    assert_eq!(proxy_on_response_headers(2, 1, 1), ACTION_CONTINUE);
    let stamped = fake::take_added_response_headers();
    assert!(stamped.contains(&(CORRELATION_HEADER.to_string(), "unset".to_string())));
}
