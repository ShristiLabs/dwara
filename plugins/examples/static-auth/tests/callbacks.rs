//! Callback-level unit tests: drive the real `proxy_on_*` exports.
//!
//! `src/abi.rs` compiles a fake host on non-wasm targets, so on the
//! development machine `cargo test` can call the plugin's actual
//! proxy-wasm entrypoints and observe exactly what the plugin would
//! have done to the gateway (local response, added headers, logged
//! lines). This is the second half of level 1 in the plugin testing
//! guide: no gateway, no wasm, but the real callback wiring.
//!
//! The scenarios run sequentially in one test: the per-instance root
//! state is a process-wide static (mirroring the wasm module's
//! linear-memory static), so scenarios must not interleave.

use static_auth::{
    abi::{
        fake,
        fake::LocalResponse,
        {ACTION_CONTINUE, ACTION_END_STREAM},
    },
    proxy_on_configure, proxy_on_request_headers, test_reset,
};

const CONFIG: &[u8] = br#"{"header":"authorization","scheme":"Bearer","token":"s3cr3t"}"#;

fn configure() {
    fake::set_config(CONFIG);
    assert_eq!(proxy_on_configure(1, CONFIG.len() as i32), 1);
}

fn request(authorization: Option<&str>) -> i32 {
    let mut headers: Vec<(&str, &str)> = vec![(":method", "GET"), (":path", "/v1/things")];
    if let Some(value) = authorization {
        headers.push(("authorization", value));
    }
    fake::set_request_headers(&headers);
    proxy_on_request_headers(2, headers.len() as i32, 1)
}

fn header<'a>(response: &'a LocalResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[test]
fn callback_scenarios() {
    // --- configure: a good config activates the plugin -------------
    test_reset();
    configure();

    // --- allow: the correct bearer token continues the request -----
    assert_eq!(request(Some("Bearer s3cr3t")), ACTION_CONTINUE);
    assert!(
        fake::take_local_response().is_none(),
        "allowed request must not answer locally"
    );

    // --- deny (missing): 401 with a WWW-Authenticate challenge -----
    assert_eq!(request(None), ACTION_END_STREAM);
    let response = fake::take_local_response().expect("missing credential must 401");
    assert_eq!(response.status, 401);
    assert_eq!(
        header(&response, "WWW-Authenticate"),
        Some("Bearer realm=\"dwara\"")
    );
    let body = String::from_utf8(response.body).expect("body is UTF-8");
    assert!(body.contains("missing credential"), "body: {body}");
    // The upstream was never dialed: a local response IS the answer.
    assert_eq!(fake::take_local_response(), None);

    // --- deny (wrong token): same challenge, invalid reason --------
    assert_eq!(request(Some("Bearer wrong")), ACTION_END_STREAM);
    let response = fake::take_local_response().expect("wrong token must 401");
    assert_eq!(response.status, 401);
    let body = String::from_utf8(response.body).expect("body is UTF-8");
    assert!(body.contains("invalid credential"), "body: {body}");

    // --- deny (wrong scheme): Basic does not satisfy Bearer --------
    assert_eq!(request(Some("Basic c2VjcmV0")), ACTION_END_STREAM);
    assert!(fake::take_local_response().is_some());

    // --- fail closed: a malformed config refuses to activate -------
    test_reset();
    fake::set_config(b"not json at all");
    assert_eq!(
        proxy_on_configure(1, 14),
        0,
        "a plugin that cannot parse its config must not run"
    );
    // Every request on the route now fails closed at the gateway
    // (500 plugin_unavailable); nothing the plugin can do about it.

    // --- deny (unconfigured): if configure never ran, deny ---------
    // Directly exercising the defensive branch: fresh state, no
    // configure call.
    test_reset();
    assert_eq!(request(None), ACTION_END_STREAM);
    let response = fake::take_local_response().expect("unconfigured plugin denies");
    assert_eq!(response.status, 401);
}
