//! Unit tests for the DW-039 protocol polish: the WebSocket origin
//! gate and upgrade-token detection, the RFC 6455 frame-boundary
//! scanner, and the gRPC request detection + `grpc-timeout` grammar.
//! The end-to-end pins (grpc trailers through the gateway, deadline
//! enforcement against a hanging upstream, origin denial, abusive-flood
//! policing) live in `tests/grpc_websocket.rs`.

use dwara_core::config::RouteWebsocket;

// --- upgrade token detection ----------------------------------------------

fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
    let mut h = hyper::HeaderMap::new();
    for (k, v) in pairs {
        h.insert(
            hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    h
}

#[test]
fn websocket_upgrade_tokens_match_case_insensitively_in_lists() {
    assert!(dwara_core::dataplane::websocket::offers_websocket(
        &headers(&[("upgrade", "websocket")])
    ));
    assert!(dwara_core::dataplane::websocket::offers_websocket(
        &headers(&[("upgrade", "WebSocket")])
    ));
    assert!(dwara_core::dataplane::websocket::offers_websocket(
        &headers(&[("upgrade", "foo, websocket")])
    ));
    // Other upgrades are not WebSocket.
    assert!(!dwara_core::dataplane::websocket::offers_websocket(
        &headers(&[("upgrade", "h2c")])
    ));
    // A substring is not a token.
    assert!(!dwara_core::dataplane::websocket::offers_websocket(
        &headers(&[("upgrade", "websocketish")])
    ));
}

// --- the origin gate ---------------------------------------------------------

fn ws_cfg(origins: &[&str]) -> RouteWebsocket {
    RouteWebsocket {
        origins: origins.iter().map(|s| s.to_string()).collect(),
        max_frames_per_sec: None,
    }
}

#[test]
fn an_empty_allowlist_is_open_and_a_nonempty_one_is_exact() {
    use dwara_core::dataplane::websocket::{handshake_verdict, Handshake};
    let open = ws_cfg(&[]);
    assert_eq!(
        handshake_verdict(&headers(&[("origin", "https://anywhere.example")]), &open),
        Handshake::Allowed,
        "no allowlist: the transparent default"
    );
    assert_eq!(
        handshake_verdict(&headers(&[]), &open),
        Handshake::Allowed,
        "no allowlist: a missing Origin is fine"
    );

    let list = ws_cfg(&["https://app.example.com", "null"]);
    assert_eq!(
        handshake_verdict(&headers(&[("origin", "https://app.example.com")]), &list),
        Handshake::Allowed
    );
    assert_eq!(
        handshake_verdict(&headers(&[("origin", "null")]), &list),
        Handshake::Allowed,
        "the sandboxed-document origin is a literal match"
    );
    assert_eq!(
        handshake_verdict(&headers(&[("origin", "https://evil.example")]), &list),
        Handshake::OriginDenied
    );
    // Scheme matters (exact string comparison).
    assert_eq!(
        handshake_verdict(&headers(&[("origin", "http://app.example.com")]), &list),
        Handshake::OriginDenied
    );
    // Fail closed: browsers always send Origin; a missing one is not
    // named by the allowlist.
    assert_eq!(
        handshake_verdict(&headers(&[]), &list),
        Handshake::OriginDenied
    );
}

// --- the frame scanner -------------------------------------------------------

/// A masked client frame (RFC 6455 client-to-server framing): FIN +
/// opcode, mask bit + length, 4 mask bytes, masked payload.
fn masked_frame(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
    let mut b0 = opcode;
    if fin {
        b0 |= 0x80;
    }
    let mut frame = vec![b0];
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    match payload.len() {
        0..=125 => frame.push(0x80 | payload.len() as u8),
        126..=65_535 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

use dwara_core::dataplane::websocket::count_data_frames;

#[test]
fn the_scanner_counts_data_frames_across_all_length_classes() {
    let text = masked_frame(0x1, b"hello", true);
    let binary = masked_frame(0x2, &[0u8; 200], true); // 16-bit length
    let big = masked_frame(0x2, &[0u8; 70_000], true); // 64-bit length
    let empty = masked_frame(0x1, b"", true);
    let all = [text, binary, big, empty].concat();
    assert_eq!(count_data_frames(&all), 4);
}

#[test]
fn control_frames_are_free() {
    let ping = masked_frame(0x9, b"hb", true);
    let pong = masked_frame(0xA, b"hb", true);
    let close = masked_frame(0x8, &[0x03, 0xe8], true);
    let text = masked_frame(0x1, b"x", true);
    let all = [ping, pong, close, text].concat();
    assert_eq!(count_data_frames(&all), 1, "only the data frame counts");
}

#[test]
fn the_scanner_spans_arbitrary_chunk_boundaries() {
    use dwara_core::dataplane::websocket::FrameCounter;
    let frames = [
        masked_frame(0x1, b"one", true),
        masked_frame(0x2, &[0u8; 300], true),
        masked_frame(0x1, b"three", true),
    ]
    .concat();
    // One counter fed byte-by-byte: the boundaries must not matter.
    let mut c = FrameCounter::new();
    for b in &frames {
        c.feed(std::slice::from_ref(b));
    }
    assert_eq!(c.data_frames(), 3);
    // And in awkward two-byte chunks.
    let mut c = FrameCounter::new();
    for pair in frames.chunks(2) {
        c.feed(pair);
    }
    assert_eq!(c.data_frames(), 3);
}

#[test]
fn fragmented_messages_count_per_frame() {
    let first = masked_frame(0x1, b"part-one", false); // FIN=0
    let second = masked_frame(0x0, b"part-two", false); // continuation
    let last = masked_frame(0x0, b"part-three", true); // FIN=1
    assert_eq!(count_data_frames(&[first, second, last].concat()), 3);
}

// --- gRPC detection and the timeout grammar ----------------------------------

#[test]
fn grpc_detection_requires_h2_and_the_grpc_content_type_family() {
    let grpc = headers(&[("content-type", "application/grpc")]);
    let grpc_proto = headers(&[("content-type", "application/grpc+proto")]);
    let json = headers(&[("content-type", "application/json")]);
    assert!(dwara_core::proxy::grpc_request(
        &grpc,
        hyper::Version::HTTP_2
    ));
    assert!(dwara_core::proxy::grpc_request(
        &grpc_proto,
        hyper::Version::HTTP_2
    ));
    assert!(!dwara_core::proxy::grpc_request(
        &grpc,
        hyper::Version::HTTP_11
    ));
    assert!(!dwara_core::proxy::grpc_request(
        &json,
        hyper::Version::HTTP_2
    ));
}

#[test]
fn grpc_timeout_parses_every_unit_and_rejects_garbage() {
    use dwara_core::proxy::parse_grpc_timeout;
    use std::time::Duration;
    let d = |s: &str| parse_grpc_timeout(s);
    assert_eq!(d("1H"), Some(Duration::from_secs(3600)));
    assert_eq!(d("2M"), Some(Duration::from_secs(120)));
    assert_eq!(d("3S"), Some(Duration::from_secs(3)));
    assert_eq!(d("6m"), Some(Duration::from_millis(6)));
    assert_eq!(d("1500u"), Some(Duration::from_micros(1500)));
    assert_eq!(d("100n"), Some(Duration::from_nanos(100)));
    assert_eq!(d("0S"), Some(Duration::ZERO));
    // The spec's maximum: 8 digits.
    assert_eq!(d("99999999n"), Some(Duration::from_nanos(99_999_999)));
    // Overflow saturates at one day (still an enforceable deadline).
    assert_eq!(d("99999999H"), Some(Duration::from_secs(86_400)));
    // Garbage: absent or unknown unit, empty digits, too many digits,
    // non-digits, case-exact units only.
    assert_eq!(d("6"), None);
    assert_eq!(d("6x"), None);
    assert_eq!(d("6h"), None, "units are case-exact (S not s)");
    assert_eq!(d(""), None);
    assert_eq!(d("123456789S"), None);
    assert_eq!(d("12a4S"), None);
    assert_eq!(d("-6S"), None);
}

// --- interleaved control frames mid-fragmentation ------------------------------

#[test]
fn control_frames_interleaved_mid_fragmentation_are_free_and_do_not_desync() {
    // A fragmented text message with pings/pongs interleaved between
    // the fragments: the scanner counts the three DATA frames, skips
    // the control frames, and stays in sync across the whole stream.
    let fragment1 = masked_frame(0x1, b"part-one", false); // FIN=0 text
    let ping = masked_frame(0x9, b"hb", true);
    let fragment2 = masked_frame(0x0, b"part-two", false); // continuation
    let pong = masked_frame(0xA, b"hb", true);
    let fragment3 = masked_frame(0x0, b"end", true); // FIN=1
    let stream = [fragment1, ping, fragment2, pong, fragment3].concat();
    assert_eq!(count_data_frames(&stream), 3);
    // And a following frame is still counted correctly (no desync).
    let after = masked_frame(0x1, b"next-message", true);
    assert_eq!(count_data_frames(&[stream, after].concat()), 4);
}

// --- the config validation matrix -----------------------------------------------

fn validate_ws_yaml(ws_block: &str) -> Vec<String> {
    let yaml = format!(
        "routes:\n\
         - name: ws\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /chat\n{ws_block}\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: 9999\n"
    );
    let gateway = dwara_core::config::parse_gateway(&yaml).unwrap();
    dwara_core::snapshot::validate(&gateway)
        .into_iter()
        .map(|i| format!("{i}"))
        .collect()
}

#[test]
fn a_well_formed_websocket_block_validates_and_the_knobs_are_independent() {
    // Both knobs.
    assert!(validate_ws_yaml(
        "  websocket:\n    origins: [https://a.example]\n    max_frames_per_sec: 100\n"
    )
    .is_empty());
    // Rate only (policing without an allowlist).
    assert!(validate_ws_yaml("  websocket:\n    max_frames_per_sec: 100\n").is_empty());
    // Origins only.
    assert!(validate_ws_yaml("  websocket:\n    origins: [https://a.example]\n").is_empty());
}

#[test]
fn websocket_validation_rejects_unusable_origins_and_out_of_bounds_rates() {
    let issues = validate_ws_yaml("  websocket:\n    origins: ['', 'https://ok.example']\n");
    let joined = issues.join("\n");
    assert!(joined.contains("origin is empty"), "{joined}");

    let issues = validate_ws_yaml(&format!(
        "  websocket:\n    origins: ['{}']\n",
        "x".repeat(257)
    ));
    let joined = issues.join("\n");
    assert!(
        joined.contains("printable ASCII at most 256 bytes"),
        "{joined}"
    );

    let issues = validate_ws_yaml("  websocket:\n    max_frames_per_sec: 0\n");
    let joined = issues.join("\n");
    assert!(joined.contains("max_frames_per_sec must be in"), "{joined}");

    let issues = validate_ws_yaml(&format!(
        "  websocket:\n    max_frames_per_sec: {}\n",
        dwara_core::config::limits::MAX_WEBSOCKET_FRAMES_PER_SEC + 1
    ));
    let joined = issues.join("\n");
    assert!(joined.contains("max_frames_per_sec must be in"), "{joined}");
}
