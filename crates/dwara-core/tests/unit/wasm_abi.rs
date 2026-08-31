//! Unit tests for `wasm::abi` (relocated from src).

#![cfg(feature = "wasm")]

use dwara_core::wasm::abi::{deserialize_header_map, serialize_header_map};

#[test]
fn header_map_round_trip() {
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        (":path".to_string(), "/api/v1".to_string()),
        ("x-custom".to_string(), "value with spaces".to_string()),
    ];
    let encoded = serialize_header_map(&headers);
    let decoded = deserialize_header_map(&encoded).unwrap();
    assert_eq!(decoded, headers);
}

#[test]
fn empty_header_map_serializes_to_empty() {
    let encoded = serialize_header_map(&[]);
    assert!(encoded.is_empty());
    let decoded = deserialize_header_map(&encoded).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn truncated_header_map_returns_none() {
    let headers = vec![("key".to_string(), "value".to_string())];
    let mut encoded = serialize_header_map(&headers);
    encoded.truncate(encoded.len() - 1);
    assert!(deserialize_header_map(&encoded).is_none());
}
