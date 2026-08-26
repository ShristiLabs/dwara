//! Fuzz the JWT pre-verification token parsing path (DW-025): everything
//! reachable WITHOUT any cryptographic validation — segment splitting
//! and base64 decoding of the token header, i.e.
//! `jsonwebtoken::decode_header`, the same entry the gateway's Bearer
//! path calls before any key lookup or signature check. Any input must
//! produce `Ok(_)` or `Err(_)`, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let token = String::from_utf8_lossy(data);
    let _ = std::hint::black_box(jsonwebtoken::decode_header(&token));
});
