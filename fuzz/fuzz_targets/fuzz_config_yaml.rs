//! Fuzz the YAML gateway configuration parser (DW-025): `parse_gateway`
//! over arbitrary bytes. Only UTF-8 inputs are valid YAML; everything
//! else exercises the error path. No panic is allowed on any input —
//! malformed configs must produce `Err`, never a crash.

#![no_main]

use dwara_core::config::parse_gateway;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = std::hint::black_box(parse_gateway(text));
    }
});
