//! Fuzz the TLS ClientHello SNI parser (DW-025):
//! `dwara_core::tls::sni_from_client_hello` over arbitrary bytes — the
//! exact bytes a hostile client can put on the wire before the TLS
//! handshake is validated. Structural shortcoming must yield `None`,
//! never a panic.

#![no_main]

use dwara_core::tls::sni_from_client_hello;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = std::hint::black_box(sni_from_client_hello(data));
});
