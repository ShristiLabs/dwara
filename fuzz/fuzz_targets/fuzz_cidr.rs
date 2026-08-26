//! Fuzz the trusted-proxy CIDR machinery (DW-025):
//! `parse_ip_or_cidr` over arbitrary strings, plus `ip_in_net` with
//! network/address pairs derived from the input (and the parsed form
//! when it succeeds) to cover the prefix-match arithmetic.

#![no_main]

use dwara_core::config::net::{ip_in_net, parse_ip_or_cidr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let parsed = parse_ip_or_cidr(&raw);
    let _ = std::hint::black_box(&parsed);

    // Cover the containment check with both the parsed network (if any)
    // and fixed bounds (prefix lengths 0..=128 exercised via the input).
    let probe = std::net::IpAddr::from([127, 0, 0, 1]);
    if let Some((net, prefix)) = parsed {
        let _ = std::hint::black_box(ip_in_net(probe, net, prefix));
    }
    // ip_in_net's contract (enforced by parse_ip_or_cidr + validation)
    // is prefix <= family width; derive a contract-valid prefix here.
    let max = if probe.is_ipv4() { 32 } else { 128 };
    let prefix = data.first().copied().unwrap_or(0) % (max + 1);
    let _ = std::hint::black_box(ip_in_net(probe, probe, prefix));
});
