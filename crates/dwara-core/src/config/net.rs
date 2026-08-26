//! Minimal IP/CIDR support for trusted-proxy and IP-ACL matching
//! (DW-009/DW-020).
//!
//! The trusted-proxy matcher is part of the CONFIG CONTRACT — validation
//! (`snapshot::validate`) and every runtime consumer (the dataplane's
//! forwarded-header rule, authorization's IP ACLs) must agree on what a
//! well-formed `ip`/`ip/prefix` entry is, so the parser and the matcher
//! live here with the schema instead of in any one consumer. No new
//! dependency: `std::net` parsing plus a shift-compare.

use std::net::IpAddr;

/// Parse `ip`, `ip/prefix` into (network address, prefix length).
/// Returns None for anything that is not a well-formed IPv4/IPv6 address
/// or CIDR (including prefixes wider than the address family allows).
pub fn parse_ip_or_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        return Some((ip, bits));
    }
    let (addr, prefix) = s.split_once('/')?;
    let ip: IpAddr = addr.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = prefix.trim().parse().ok()?;
    if prefix > max {
        return None;
    }
    Some((ip, prefix))
}

/// Whether `ip` falls inside `net/prefix` (same-family only). Public so
/// authorization (DW-020) matches IP ACL entries with the exact
/// DW-009 trusted-proxy semantics.
pub fn ip_in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (a, b) = (u32::from(a), u32::from(b));
            prefix == 0 || ((a ^ b) >> (32 - prefix as u32)) == 0
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (a, b) = (u128::from(a), u128::from(b));
            prefix == 0 || ((a ^ b) >> (128 - prefix as u32)) == 0
        }
        _ => false,
    }
}

/// Whether `peer` falls inside any configured trusted-proxy entry.
/// Unparseable entries cannot occur in a validated config; they are
/// conservatively treated as non-matching here (validation rejects the
/// whole config before the dataplane ever sees it).
pub fn peer_is_trusted(trusted: &[String], peer: IpAddr) -> bool {
    trusted.iter().any(|entry| {
        parse_ip_or_cidr(entry).is_some_and(|(net, prefix)| ip_in_net(peer, net, prefix))
    })
}
