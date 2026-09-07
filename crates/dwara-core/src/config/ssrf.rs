//! SSRF egress filter (SEC-13).
//!
//! A configurable egress filter that rejects outbound connections to
//! private/loopback/link-local/metadata endpoints. Applied to webhook
//! deliveries and OPA callouts — any outbound dial the gateway makes
//! on behalf of operator configuration that could be redirected to an
//! internal address.
//!
//! # Design
//!
//! The filter is OPT-IN with an ALLOWLIST: when enabled, every resolved
//! IP is checked against the deny set (RFC 1918, loopback, link-local,
//! IPv6 ULA, cloud metadata endpoints). An optional allowlist exempts
//! specific CIDRs (e.g. an internal alerting listener on 10/8).
//!
//! DNS REBINDING is mitigated by checking the resolved IP at connect
//! time, not at config compile time — the webhook deliverer resolves
//! and checks immediately before `TcpStream::connect`.
//!
//! The filter lives in the `config` domain because it uses
//! [`crate::config::net`] IP/CIDR utilities and is a config-level
//! policy (the deny set is config-bounded, not request-bounded).

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::net::{ip_in_net, parse_ip_or_cidr};

/// The default deny set: CIDR ranges that are always rejected when the
/// filter is enabled (unless the allowlist exempts them). Covers
/// RFC 1918 private space, loopback, link-local, IPv6 ULA, the AWS/GCP/
/// Azure cloud metadata endpoints, and the IPv6 loopback.
const DEFAULT_DENY_CIDRS: &[&str] = &[
    // IPv4 loopback
    "127.0.0.0/8",
    // IPv4 private (RFC 1918)
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    // IPv4 link-local
    "169.254.0.0/16",
    // IPv4 CGNAT (RFC 6598)
    "100.64.0.0/10",
    // IPv4 benchmarking (RFC 2544) — sometimes routed
    "198.18.0.0/15",
    // IPv4 multicast/reserved
    "224.0.0.0/4",
    "240.0.0.0/4",
    // IPv4 broadcast
    "255.255.255.255/32",
    // IPv6 loopback
    "::1/128",
    // IPv6 link-local
    "fe80::/10",
    // IPv6 unique local
    "fc00::/7",
    // IPv6 multicast
    "ff00::/8",
    // IPv6 unspecified
    "::/128",
    // Cloud metadata endpoints (AWS/GCP/Azure — 169.254.169.254 is
    // already in the link-local range above, but we list it explicitly
    // for documentation; the GCP metadata endpoint is
    // metadata.google.internal — DNS-based, caught at resolve time).
];

/// SSRF egress filter configuration. When `enabled` is true, outbound
/// connections from webhook deliveries and OPA callouts are checked
/// against the deny set; an IP in the deny set that is NOT in the
/// allowlist is rejected. When `enabled` is false (the default), no
/// filtering is applied (the v1 behavior — operator config is trusted).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SsrfFilterConfig {
    /// Whether the SSRF egress filter is enabled. Default false: the
    /// v1 posture trusts operator-configured endpoints (an internal
    /// alerting listener on 127.0.0.1 is a normal shape). Enable when
    /// the gateway processes externally-sourced URLs (e.g. webhook
    /// targets from a control-plane API).
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    /// Additional CIDR ranges to EXEMPT from the deny set (allowlist).
    /// Entries are IP or CIDR strings (e.g. `10.0.0.0/8` to allow all
    /// of 10/8). An IP that matches any allowlist entry is accepted
    /// even when it falls inside the default deny set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowlist: Vec<String>,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// A compiled SSRF filter: the parsed deny set and allowlist, ready for
/// O(1) checks at connect time. Built from [`SsrfFilterConfig`] at
/// config compile time; the deny set is the default plus any operator
/// additions (future), the allowlist is the parsed config entries.
#[derive(Debug, Clone, Default)]
pub struct SsrfFilter {
    /// The parsed deny CIDRs: (network, prefix) pairs.
    deny: Vec<(IpAddr, u8)>,
    /// The parsed allowlist CIDRs: (network, prefix) pairs.
    allow: Vec<(IpAddr, u8)>,
    /// Whether the filter is enabled.
    enabled: bool,
}

impl SsrfFilter {
    /// Build a filter from config. Invalid deny/allowlist entries are
    /// silently skipped (validation rejects them at config compile
    /// time; this is a defense-in-depth backstop).
    pub fn from_config(cfg: &SsrfFilterConfig) -> Self {
        if !cfg.enabled {
            return Self::disabled();
        }
        let deny: Vec<(IpAddr, u8)> = DEFAULT_DENY_CIDRS
            .iter()
            .filter_map(|s| parse_ip_or_cidr(s))
            .collect();
        let allow: Vec<(IpAddr, u8)> = cfg
            .allowlist
            .iter()
            .filter_map(|s| parse_ip_or_cidr(s))
            .collect();
        Self {
            deny,
            allow,
            enabled: true,
        }
    }

    /// A disabled filter (accepts everything).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Whether the filter is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check whether `ip` is allowed. Returns `Ok(())` when the IP is
    /// accepted, `Err(reason)` when it is rejected. A disabled filter
    /// always returns `Ok(())`.
    pub fn check(&self, ip: IpAddr) -> Result<(), &'static str> {
        if !self.enabled {
            return Ok(());
        }
        // Allowlist takes precedence: an explicitly-allowed IP is
        // accepted even when it falls inside the deny set.
        if self
            .allow
            .iter()
            .any(|(net, prefix)| ip_in_net(ip, *net, *prefix))
        {
            return Ok(());
        }
        if self
            .deny
            .iter()
            .any(|(net, prefix)| ip_in_net(ip, *net, *prefix))
        {
            return Err(
                "SSRF egress filter: target IP is in a denied range (private/loopback/\
                        link-local/metadata)",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_filter_accepts_all() {
        let f = SsrfFilter::disabled();
        assert!(f.check("127.0.0.1".parse().unwrap()).is_ok());
        assert!(f.check("10.0.0.1".parse().unwrap()).is_ok());
        assert!(f.check("8.8.8.8".parse().unwrap()).is_ok());
    }

    #[test]
    fn enabled_filter_rejects_private() {
        let cfg = SsrfFilterConfig {
            enabled: true,
            allowlist: vec![],
        };
        let f = SsrfFilter::from_config(&cfg);
        assert!(f.check("127.0.0.1".parse().unwrap()).is_err());
        assert!(f.check("10.0.0.1".parse().unwrap()).is_err());
        assert!(f.check("192.168.1.1".parse().unwrap()).is_err());
        assert!(f.check("169.254.169.254".parse().unwrap()).is_err());
        assert!(f.check("::1".parse().unwrap()).is_err());
    }

    #[test]
    fn enabled_filter_accepts_public() {
        let cfg = SsrfFilterConfig {
            enabled: true,
            allowlist: vec![],
        };
        let f = SsrfFilter::from_config(&cfg);
        assert!(f.check("8.8.8.8".parse().unwrap()).is_ok());
        assert!(f.check("1.1.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn allowlist_exempts_private() {
        let cfg = SsrfFilterConfig {
            enabled: true,
            allowlist: vec!["10.0.0.0/8".to_string()],
        };
        let f = SsrfFilter::from_config(&cfg);
        assert!(f.check("10.0.0.1".parse().unwrap()).is_ok());
        // Non-allowlisted private is still rejected.
        assert!(f.check("127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn ipv6_link_local_rejected() {
        let cfg = SsrfFilterConfig {
            enabled: true,
            allowlist: vec![],
        };
        let f = SsrfFilter::from_config(&cfg);
        assert!(f.check("fe80::1".parse().unwrap()).is_err());
        assert!(f.check("fc00::1".parse().unwrap()).is_err());
    }
}
