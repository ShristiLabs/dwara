//! GeoIP lookup for geo-based ACL predicates (DW-050, feature analysis
//! 5-Security "Geo-blocking").
//!
//! A single MaxMind-format database file (GeoLite2-Country, GeoLite2-
//! ASN, or a combined DB) is opened once and held behind an
//! [`arc_swap::ArcSwapOption`] on the dataplane; authorization rules
//! (`authorization.geoip`) consult it with the EFFECTIVE client IP
//! (the same XFF-resolved address `ip_acl` uses — behind a trusted
//! proxy or PROXY-protocol LB, geo decisions follow the real client,
//! not the hop).
//!
//! Semantics frozen with the design:
//!
//! - Country is the ISO 3166-1 alpha-2 code, UPPERCASE, preferring
//!   `country` over `registered_country` (the MaxMind convention:
//!   the more specific of the two).
//! - ASN is `autonomous_system_number`.
//! - An address the database does not resolve (private/reserved
//!   ranges, not-in-DB, or no database loaded) yields `None` —
//!   "unknown" — and matches NEITHER allow nor deny lists in the
//!   authorization rule: a deny-list keeps passing unknowns (geo
//!   blocking must not fail closed on unlocatable addresses — they
//!   are usually infrastructure), an allow-list keeps rejecting them
//!   (an allow-list that admitted unknowns would filter nothing).
//! - The database HOT-RELOADS: the watcher in dwara-bin polls the
//!   file's mtime and swaps the reader; in-flight lookups keep the
//!   reader they loaded (an `Arc` swap — no torn state).

use std::net::IpAddr;

use serde::Deserialize;

/// Why a GeoIP database could not be opened.
#[derive(Debug)]
pub struct GeoipError(String);

impl std::fmt::Display for GeoipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "geoip database: {}", self.0)
    }
}

impl std::error::Error for GeoipError {}

/// The `country`/`registered_country` subtree shape (maxminddb
/// deserializes ONLY the fields the struct names — extra tree data is
/// ignored, so one struct serves country and combined databases).
#[derive(Deserialize)]
struct CountryNode {
    #[serde(rename = "iso_code")]
    iso_code: Option<String>,
}

#[derive(Deserialize)]
struct CountryTree {
    country: Option<CountryNode>,
    registered_country: Option<CountryNode>,
}

/// The `autonomous_system_number` subtree shape (GeoLite2-ASN /
/// combined databases).
#[derive(Deserialize)]
struct AsnTree {
    #[serde(rename = "autonomous_system_number")]
    asn: Option<u32>,
}

/// An opened MaxMind database.
pub struct GeoipDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoipDb {
    /// Open (and memory-map) the database at `path`. The file is read
    /// eagerly into the reader's buffer, so a later atomic replace of
    /// the path never tears an in-flight lookup.
    pub fn open(path: &str) -> Result<Self, GeoipError> {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| GeoipError(format!("open '{path}' failed: {e}")))?;
        Ok(GeoipDb { reader })
    }

    /// The ISO 3166-1 alpha-2 country code for `ip` (uppercase), if
    /// the database resolves one. `country` is preferred over
    /// `registered_country`.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let found = self.reader.lookup(ip).ok()?;
        let tree: Option<CountryTree> = found.decode().ok().flatten();
        tree.and_then(|t| {
            t.country
                .or(t.registered_country)
                .and_then(|c| c.iso_code)
                .map(|s| s.to_ascii_uppercase())
        })
    }

    /// The autonomous system number for `ip`, if the database
    /// resolves one.
    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let found = self.reader.lookup(ip).ok()?;
        let tree: Option<AsnTree> = found.decode().ok().flatten();
        tree.and_then(|t| t.asn)
    }
}

impl std::fmt::Debug for GeoipDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoipDb").finish_non_exhaustive()
    }
}
