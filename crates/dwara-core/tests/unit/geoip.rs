//! Unit tests for the GeoIP module (DW-050): reader lookups against a
//! runtime-GENERATED .mmdb fixture (mmdb-writer, dev-only — no binary
//! test data in the repo) and the geo-rule decision semantics through
//! `authz::evaluate_one`.

use std::net::{IpAddr, Ipv4Addr};

use mmdb_writer::ipnet::IpNet as MmdbNet;
use mmdb_writer::{Value, Writer};

use dwara_core::config::{Authz, GeoipRules};
use dwara_core::security::authz::{evaluate_one, AuthzContext, Decision};
use dwara_core::security::geoip::GeoipDb;

/// Build a fixture database: countries for 1.1.1.0/24 (US, with a
/// registered_country fallback case on 2.2.2.0/24 -> DE via
/// registered only), a blocked-land 3.3.3.0/24 (XX), and an ASN
/// network 9.9.9.0/24 (64512). Returns the written file's path.
fn write_fixture(dir: &std::path::Path, tag: &str, us: bool) -> std::path::PathBuf {
    let mut w = Writer::new("GeoLite2-Country-Test");
    let us_country = if us { "US" } else { "CA" };
    w.insert_value(
        "1.1.1.0/24".parse::<MmdbNet>().unwrap(),
        Value::map([(
            "country",
            Value::map([("iso_code", Value::from(us_country))]),
        )]),
    )
    .unwrap();
    w.insert_value(
        "2.2.2.0/24".parse::<MmdbNet>().unwrap(),
        Value::map([(
            "registered_country",
            Value::map([("iso_code", Value::from("DE"))]),
        )]),
    )
    .unwrap();
    w.insert_value(
        "3.3.3.0/24".parse::<MmdbNet>().unwrap(),
        Value::map([("country", Value::map([("iso_code", Value::from("XX"))]))]),
    )
    .unwrap();
    w.insert_value(
        "9.9.9.0/24".parse::<MmdbNet>().unwrap(),
        Value::map([
            ("country", Value::map([("iso_code", Value::from("US"))])),
            ("autonomous_system_number", Value::from(64_512_u32)),
        ]),
    )
    .unwrap();
    let path = dir.join(format!("geoip-{tag}.mmdb"));
    std::fs::write(&path, w.to_bytes().unwrap()).unwrap();
    path
}

fn ip(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
}

#[test]
fn reader_resolves_countries_asns_and_unknowns() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_fixture(dir.path(), "reader", true);
    let db = GeoipDb::open(path.to_str().unwrap()).unwrap();
    assert_eq!(db.country(ip("1.1.1.1")).as_deref(), Some("US"));
    // registered_country is the fallback when country is absent.
    assert_eq!(db.country(ip("2.2.2.2")).as_deref(), Some("DE"));
    assert_eq!(db.country(ip("3.3.3.3")).as_deref(), Some("XX"));
    assert_eq!(db.asn(ip("9.9.9.9")), Some(64_512));
    // Unknowns: not-in-DB and private addresses resolve to None.
    assert_eq!(db.country(ip("4.4.4.4")), None);
    assert_eq!(db.country(ip("127.0.0.1")), None);
    assert_eq!(db.asn(ip("1.1.1.1")), None);
    // Lowercase iso codes in the DB normalize to uppercase.
    // (fixture uses uppercase; normalization is exercised in the
    // decision tests via case-insensitive comparison instead)
    // A missing/unopenable file is a typed error.
    assert!(GeoipDb::open("/nonexistent/dwara-geo/none.mmdb").is_err());
}

fn ctx<'a>(db: Option<&'a GeoipDb>, effective: IpAddr) -> AuthzContext<'a> {
    AuthzContext {
        identity: None,
        consumer_groups: &[],
        peer_ip: ip("127.0.0.1"),
        effective_ip: effective,
        geoip: db,
    }
}

fn rules(
    allowed_countries: &[&str],
    denied_countries: &[&str],
    allowed_asns: &[u32],
    denied_asns: &[u32],
) -> Authz {
    Authz {
        geoip: Some(GeoipRules {
            allowed_countries: allowed_countries.iter().map(|s| s.to_string()).collect(),
            denied_countries: denied_countries.iter().map(|s| s.to_string()).collect(),
            allowed_asns: allowed_asns.to_vec(),
            denied_asns: denied_asns.to_vec(),
        }),
        allowed_consumers: vec![],
        denied_consumers: vec![],
        allowed_groups: vec![],
        denied_groups: vec![],
        required_scopes: vec![],
        required_claims: Default::default(),
        ip_acl: None,
        dry_run: false,
    }
}

fn denied(authz: &Authz, c: &AuthzContext<'_>) -> bool {
    matches!(evaluate_one(authz, c), Some(Decision::Deny { .. }))
}

#[test]
fn geo_decisions_follow_the_frozen_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_fixture(dir.path(), "decisions", true);
    let db = GeoipDb::open(path.to_str().unwrap()).unwrap();

    // Deny list: a known denied country rejects.
    let deny_xx = rules(&[], &["XX"], &[], &[]);
    assert!(denied(&deny_xx, &ctx(Some(&db), ip("3.3.3.3"))));
    // Unknown addresses pass a deny list (infrastructure is not
    // geolocatable; geo blocking does not fail closed on them).
    assert!(!denied(&deny_xx, &ctx(Some(&db), ip("4.4.4.4"))));
    assert!(!denied(&deny_xx, &ctx(Some(&db), ip("127.0.0.1"))));
    // No database at all: everything is unknown.
    assert!(!denied(&deny_xx, &ctx(None, ip("3.3.3.3"))));

    // Allow list: only known matches pass; unknown rejects.
    let allow_us = rules(&["US"], &[], &[], &[]);
    assert!(!denied(&allow_us, &ctx(Some(&db), ip("1.1.1.1"))));
    assert!(denied(&allow_us, &ctx(Some(&db), ip("3.3.3.3"))));
    assert!(denied(&allow_us, &ctx(Some(&db), ip("4.4.4.4"))));
    // Case-insensitive country comparison (config lowercase).
    let allow_lower = rules(&["us"], &[], &[], &[]);
    assert!(!denied(&allow_lower, &ctx(Some(&db), ip("1.1.1.1"))));

    // ASN rules: deny a specific network; unknown ASN passes a deny
    // list and rejects an allow list.
    let deny_asn = rules(&[], &[], &[], &[64_512]);
    assert!(denied(&deny_asn, &ctx(Some(&db), ip("9.9.9.9"))));
    assert!(!denied(&deny_asn, &ctx(Some(&db), ip("1.1.1.1"))));
    let allow_asn = rules(&[], &[], &[64_512], &[]);
    assert!(!denied(&allow_asn, &ctx(Some(&db), ip("9.9.9.9"))));
    assert!(denied(&allow_asn, &ctx(Some(&db), ip("1.1.1.1"))));

    // A geoip-only block ADMITS anonymous traffic (the ip_acl-only
    // shape generalized): no identity rules, request allowed.
    let allow_us = rules(&["US"], &[], &[], &[]);
    let c = ctx(Some(&db), ip("1.1.1.1"));
    assert_eq!(
        evaluate_one(&allow_us, &c),
        Some(Decision::Allow),
        "geo-only authorization permits an allowed country anonymously"
    );
}
