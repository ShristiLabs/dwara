//! Unit tests for the API-versioning aids (DW-048): the HTTP-date and
//! media-type grammar (`config::versioning`), the Accept matcher
//! (`dataplane::versioning::accept_matches`), and the compiled
//! deprecation header values (`config::CompiledDeprecation`).

use dwara_core::config::versioning::{normalize_media_type, parse_http_date};
use dwara_core::config::{CompiledDeprecation, Deprecation};
use dwara_core::dataplane::versioning::{accept_matches, decorate};
use hyper::header::{HeaderMap, HeaderValue, ACCEPT};

// --- HTTP-date (IMF-fixdate) -------------------------------------------

#[test]
fn http_date_parses_the_rfc_example() {
    // The RFC 9110 example date; 784111777 is its documented Unix time.
    let d = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
    assert_eq!(d.unix_seconds(), 784_111_777);
}

#[test]
fn http_date_parses_epoch_boundary_and_far_future() {
    assert_eq!(
        parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT")
            .unwrap()
            .unix_seconds(),
        0
    );
    assert_eq!(
        parse_http_date("Tue, 01 Jan 2030 00:00:00 GMT")
            .unwrap()
            .unix_seconds(),
        1_893_456_000
    );
    // 4-digit years through 9999 parse (the format's whole range).
    assert!(parse_http_date("Fri, 31 Dec 9999 23:59:59 GMT").is_some());
}

#[test]
fn http_date_rejects_wrong_day_name() {
    // 1994-11-06 was a Sunday; any other day-name is a typo'd date.
    assert!(parse_http_date("Mon, 06 Nov 1994 08:49:37 GMT").is_none());
}

#[test]
fn http_date_rejects_obsolete_forms_and_non_gmt() {
    // RFC 850 date (dashes, 2-digit year, long day name).
    assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_none());
    // asctime date.
    assert!(parse_http_date("Sun Nov  6 08:49:37 1994").is_none());
    // IMF-fixdate shape but a non-GMT zone (the format allows only GMT).
    assert!(parse_http_date("Sun, 06 Nov 1994 08:49:37 PDT").is_none());
}

#[test]
fn http_date_enforces_field_shapes() {
    for bad in [
        "",                               // empty
        "Sun, 6 Nov 1994 08:49:37 GMT",   // 1-digit day
        "Sun, 06 Nov 94 08:49:37 GMT",    // 2-digit year
        "Sun, 06 Nov 1994 8:49:37 GMT",   // 1-digit hour
        "Sun, 06 Nov 1994 08:49 GMT",     // no seconds
        "Sun, 06 Nov 1994 24:00:00 GMT",  // hour 24
        "Sun, 06 Nov 1994 08:60:37 GMT",  // minute 60
        "Sun, 06 Nov 1994 08:49:60 GMT",  // second 60
        "Sun, 06 Nov 1994 08:49:37",      // no zone
        "Sun, 06 Xyz 1994 08:49:37 GMT",  // unknown month
        "Sun,  06 Nov 1994 08:49:37 GMT", // double space
        " Sun, 06 Nov 1994 08:49:37 GMT", // leading space
        "Sun, 06 Nov 1994 08:49:37 GMT ", // trailing space
        "Sun, 32 Nov 1994 08:49:37 GMT",  // day 32
        "Sun, 00 Nov 1994 08:49:37 GMT",  // day 0
    ] {
        assert!(parse_http_date(bad).is_none(), "must reject {bad:?}");
    }
}

#[test]
fn http_date_enforces_month_lengths_and_leap_years() {
    // 1994 is not a leap year: Feb 29 does not exist (Feb 28 does).
    assert!(parse_http_date("Mon, 28 Feb 1994 00:00:00 GMT").is_some());
    assert!(parse_http_date("Tue, 01 Mar 1994 00:00:00 GMT").is_some());
    assert!(parse_http_date("Mon, 29 Feb 1994 00:00:00 GMT").is_none());
    // 2000 IS a leap year (quadricentennial); 1900 is not (century).
    assert!(parse_http_date("Tue, 29 Feb 2000 00:00:00 GMT").is_some());
    assert!(parse_http_date("Thu, 29 Feb 1900 00:00:00 GMT").is_none());
    // April 31st never exists.
    assert!(parse_http_date("Sun, 30 Apr 2000 00:00:00 GMT").is_some());
    assert!(parse_http_date("Mon, 31 Apr 2000 00:00:00 GMT").is_none());
}

#[test]
fn http_date_roundtrips_across_a_leap_day() {
    // 2024-02-29 -> 2024-03-01 is one day apart; the parser must agree
    // with real calendar arithmetic around the insertion.
    let a = parse_http_date("Thu, 29 Feb 2024 12:00:00 GMT")
        .unwrap()
        .unix_seconds();
    let b = parse_http_date("Fri, 01 Mar 2024 12:00:00 GMT")
        .unwrap()
        .unix_seconds();
    assert_eq!(b - a, 86_400);
}

// --- Media types --------------------------------------------------------

#[test]
fn media_type_normalizes_case_and_padding() {
    assert_eq!(
        normalize_media_type("  Application/VND.Acme.V2+JSON ").unwrap(),
        "application/vnd.acme.v2+json"
    );
    assert_eq!(normalize_media_type("text/plain").unwrap(), "text/plain");
    assert_eq!(normalize_media_type("a/b").unwrap(), "a/b");
}

#[test]
fn media_type_rejects_wildcards() {
    // A wildcard can never match a versioned route (the client must NAME
    // the version), so configuring one is always an authoring error.
    assert!(normalize_media_type("*/*").is_none());
    assert!(normalize_media_type("application/*").is_none());
    assert!(normalize_media_type("*/json").is_none());
}

#[test]
fn media_type_rejects_parameters_and_malformed_tokens() {
    for bad in [
        "",
        "   ",
        "application",
        "/json",
        "application/",
        "/",
        "application/json; q=1",
        "application/json;charset=utf-8",
        "appli cation/json",
        "application//json",
        "application/json/x",
    ] {
        assert!(normalize_media_type(bad).is_none(), "must reject {bad:?}");
    }
}

#[test]
fn http_date_rejects_non_gmt_zone_spellings() {
    // IMF-fixdate allows only the literal `GMT`. RFC 9110 obliges
    // recipients to also parse the legacy zone names and numeric
    // offsets, but this grammar parses operator-authored config that is
    // echoed verbatim into Sunset, so only the canonical form passes.
    for zone in ["UT", "UTC", "Z", "+0000", "-0000", "gmt"] {
        let date = format!("Sun, 06 Nov 1994 08:49:37 {zone}");
        assert!(parse_http_date(&date).is_none(), "must reject {date:?}");
    }
}

#[test]
fn media_type_accepts_every_tchar_class() {
    // RFC 9110 tchar set in both halves.
    assert!(normalize_media_type("a!#$%&'*+-.^_`|~z/0!#$%&'*+-.^_`|~9").is_some());
}

// --- Accept criterion (dataplane::versioning) ---------------------------

fn accept_headers(values: &[&str]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for v in values {
        m.append(ACCEPT, HeaderValue::from_str(v).unwrap());
    }
    m
}

#[test]
fn accept_matcher_matches_entries_with_parameters_whitespace_and_case() {
    // Entry-level flexibility the request-path tests do not isolate:
    // media-type parameters, whitespace around commas and entries,
    // case-insensitivity, duplicates, and empty entries between commas.
    let want = "application/vnd.acme.v2+json";
    for raw in [
        "application/vnd.acme.v2+json",
        "Application/VND.Acme.V2+JSON",
        "application/vnd.acme.v2+json;charset=v2",
        "text/html, application/vnd.acme.v2+json",
        "text/html , application/vnd.acme.v2+json",
        " application/vnd.acme.v2+json ",
        "application/json, application/vnd.acme.v2+json, application/vnd.acme.v2+json",
        "application/vnd.acme.v2+json,,text/html",
    ] {
        assert!(accept_matches(&accept_headers(&[raw]), want), "{raw:?}");
    }
    // A type-only entry (no slash) names no media type, and no Accept
    // header at all never selects a version.
    assert!(!accept_matches(&accept_headers(&["application"]), want));
    assert!(!accept_matches(&accept_headers(&[""]), want));
    assert!(!accept_matches(&HeaderMap::new(), want));
}

#[test]
fn accept_matcher_matches_across_any_header_line() {
    // Multiple Accept header lines: any line may name the media type.
    let want = "application/vnd.acme.v2+json";
    assert!(accept_matches(
        &accept_headers(&[
            "text/html",
            "application/json;q=0.9, application/vnd.acme.v2+json"
        ]),
        want
    ));
    // A non-UTF-8 line (obs-text bytes are legal header values) cannot
    // name anything; it is skipped without failing the other lines.
    let mut m = HeaderMap::new();
    m.append(
        ACCEPT,
        HeaderValue::from_bytes(b"\xff\xfe-not-utf8").unwrap(),
    );
    assert!(!accept_matches(&m, want));
    m.append(ACCEPT, HeaderValue::from_str(want).unwrap());
    assert!(accept_matches(&m, want));
}

#[test]
fn accept_matcher_ignores_q_values_including_q_zero() {
    // PINS the documented behavior: q-values are ignored ENTIRELY. RFC
    // 9110 section 12.5.1 gives q=0 the meaning "not acceptable"; this
    // matcher does not implement q at all, so a client naming the
    // versioned type with q=0 still selects the versioned route.
    let want = "application/vnd.acme.v2+json";
    for raw in [
        "application/vnd.acme.v2+json;q=0",
        "application/vnd.acme.v2+json;q=0.0",
        "text/html;q=1, application/vnd.acme.v2+json;q=0",
    ] {
        assert!(accept_matches(&accept_headers(&[raw]), want), "{raw:?}");
    }
}

// --- Compiled deprecation (config::CompiledDeprecation) ------------------

fn dep_block(since: Option<&str>, sunset: Option<&str>, uri: Option<&str>) -> Deprecation {
    Deprecation {
        since: since.map(str::to_string),
        sunset: sunset.map(str::to_string),
        uri: uri.map(str::to_string),
    }
}

#[test]
fn compiled_deprecation_precomputes_the_rfc_header_values() {
    let c = CompiledDeprecation::compile(&dep_block(
        Some("Mon, 01 Jan 2024 00:00:00 GMT"),
        Some("Tue, 01 Jan 2030 00:00:00 GMT"),
        Some("https://docs.example.com/deprecations/users-v1"),
    ));
    assert_eq!(c.deprecation_header(), Some("@1704067200"));
    assert_eq!(
        c.sunset_header(),
        Some("Tue, 01 Jan 2030 00:00:00 GMT") // verbatim config string
    );
    assert_eq!(
        c.link_header(),
        Some("<https://docs.example.com/deprecations/users-v1>; rel=\"deprecation\"")
    );

    // A standalone RFC 8594 sunset compiles to exactly one header.
    let c = CompiledDeprecation::compile(&dep_block(
        None,
        Some("Tue, 01 Jan 2030 00:00:00 GMT"),
        None,
    ));
    assert_eq!(c.deprecation_header(), None);
    assert_eq!(c.sunset_header(), Some("Tue, 01 Jan 2030 00:00:00 GMT"));
    assert_eq!(c.link_header(), None);
}

#[test]
fn compiled_deprecation_carries_no_wall_clock() {
    // Enforcement is compile-time-only by design: a sunset already in
    // the past still compiles, so a published generation keeps emitting
    // it until the next publish (where snapshot::validate rejects it).
    let c = CompiledDeprecation::compile(&dep_block(
        None,
        Some("Sun, 06 Nov 1994 08:49:37 GMT"),
        None,
    ));
    assert_eq!(c.sunset_header(), Some("Sun, 06 Nov 1994 08:49:37 GMT"));

    // The structured-date render guard: a pre-1970 since cannot form a
    // non-negative @<seconds> (validation rejects it; compile drops it
    // rather than rendering a negative).
    let c = CompiledDeprecation::compile(&dep_block(
        Some("Fri, 01 Jan 1960 00:00:00 GMT"),
        None,
        None,
    ));
    assert_eq!(c.deprecation_header(), None);
}

#[test]
fn decorate_replaces_scalar_headers_and_appends_links() {
    // Emission semantics at the header-map level: Deprecation and
    // Sunset REPLACE any present values; Link is APPENDED beside them.
    let mut headers = HeaderMap::new();
    headers.insert("deprecation", HeaderValue::from_static("@1"));
    headers.insert(
        "sunset",
        HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"),
    );
    headers.append(
        "link",
        HeaderValue::from_static("<https://up.example/help>; rel=\"help\""),
    );

    let c = CompiledDeprecation::compile(&dep_block(
        Some("Mon, 01 Jan 2024 00:00:00 GMT"),
        Some("Tue, 01 Jan 2030 00:00:00 GMT"),
        Some("https://docs.example.com/d"),
    ));
    decorate(&mut headers, &c);

    assert_eq!(
        headers.get("deprecation").and_then(|v| v.to_str().ok()),
        Some("@1704067200")
    );
    assert_eq!(
        headers.get("sunset").and_then(|v| v.to_str().ok()),
        Some("Tue, 01 Jan 2030 00:00:00 GMT")
    );
    let links: Vec<_> = headers
        .get_all("link")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(links.len(), 2, "upstream link survives the append");
}

#[test]
fn decorate_skips_unbuildable_link_values_without_panicking() {
    // Generation-tear backstop: compile does not re-validate the uri,
    // so a value carrying a control byte (impossible via validated
    // config) must be skipped at emission, never panic.
    let c = CompiledDeprecation::compile(&dep_block(None, None, Some("https://x/\u{7f}")));
    let mut headers = HeaderMap::new();
    decorate(&mut headers, &c);
    assert!(headers.get("link").is_none());
}
