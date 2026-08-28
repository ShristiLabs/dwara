//! API-versioning grammar (DW-048): the two shared vocabularies the
//! versioning aids need beyond serde shapes — HTTP-dates (RFC 9110
//! IMF-fixdate) and media types (RFC 9110 `type/subtype` tokens).
//!
//! Both are config-contract grammar in the same sense as `net.rs` (the
//! IP/CIDR vocabulary) and `normalize_origin` (the CORS origin
//! vocabulary): validation (`snapshot::validate`) and the runtime
//! (`dataplane::versioning`) must agree on ONE parsing of these strings,
//! so it lives in `config`, the lowest consuming domain, and everything
//! above imports it from here.
//!
//! ## Why IMF-fixdate only
//!
//! RFC 9110 defines three HTTP-date formats (IMF-fixdate, RFC 850,
//! asctime) and requires RECIPIENTS to accept all three — but generators
//! "MUST send the IMF-fixdate form". This module is not a recipient of
//! arbitrary network dates; it parses OPERATOR-AUTHORED config strings
//! that this gateway will echo verbatim into the `Sunset` response
//! header. Accepting only the one form generators must produce keeps the
//! emitted header canonical and the validation message short; the
//! obsolete forms are rejected with an example of the expected shape.
//!
//! ## Why bare media types
//!
//! The `match.accept` criterion matches a media TYPE (`type/subtype`),
//! ignoring parameters and q-values on the request side — the
//! versioned-media-type convention embeds the version in the subtype
//! (`application/vnd.acme.v2+json`). Parameter-form versioning
//! (`application/vnd.acme+json;version=2`) is deliberately unsupported:
//! Accept entries mix media-type parameters with accept-extensions
//! (RFC 9110 section 12.5.1), and separating them reliably is parser
//! work out of proportion to an S-sized aid. Wildcards are rejected as
//! CONFIG values because they can never match (the criterion requires
//! the client to NAME the version explicitly — see
//! `dataplane::versioning`).

/// A parsed IMF-fixdate HTTP-date (DW-048). The original config string is
/// what gets echoed into the `Sunset` header (validated verbatim); this
/// type carries the derived Unix seconds the RFC 9745 `Deprecation`
/// structured date (`@<seconds>`) needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpDate {
    unix_seconds: i64,
}

impl HttpDate {
    /// Seconds since the Unix epoch (UTC by definition of the format —
    /// the only allowed zone is the literal `GMT`).
    pub fn unix_seconds(self) -> i64 {
        self.unix_seconds
    }
}

/// Day names in IMF-fixdate order (index 0 = Sunday), for the
/// day-of-week consistency check.
const DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Month names in IMF-fixdate order, paired with their day counts
/// (February's placeholder is replaced by the leap-year rule).
const MONTHS: [(&str, u32); 12] = [
    ("Jan", 31),
    ("Feb", 28),
    ("Mar", 31),
    ("Apr", 30),
    ("May", 31),
    ("Jun", 30),
    ("Jul", 31),
    ("Aug", 31),
    ("Sep", 30),
    ("Oct", 31),
    ("Nov", 30),
    ("Dec", 31),
];

/// Parse an IMF-fixdate HTTP-date (DW-048):
/// `day-name "," SP 2DIGIT SP month SP 4DIGIT SP time SP "GMT"`, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`. Returns `None` for anything else —
/// including the obsolete RFC 850 / asctime forms (see the module docs
/// for why) and a day-name that disagrees with the date it names (a
/// typo'd weekday is a typo'd date; `date -u` output always agrees).
pub fn parse_http_date(value: &str) -> Option<HttpDate> {
    // Single spaces only: splitting "Sun,  06 Nov..." (double space)
    // yields an empty part and fails the exact-count check below.
    let parts: Vec<&str> = value.split(' ').collect();
    if parts.len() != 6 {
        return None;
    }
    let day_name = parts[0].strip_suffix(',')?;
    let day: u32 = two_digits(parts[1])?;
    let month = MONTHS.iter().find(|(name, _)| *name == parts[2])?;
    let year: i64 = four_digits(parts[3])?;
    let (hour, minute, second) = parse_time(parts[4])?;
    if parts[5] != "GMT" {
        return None;
    }

    // Day-of-month bound (leap-year rule: divisible by 4, except
    // centuries, except quadricenturies).
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = if month.0 == "Feb" && leap {
        29
    } else {
        month.1
    };
    if !(1..=max_day).contains(&day) {
        return None;
    }

    let days = days_from_civil(year, month_index(parts[2])?, day);
    // Weekday consistency: Unix day 0 (1970-01-01) was a Thursday.
    let weekday = ((days % 7) + 7 + 4) % 7;
    if DAY_NAMES[weekday as usize] != day_name {
        return None;
    }

    Some(HttpDate {
        unix_seconds: days * 86_400
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second),
    })
}

/// Normalize a configured media type (DW-048): trim, lowercase, and
/// require a bare `type/subtype` — both halves non-empty RFC 9110
/// tokens, no parameters (`;...`), no whitespace, no wildcards. The
/// lowercased form is the comparison key; `None` marks an authoring
/// error validation reports.
pub fn normalize_media_type(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    let (ty, subtype) = lower.split_once('/')?;
    if ty.is_empty() || subtype.is_empty() || ty == "*" || subtype == "*" {
        return None;
    }
    if !ty.bytes().chain(subtype.bytes()).all(is_tchar) {
        return None;
    }
    Some(format!("{ty}/{subtype}"))
}

/// RFC 9110 `tchar` (token character): the entire grammar of a media
/// type's type and subtype names.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn two_digits(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    if b.len() == 2 && b[0].is_ascii_digit() && b[1].is_ascii_digit() {
        Some(u32::from((b[0] - b'0') * 10 + (b[1] - b'0')))
    } else {
        None
    }
}

fn four_digits(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() == 4 && b.iter().all(u8::is_ascii_digit) {
        Some(b.iter().fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0')))
    } else {
        None
    }
}

/// `HH:MM:SS`, each a two-digit field with the clock bounds enforced.
fn parse_time(s: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let hour = two_digits(parts[0])?;
    let minute = two_digits(parts[1])?;
    let second = two_digits(parts[2])?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((hour, minute, second))
}

fn month_index(name: &str) -> Option<u32> {
    // 1..=12 (March = 3), matching days_from_civil's convention.
    Some(match name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days from 1970-01-01 for a civil (proleptic Gregorian) date — Howard
/// Hinnant's `days_from_civil`, the standard integer-form conversion.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(m) + 9) % 12; // [0, 11], March = 0
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
