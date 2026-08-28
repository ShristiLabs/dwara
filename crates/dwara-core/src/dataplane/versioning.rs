//! API versioning aids (DW-048): the Accept media-type criterion of
//! route matching, and the Deprecation/Sunset response-header
//! automation.
//!
//! ## What is code here vs already expressible (the honest split)
//!
//! The router (DW-010) already covers the common versioning shapes, and
//! this module deliberately does NOT re-implement any of them:
//!
//! - **Path-segment versions** (`/v1/users`, `/v2/users`): plain path
//!   routes with the canonical precedence (exact > regex > prefix;
//!   longest prefix wins), plus `rewrite.replace_prefix` to strip the
//!   version segment toward a version-agnostic upstream. Nothing new
//!   was needed.
//! - **Version-header constraints** (`X-API-Version: "2"`): the exact
//!   header matcher (`match.headers`) already expresses "this route
//!   additionally requires that header value". Nothing new was needed.
//! - **Version-in-query** (`?version=2`): `match.query` covers it.
//!
//! Two things were genuinely missing, and are the whole of the code:
//!
//! 1. **Accept media-type selection** ([`accept_matches`]): the exact
//!    header matcher requires byte-equality of the ENTIRE header value,
//!    so `Accept: application/vnd.acme.v2+json, application/json;q=0.8`
//!    cannot select a version. `match.accept` names one media type; the
//!    route applies when any Accept entry names that type/subtype
//!    (case-insensitive), ignoring parameters and q-values — including
//!    q=0, which RFC 9110 section 12.5.1 defines as `not acceptable`
//!    but which does not affect selection in v1 (a documented design
//!    decision: naming the version selects it, however reluctantly).
//!    The configured value is normalized (padding, case) once at
//!    snapshot compile and the compiled form is what the criterion
//!    compares, so the raw config string never reaches the hot path.
//!    Wildcard entries and a missing Accept never match: version
//!    selection requires the client to NAME the version, so
//!    unconstrained clients fall through to the unversioned default
//!    route.
//! 2. **Deprecation/Sunset automation** ([`decorate`]): the
//!    `routes[].deprecation` config block emitting the RFC headers (see
//!    `config::Deprecation` for the frozen semantics).
//!
//! ## The v1 same-path limitation (documented, deliberately not fixed)
//!
//! Non-path criteria are applied AFTER path resolution and a criteria
//! miss does NOT fall through to another candidate (the frozen DW-010
//! model; duplicate exact templates are additionally rejected at
//! compile). Consequence: multiple versions of ONE path cannot be
//! selected by header or Accept in v1 — a version family uses distinct
//! paths (`/v1/`, `/v2/`, optionally constrained further by
//! `match.headers`/`match.accept`), or a single route serving one
//! version. Candidate iteration across same-path routes is a router
//! model change, out of scope for this aid; noted for the future.
//!
//! ## Caching correctness
//!
//! A response whose route was selected by `match.accept` varies with
//! the request's `Accept`, so the decoration tail merges
//! `Vary: Accept` into every response of such a route (the same
//! reasoning as CORS's `Vary: Origin`), composing with compression's
//! `Vary: Accept-Encoding`.

use hyper::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};

use crate::config::CompiledDeprecation;

const DEPRECATION: HeaderName = HeaderName::from_static("deprecation");
const SUNSET: HeaderName = HeaderName::from_static("sunset");
const LINK: HeaderName = HeaderName::from_static("link");

/// Does the request's `Accept` header name `media_type` (the compiled,
/// NORMALIZED `type/subtype` of `match.accept` —
/// `RouteTable::accept_media_type`, never the raw config string)? Any
/// comma-separated entry of ANY `Accept` header line matches,
/// case-insensitively, with parameters (`;q=...`, media-type
/// parameters) and surrounding whitespace ignored. Wildcard entries
/// (`*/*`, `type/*`) never match a specific type, and no `Accept`
/// header at all never matches — both deliberately (see the module
/// docs).
pub fn accept_matches(headers: &HeaderMap, media_type: &str) -> bool {
    headers.get_all(&ACCEPT).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|raw| accept_lists_media_type(raw, media_type))
    })
}

/// One `Accept` header value: does any of its comma-separated media
/// ranges equal `want` on type/subtype?
fn accept_lists_media_type(raw: &str, want: &str) -> bool {
    raw.split(',').any(|entry| {
        let media_type = entry.split(';').next().unwrap_or("").trim();
        !media_type.is_empty() && media_type.eq_ignore_ascii_case(want)
    })
}

/// Stamp a route's deprecation policy onto a response (DW-048).
/// `Deprecation` and `Sunset` REPLACE any upstream-sent values (the
/// gateway is the source of truth for the policy it is configured to
/// emit — the same rule as the `X-RateLimit-*` headers); `Link` is
/// APPENDED (a list header: upstream links must survive). Unbuildable
/// values are skipped, never panic — validation has already rejected
/// them for publishable configs, so this is only a generation-tear
/// backstop, the same posture as the respond-action headers.
pub fn decorate(headers: &mut HeaderMap, dep: &CompiledDeprecation) {
    if let Some(v) = dep.deprecation_header() {
        if let Ok(hv) = HeaderValue::from_str(v) {
            headers.insert(&DEPRECATION, hv);
        }
    }
    if let Some(v) = dep.sunset_header() {
        if let Ok(hv) = HeaderValue::from_str(v) {
            headers.insert(&SUNSET, hv);
        }
    }
    if let Some(v) = dep.link_header() {
        if let Ok(hv) = HeaderValue::from_str(v) {
            headers.append(&LINK, hv);
        }
    }
}
