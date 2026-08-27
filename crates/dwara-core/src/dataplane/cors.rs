//! Route-scoped CORS (DW-027, feature analysis 4.14).
//!
//! Two phases, both driven by one [`Cors`] policy attached to a route:
//!
//! - **Preflight short-circuit** ([`is_preflight`] +
//!   [`preflight_response`]): an `OPTIONS` request carrying BOTH `Origin`
//!   and `Access-Control-Request-Method` on a CORS-configured route is
//!   answered 204 by the gateway immediately after route resolution and
//!   the route-scoped limit checks — before authentication,
//!   authorization, rate limiting, and cap admission, and NEVER proxied
//!   upstream. Browsers send preflights without credentials, so gating
//!   them on authn would break every credentialed route; they are also
//!   pure metadata probes, so admitting them to the concurrency cap
//!   would let a hostile page burn slots cheaply. A preflight that
//!   fails validation (origin, method, or requested headers not
//!   allowed) is still short-circuited — 204 with NO CORS headers,
//!   which the browser reads as a failed preflight. A plain `OPTIONS`
//!   without the preflight markers is NOT intercepted and proxies
//!   normally. A preflight whose route `match.methods` list excludes
//!   `OPTIONS` never resolves the route at all (404, the documented
//!   request-path order) — include `OPTIONS` in the method list of CORS
//!   routes.
//! - **Actual-response decoration** ([`decorate_actual`]): responses on
//!   the route (every action: proxy, redirect, respond) carry
//!   `Access-Control-Allow-Origin` (`*`, or the echoed request origin
//!   under a specific list), `Access-Control-Allow-Credentials: true`
//!   when configured, `Access-Control-Expose-Headers` when configured,
//!   and `Vary: Origin` (merged; see [`crate::dataplane::hardening::merge_vary`]).
//!   A request whose `Origin` is not allowed gets NO CORS headers — the
//!   response passes through unchanged (same-origin and no-cors reads
//!   never consult CORS).
//!
//! Origin matching uses the shared origin grammar in
//! [`crate::config::normalize_origin`]: exact match on the normalized
//! form (lowercase scheme and host, default port dropped, no userinfo)
//! or the single config entry `*`. The config side of that comparison
//! is precompiled into [`crate::config::CompiledCorsOrigins`] at
//! snapshot-compile time (see [`crate::snapshot::RouteTable::cors_origins`]),
//! so the request path normalizes only the request's own `Origin`.
//! Subdomain wildcards (`*.example.com`) are deliberately not offered
//! in v1: an explicit origin list is auditable, a wildcard is not; add
//! entries per origin until that tradeoff is worth revisiting.

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{
    HeaderMap, HeaderValue, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
};
use hyper::{Method, Response, StatusCode};

use crate::config::{CompiledCorsOrigins, Cors};
use crate::dataplane::hardening::merge_vary;

/// Is this request a CORS preflight (the only request shape the gateway
/// answers without proxying)? Requires `OPTIONS`, an `Origin`, and the
/// `Access-Control-Request-Method` marker the Fetch spec defines for
/// preflights; anything less is a normal request.
pub fn is_preflight(method: &Method, headers: &HeaderMap) -> bool {
    *method == Method::OPTIONS
        && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD)
        && headers.contains_key(ORIGIN)
}

/// Is `method` (an `Access-Control-Request-Method` value) allowed?
/// Case-insensitive token comparison against `allowed_methods`.
fn method_allowed(cors: &Cors, method: &str) -> bool {
    cors.allowed_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method.trim()))
}

/// Are ALL headers of an `Access-Control-Request-Headers` value allowed?
/// `*` in `allowed_headers` permits any requested header; otherwise
/// every requested name must appear (case-insensitively) in the list.
fn headers_allowed(cors: &Cors, requested: &str) -> bool {
    let wildcard = cors.allowed_headers.iter().any(|h| h == "*");
    requested.split(',').all(|name| {
        let name = name.trim();
        if name.is_empty() {
            return true;
        }
        wildcard
            || cors
                .allowed_headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name))
    })
}

/// Build the gateway-answered preflight response (DW-027): always 204;
/// CORS headers only when the preflight validates against the policy.
/// `origins` is the policy's snapshot-compiled origin set (normalized
/// once at compile time, not per request).
///
/// Caching correctness: the response varies by `Origin` and, when
/// echoing requested values, by the two request-marker headers — all
/// three are listed in `Vary` unconditionally so a shared cache cannot
/// serve one origin's preflight answer to another.
pub fn preflight_response(
    cors: &Cors,
    origins: &CompiledCorsOrigins,
    headers: &HeaderMap,
) -> Response<Full<Bytes>> {
    let origin = headers
        .get(ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let requested_method = headers
        .get(ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let requested_headers = headers
        .get(ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let mut builder = Response::builder().status(StatusCode::NO_CONTENT).header(
        "vary",
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );

    if origins.allows(origin)
        && method_allowed(cors, requested_method)
        && headers_allowed(cors, requested_headers)
    {
        // Echo the request origin under a specific list (the allowed
        // set is closed, so the echo IS the policy decision); `*` only
        // under the wildcard config (validation rejects `*` + creds).
        let allow_origin = if origins.wildcard() { "*" } else { origin };
        if let Ok(v) = HeaderValue::from_str(allow_origin) {
            builder = builder.header(ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
        if let Ok(v) = HeaderValue::from_str(&cors.allowed_methods.join(", ")) {
            builder = builder.header(ACCESS_CONTROL_ALLOW_METHODS, v);
        }
        // Allow-headers: echo the requested list under a `*` policy
        // (the browser asked for exactly these), the configured list
        // otherwise — both are correct answers to "may I send these".
        let allow_headers = if cors.allowed_headers.iter().any(|h| h == "*") {
            requested_headers.to_string()
        } else {
            cors.allowed_headers.join(", ")
        };
        if !allow_headers.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&allow_headers) {
                builder = builder.header(ACCESS_CONTROL_ALLOW_HEADERS, v);
            }
        }
        if cors.allow_credentials {
            builder = builder.header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }
        if let Some(max_age) = cors.max_age_secs {
            builder = builder.header(ACCESS_CONTROL_MAX_AGE, max_age.to_string());
        }
    }

    builder
        .body(Full::new(Bytes::new()))
        .expect("static preflight response is valid")
}

/// Decorate an ACTUAL (non-preflight) response with the route's CORS
/// headers (DW-027). No-ops when the request carried no `Origin` or an
/// origin the policy does not allow. `origins` is the policy's
/// snapshot-compiled origin set (see [`preflight_response`]).
pub fn decorate_actual(
    cors: &Cors,
    origins: &CompiledCorsOrigins,
    origin: Option<&HeaderValue>,
    resp_headers: &mut HeaderMap,
) {
    let Some(origin) = origin.and_then(|v| v.to_str().ok()) else {
        return;
    };
    if !origins.allows(origin) {
        return;
    }
    let allow_origin = if origins.wildcard() { "*" } else { origin };
    if let Ok(v) = HeaderValue::from_str(allow_origin) {
        resp_headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    if cors.allow_credentials {
        resp_headers.insert(
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    if !cors.expose_headers.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&cors.expose_headers.join(", ")) {
            resp_headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, v);
        }
    }
    merge_vary(resp_headers, "Origin");
}
