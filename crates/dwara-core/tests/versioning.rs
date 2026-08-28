//! API versioning aids (DW-048): Accept media-type route selection and
//! Deprecation/Sunset response-header automation. The already-expressible
//! versioning shapes (path segments with rewrite, exact header criteria)
//! are exercised here as the documented patterns; the same-path
//! multi-version limitation (no criteria fallthrough, the DW-010 model)
//! is pinned by the 404 assertions.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{
    ACCEPT_ENCODING, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_ENCODING, CONTENT_TYPE, ORIGIN, VARY,
};
use hyper::{Method, Request, StatusCode};

use support::{body_of, body_text, dataplane_from, envelope_code, spawn_backend_full};

/// Fixed dates so every assertion is deterministic: `since` in the past
/// (a deprecation in effect is normal), `sunset` comfortably in the
/// future (validation rejects past sunsets).
const SINCE: &str = "Mon, 01 Jan 2024 00:00:00 GMT";
const SINCE_EPOCH: &str = "@1704067200";
const SUNSET: &str = "Tue, 01 Jan 2030 00:00:00 GMT";
const DEP_URI: &str = "https://docs.example.com/deprecations/users-v1";

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn h(v: Option<&hyper::header::HeaderValue>) -> String {
    v.and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn dep_hdr(resp: &hyper::Response<dwara_core::proxy::ProxyBody>) -> String {
    h(resp.headers().get("deprecation"))
}

fn sunset_hdr(resp: &hyper::Response<dwara_core::proxy::ProxyBody>) -> String {
    h(resp.headers().get("sunset"))
}

fn link_values(resp: &hyper::Response<dwara_core::proxy::ProxyBody>) -> Vec<String> {
    resp.headers()
        .get_all("link")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect()
}

async fn send(
    dp: &Arc<dwara_core::proxy::DataPlane>,
    req: Request<Full<Bytes>>,
) -> hyper::Response<dwara_core::proxy::ProxyBody> {
    dwara_core::proxy::handle(dp, ip(), req).await
}

/// Is `value` the fixed-width IMF-fixdate shape (RFC 9110), the only
/// form a generator may send and RFC 8594 `Sunset` requires?
fn is_imf_fixdate(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 29 || !value.ends_with(" GMT") {
        return false;
    }
    let day_names = ["Sun,", "Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let digits = |slice: &[u8]| slice.iter().all(u8::is_ascii_digit);
    day_names.iter().any(|d| value.starts_with(d))
        && digits(&b[5..7])
        && b[7] == b' '
        && months.iter().any(|m| &value[8..11] == *m)
        && b[11] == b' '
        && digits(&b[12..16])
        && b[16] == b' '
        && digits(&b[17..19])
        && b[19] == b':'
        && digits(&b[20..22])
        && b[22] == b':'
        && digits(&b[23..25])
        && b[25] == b' '
}

/// Backend for the suite: echoes the received path in the body so route
/// selection (and the path rewrite) is visible, serves a compressible
/// `text/plain` body on `*/big`, and decorates EVERY response with its
/// own deprecation-family headers — the interaction tests assert the
/// gateway REPLACES them on deprecated routes, passes them through
/// untouched on undeprecated ones, and appends `Link` beside the
/// upstream's own.
async fn echo_backend() -> u16 {
    spawn_backend_full(Arc::new(
        move |req: hyper::Request<hyper::body::Incoming>| {
            let path = req.uri().path();
            let (ctype, body): (&str, Bytes) = if path.ends_with("/big") {
                (
                    "text/plain",
                    Bytes::from("dwara versioning payload\n".repeat(128)),
                )
            } else {
                ("text/plain", Bytes::from(format!("path:{path}")))
            };
            hyper::Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, ctype)
                .header("deprecation", "@1")
                .header("sunset", "Thu, 01 Jan 1970 00:00:00 GMT")
                .header("link", "<https://upstream.example/help>; rel=\"help\"")
                .body(Full::new(body))
                .unwrap()
        },
    ))
    .await
}

fn versioning_yaml(backend_port: u16) -> String {
    format!(
        r#"
routes:
  - name: users-v1
    service: svc
    match: {{ path: {{ type: prefix, value: /v1 }} }}
    action:
      type: proxy
      rewrite: {{ type: replace_prefix, prefix: /v1, replacement: "" }}
    deprecation:
      since: "{SINCE}"
      sunset: "{SUNSET}"
      uri: "{DEP_URI}"
  - name: users-v2
    service: svc
    match: {{ path: {{ type: prefix, value: /v2 }} }}
    action:
      type: proxy
      rewrite: {{ type: replace_prefix, prefix: /v2, replacement: "" }}
  - name: header-v2
    service: svc
    match:
      path: {{ type: prefix, value: /hv }}
      headers: {{ x-api-version: "2" }}
    action: {{ type: proxy }}
  - name: media-v2
    service: svc
    match:
      path: {{ type: prefix, value: /media/v2 }}
      accept: application/vnd.acme.v2+json
    action: {{ type: proxy }}
  - name: media-default
    service: svc
    match: {{ path: {{ type: prefix, value: /media }} }}
    action: {{ type: proxy }}
  - name: retired-info
    service: svc
    match: {{ path: {{ type: exact, value: /info }} }}
    action: {{ type: respond, status: 200, body: "info" }}
    deprecation:
      since: "{SINCE}"
      sunset: "{SUNSET}"
  - name: moved-deprecated
    service: svc
    match: {{ path: {{ type: prefix, value: /moved }} }}
    action: {{ type: redirect, status: 302, path: /landed }}
    deprecation:
      since: "{SINCE}"
      sunset: "{SUNSET}"
  - name: limited-deprecated
    service: svc
    match: {{ path: {{ type: prefix, value: /limited }} }}
    action: {{ type: proxy }}
    limits: {{ max_body_bytes: 8 }}
    deprecation:
      since: "{SINCE}"
  - name: compressed-deprecated
    service: svc
    match: {{ path: {{ type: prefix, value: /compressed }} }}
    action: {{ type: proxy }}
    compression: {{ algorithms: [gzip], min_size: 0 }}
    deprecation:
      since: "{SINCE}"
      sunset: "{SUNSET}"
  - name: all-policies
    service: svc
    match:
      path: {{ type: prefix, value: /all }}
      accept: application/vnd.acme.v2+json
    action: {{ type: proxy }}
    compression: {{ algorithms: [gzip], min_size: 0 }}
    cors: {{ allowed_origins: ["https://app.example.com"] }}
    deprecation:
      since: "{SINCE}"
      sunset: "{SUNSET}"
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {backend_port} }}]
"#
    )
}

async fn fixture() -> Arc<dwara_core::proxy::DataPlane> {
    let port = echo_backend().await;
    dataplane_from(&versioning_yaml(port))
}

// ---------------------------------------------------------------------------
// Path-segment versioning (the already-expressible shape, DW-010)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn path_versions_route_independently_and_rewrite_the_version_segment() {
    let dp = fixture().await;

    // Longest-prefix precedence picks the right version, and each
    // version's rewrite strips its own segment toward the upstream.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/v1/users")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "path:/users", "v1 rewrite strips /v1");

    let resp = send(
        &dp,
        Request::builder()
            .uri("/v2/users")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "path:/users", "v2 rewrite strips /v2");
}

// ---------------------------------------------------------------------------
// Header-based version selection (the exact-criterion shape, DW-010)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exact_version_header_criterion_selects_and_rejects() {
    let dp = fixture().await;

    let resp = send(
        &dp,
        Request::builder()
            .uri("/hv/users")
            .header("x-api-version", "2")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "path:/hv/users");

    // A criteria miss does not fall through to another route: the
    // documented DW-010 model. Same-path multi-version is therefore NOT
    // expressible in v1; version families use distinct paths.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/hv/users")
            .header("x-api-version", "1")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Accept media-type selection (the DW-048 matcher)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accept_matcher_selects_on_type_subtype_ignoring_list_and_q() {
    let dp = fixture().await;

    let get = |accept: Option<&str>| {
        let builder = Request::builder().uri("/media/v2/item");
        match accept {
            Some(a) => builder.header(hyper::header::ACCEPT, a),
            None => builder,
        }
        .body(Full::new(Bytes::new()))
        .unwrap()
    };

    // Exact value.
    let resp = send(&dp, get(Some("application/vnd.acme.v2+json"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "path:/media/v2/item");

    // Case-insensitive type/subtype, inside a list, with q-values and
    // parameters on the request side ignored.
    let resp = send(
        &dp,
        get(Some(
            "application/json;q=0.8, Application/VND.Acme.V2+JSON ;v=2",
        )),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "list + q + case-insensitive");

    // Wildcards and a missing Accept never select a version: the client
    // must NAME the version. These 404 (the /media default route is a
    // different path and does not fall through — the documented limit).
    for accept in [
        Some("*/*"),
        Some("application/*"),
        Some("application/json"),
        None,
    ] {
        let resp = send(&dp, get(accept)).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "accept: {accept:?}");
    }

    // The unversioned default path keeps serving unconstrained clients.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/media/item")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "path:/media/item");
}

#[tokio::test]
async fn padded_accept_config_value_matches_like_its_canonical_spelling() {
    // Regression (DW-048 tester finding): quoted YAML keeps padding, and
    // the criterion used to compare the RAW config string — a padded
    // `match.accept` published cleanly (validation checks through the
    // normalizing grammar) and then 404ed every request. The comparison
    // key is now the compiled normalized form
    // (`RouteTable::accept_media_type`), so padding and case in the
    // config are authoring conveniences, never routing inputs.
    let port = echo_backend().await;
    let dp = dataplane_from(&format!(
        r#"
routes:
  - name: padded
    service: svc
    match:
      path: {{ type: prefix, value: /padded }}
      accept: "  Application/VND.Acme.V2+JSON  "
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    ));

    // The trimmed, lowercased request spelling selects the route.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/padded/item")
            .header(hyper::header::ACCEPT, "application/vnd.acme.v2+json")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "padded spelling must match");
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "path:/padded/item");

    // The criterion is live, not dropped by the normalization: a
    // different media type still misses (404, no fallthrough).
    let resp = send(
        &dp,
        Request::builder()
            .uri("/padded/item")
            .header(hyper::header::ACCEPT, "application/json")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn accept_selected_routes_vary_on_accept() {
    let dp = fixture().await;

    // Cache correctness: the representation was chosen by the request's
    // Accept, so shared caches must key on it.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/media/v2/item")
            .header(hyper::header::ACCEPT, "application/vnd.acme.v2+json")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let vary = h(resp.headers().get(VARY));
    assert!(vary.to_lowercase().contains("accept"), "vary: {vary}");

    // A route without the criterion does not grow the Vary.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/v2/users")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let vary = h(resp.headers().get(VARY)).to_lowercase();
    assert!(
        !vary.contains("accept"),
        "unconstrained route must not Vary: {vary}"
    );
}

// ---------------------------------------------------------------------------
// Deprecation / Sunset automation (DW-048)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deprecated_route_carries_rfc_formed_headers_on_proxied_responses() {
    let dp = fixture().await;

    let resp = send(
        &dp,
        Request::builder()
            .uri("/v1/users")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // RFC 9745: the Deprecation field is a structured date, `@<unix>`.
    let dep = dep_hdr(&resp);
    assert!(
        dep.starts_with('@') && dep[1..].bytes().all(|b| b.is_ascii_digit()),
        "not the @<unix> form: {dep}"
    );
    assert_eq!(dep, SINCE_EPOCH, "the @unix rendering of the since date");

    // RFC 8594: Sunset is an HTTP-date; the validated config string is
    // emitted verbatim.
    let sunset = sunset_hdr(&resp);
    assert_eq!(sunset, SUNSET);
    assert!(is_imf_fixdate(&sunset), "IMF-fixdate shape: {sunset}");

    // RFC 9745 companion link, APPENDED beside the upstream's own link.
    let links = link_values(&resp);
    assert!(
        links
            .iter()
            .any(|l| l == &format!("<{DEP_URI}>; rel=\"deprecation\"")),
        "{links:?}"
    );
    assert!(
        links.iter().any(|l| l.contains("rel=\"help\"")),
        "upstream link must survive the append: {links:?}"
    );

    // The gateway is the source of truth for the headers it configures:
    // the upstream's own deprecation-family values are replaced (the
    // backend sends @1 / the 1970 date on every response).
    assert_eq!(dep_hdr(&resp), SINCE_EPOCH);
    assert_eq!(sunset_hdr(&resp), SUNSET);
}

#[tokio::test]
async fn deprecation_headers_on_direct_response_action() {
    let dp = fixture().await;

    let resp = send(
        &dp,
        Request::builder()
            .uri("/info")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(dep_hdr(&resp), SINCE_EPOCH);
    assert_eq!(sunset_hdr(&resp), SUNSET);
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "info");
}

#[tokio::test]
async fn deprecation_headers_on_redirect_action() {
    let dp = fixture().await;

    // The decoration tail sits after EVERY action: a redirect response
    // carries the policy headers exactly like a proxied one.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/moved/users")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(h(resp.headers().get("location")), "/landed");
    assert_eq!(dep_hdr(&resp), SINCE_EPOCH);
    assert_eq!(sunset_hdr(&resp), SUNSET);
}

#[tokio::test]
async fn gateway_deprecation_link_appends_after_upstream_links() {
    let dp = fixture().await;

    // Byte-order pin for the append semantics: the upstream's own links
    // come first, the gateway's deprecation link LAST.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/v1/users")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    let links = link_values(&resp);
    assert_eq!(links.len(), 2, "{links:?}");
    assert!(
        links[0].contains("rel=\"help\""),
        "upstream link first: {links:?}"
    );
    assert_eq!(
        links[1],
        format!("<{DEP_URI}>; rel=\"deprecation\""),
        "gateway link appended last: {links:?}"
    );
}

#[tokio::test]
async fn undeprecated_route_passes_upstream_values_through_untouched() {
    let dp = fixture().await;

    let resp = send(
        &dp,
        Request::builder()
            .uri("/v2/users")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // No deprecation block on the route: the upstream's own values stand.
    assert_eq!(dep_hdr(&resp), "@1");
    assert_eq!(sunset_hdr(&resp), "Thu, 01 Jan 1970 00:00:00 GMT");
    assert_eq!(link_values(&resp).len(), 1, "only the upstream link");
}

#[tokio::test]
async fn short_circuit_responses_do_not_carry_deprecation_headers() {
    let dp = fixture().await;

    // 413 route-limit rejection: describes the request, not the route
    // lifecycle — no deprecation headers. Inspect headers before the
    // body is consumed.
    let resp = send(
        &dp,
        Request::builder()
            .method(Method::POST)
            .uri("/limited/x")
            .header(hyper::header::CONTENT_LENGTH, "10")
            .body(Full::new(Bytes::from_static(b"0123456789")))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(dep_hdr(&resp), "", "413 short-circuit");
    assert_eq!(sunset_hdr(&resp), "", "413 short-circuit");
    assert_eq!(
        envelope_code(body_text(resp.into_body()).await.as_bytes()),
        "request_body_too_large"
    );

    // Unrouted traffic never matched the route at all.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/media/v2/item")
            .header(hyper::header::ACCEPT, "application/json")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(dep_hdr(&resp), "", "404");
    assert_eq!(sunset_hdr(&resp), "", "404");
}

#[tokio::test]
async fn deprecation_headers_survive_compression() {
    let dp = fixture().await;

    let resp = send(
        &dp,
        Request::builder()
            .uri("/compressed/big")
            .header(ACCEPT_ENCODING, "gzip")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    // Stamped after the codec wrap: the compression wrapper only
    // rewrites Content-Length/Content-Encoding/Vary, so the headers
    // survive verbatim.
    assert_eq!(dep_hdr(&resp), SINCE_EPOCH);
    assert_eq!(sunset_hdr(&resp), SUNSET);
    let vary = h(resp.headers().get(VARY)).to_lowercase();
    assert!(vary.contains("accept-encoding"), "vary: {vary}");
}

#[tokio::test]
async fn all_response_policies_compose_together() {
    let dp = fixture().await;

    // One route exercising every response-decoration family at once:
    // accept selection + compression + CORS + deprecation. The single
    // folded Vary line must carry every token.
    let resp = send(
        &dp,
        Request::builder()
            .uri("/all/big")
            .header(hyper::header::ACCEPT, "application/vnd.acme.v2+json")
            .header(ACCEPT_ENCODING, "gzip")
            .header(ORIGIN, "https://app.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h(resp.headers().get(CONTENT_ENCODING)), "gzip");
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com"
    );
    assert_eq!(dep_hdr(&resp), SINCE_EPOCH);
    assert_eq!(sunset_hdr(&resp), SUNSET);
    let vary = h(resp.headers().get(VARY)).to_lowercase();
    for token in ["accept", "accept-encoding", "origin"] {
        assert!(vary.contains(token), "vary missing {token}: {vary}");
    }
}

#[tokio::test]
async fn folded_vary_carries_each_token_exactly_once() {
    let dp = fixture().await;

    // The 3-way fold must be one Vary line carrying each token exactly
    // once (a duplicated token would mis-order cache keys and bloat
    // responses; `contains` alone cannot see a duplicate).
    let resp = send(
        &dp,
        Request::builder()
            .uri("/all/big")
            .header(hyper::header::ACCEPT, "application/vnd.acme.v2+json")
            .header(ACCEPT_ENCODING, "gzip")
            .header(ORIGIN, "https://app.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut tokens: Vec<String> = h(resp.headers().get(VARY))
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    tokens.sort();
    assert_eq!(
        tokens,
        ["accept", "accept-encoding", "origin"],
        "each Vary token exactly once"
    );
}

#[tokio::test]
async fn preflight_on_accept_and_cors_route_needs_the_named_media_type() {
    let dp = fixture().await;

    let preflight = |accept: &str| {
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/all/big")
            .header(hyper::header::ACCEPT, accept)
            .header(ORIGIN, "https://app.example.com")
            .header("access-control-request-method", "GET")
            .body(Full::new(Bytes::new()))
            .unwrap()
    };

    // Browsers send `Accept: */*` (or nothing) for preflights: a
    // wildcard never names the version, so route resolution misses and
    // the request 404s BEFORE the CORS preflight short-circuit — a
    // versioned-media-type route cannot be preflighted by accident.
    let resp = send(&dp, preflight("*/*")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "wildcard Accept");

    // With the version named, the route applies and the preflight
    // short-circuits as usual: 204 with the CORS headers, but NO
    // deprecation-family headers (a preflight describes the upcoming
    // request, not the route's lifecycle).
    let resp = send(&dp, preflight("application/vnd.acme.v2+json")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        h(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)),
        "https://app.example.com"
    );
    assert_eq!(dep_hdr(&resp), "", "preflight is a short-circuit");
    assert_eq!(sunset_hdr(&resp), "", "preflight is a short-circuit");
}

#[tokio::test]
async fn equal_prefix_sibling_is_not_an_accept_fallback() {
    // Two routes, SAME prefix, one with the accept criterion and one
    // without: path resolution picks the FIRST-declared (the frozen
    // equal-length tie rule), and a criteria miss on the winner does
    // not fall through to the sibling — the DW-010 model the versioning
    // docs lean on for "the unversioned default must live on another
    // path".
    let port = echo_backend().await;
    let dp = dataplane_from(&format!(
        r#"
routes:
  - name: versioned
    service: svc
    match:
      path: {{ type: prefix, value: /sp }}
      accept: application/vnd.acme.v2+json
    action: {{ type: proxy }}
  - name: plain
    service: svc
    match: {{ path: {{ type: prefix, value: /sp }} }}
    action: {{ type: proxy }}
services:
  - name: svc
    upstream: up
upstreams:
  - name: up
    endpoints: [{{ address: 127.0.0.1, port: {port} }}]
"#
    ));

    let resp = send(
        &dp,
        Request::builder()
            .uri("/sp/item")
            .header(hyper::header::ACCEPT, "application/vnd.acme.v2+json")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "version named -> winner");
    let (_, body) = body_of(resp).await;
    assert_eq!(body, "path:/sp/item");

    let resp = send(
        &dp,
        Request::builder()
            .uri("/sp/item")
            .header(hyper::header::ACCEPT, "application/json")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "no fallback to the equal-prefix sibling"
    );
}

// ---------------------------------------------------------------------------
// Config validation (DW-048)
// ---------------------------------------------------------------------------

/// Parse + validate one route (prefix /x, proxy) carrying `extra`
/// route-level YAML, returning the validation issues.
fn validate_route(extra: &str) -> Vec<dwara_core::snapshot::ValidationIssue> {
    let yaml = format!(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {{ type: prefix, value: /x }}\n    action: {{ type: proxy }}\n{extra}services:\n  - name: s\n    upstream: u\nupstreams:\n  - name: u\n    endpoints: [{{ address: 127.0.0.1, port: 9 }}]\n"
    );
    let gateway = dwara_core::config::parse_gateway(&yaml).expect("fixture parses");
    dwara_core::snapshot::validate(&gateway)
}

#[test]
fn valid_deprecation_block_publishes_cleanly() {
    let issues = validate_route(&format!(
        "    deprecation:\n      since: \"{SINCE}\"\n      sunset: \"{SUNSET}\"\n      uri: \"{DEP_URI}\"\n"
    ));
    assert!(
        !issues.iter().any(|i| i.field.contains("deprecation")),
        "valid block rejected: {issues:?}"
    );

    // Sunset alone (a standalone RFC 8594 shape) is legitimate too.
    let issues = validate_route(&format!("    deprecation:\n      sunset: \"{SUNSET}\"\n"));
    assert!(
        !issues.iter().any(|i| i.field.contains("deprecation")),
        "{issues:?}"
    );
}

#[test]
fn validation_rejects_garbage_sunset_dates() {
    for bad in [
        "next tuesday",
        "2024-01-01T00:00:00Z",
        "Tue, 01 Jan 2030",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "01/01/2030",
    ] {
        let issues = validate_route(&format!(
            "    deprecation:\n      since: \"{SINCE}\"\n      sunset: \"{bad}\"\n"
        ));
        assert!(
            issues
                .iter()
                .any(|i| i.field == "deprecation.sunset" && i.message.contains("HTTP-date")),
            "sunset {bad:?} must be rejected: {issues:?}"
        );
    }
    // The same grammar governs `since`.
    let issues = validate_route("    deprecation:\n      since: \"whenever\"\n");
    assert!(
        issues
            .iter()
            .any(|i| i.field == "deprecation.since" && i.message.contains("HTTP-date")),
        "{issues:?}"
    );
}

#[test]
fn validation_rejects_sunset_in_the_past_and_before_since() {
    let issues =
        validate_route("    deprecation:\n      sunset: \"Sun, 06 Nov 1994 08:49:37 GMT\"\n");
    assert!(
        issues
            .iter()
            .any(|i| i.field == "deprecation.sunset" && i.message.contains("in the past")),
        "{issues:?}"
    );

    // Sunset before since: the route would be removed before it is
    // deprecated. (Both dates parse, so only the ordering fires.)
    let issues = validate_route(&format!(
        "    deprecation:\n      since: \"{SUNSET}\"\n      sunset: \"{SINCE}\"\n"
    ));
    assert!(
        issues
            .iter()
            .any(|i| i.field == "deprecation.sunset" && i.message.contains("before since")),
        "{issues:?}"
    );

    // A PAST `since` is normal (the deprecation is in effect).
    let issues = validate_route(&format!(
        "    deprecation:\n      since: \"{SINCE}\"\n      sunset: \"{SUNSET}\"\n"
    ));
    assert!(
        !issues.iter().any(|i| i.field.contains("deprecation")),
        "past since is legitimate: {issues:?}"
    );
}

#[test]
fn validation_rejects_empty_block_and_uri_without_since() {
    let issues = validate_route("    deprecation: {}\n");
    assert!(
        issues
            .iter()
            .any(|i| i.field == "deprecation" && i.message.contains("no dates")),
        "{issues:?}"
    );

    let issues = validate_route(&format!(
        "    deprecation:\n      sunset: \"{SUNSET}\"\n      uri: \"{DEP_URI}\"\n"
    ));
    assert!(
        issues
            .iter()
            .any(|i| i.field == "deprecation.uri" && i.message.contains("requires since")),
        "{issues:?}"
    );

    let issues = validate_route(&format!(
        "    deprecation:\n      since: \"{SINCE}\"\n      uri: \"not a url\"\n"
    ));
    assert!(
        issues
            .iter()
            .any(|i| i.field == "deprecation.uri" && i.message.contains("http(s) URL")),
        "{issues:?}"
    );
}

#[test]
fn validation_accepts_sunset_equal_to_since() {
    // The ordering rule is `sunset >= since`: equal dates are a same-day
    // deprecation-and-removal, not a removal before the deprecation.
    let issues = validate_route(&format!(
        "    deprecation:\n      since: \"{SUNSET}\"\n      sunset: \"{SUNSET}\"\n"
    ));
    assert!(
        !issues.iter().any(|i| i.field.contains("deprecation")),
        "equal since/sunset is legitimate: {issues:?}"
    );
}

#[test]
fn validation_rejects_since_before_the_unix_epoch() {
    // A pre-1970 since cannot render as the RFC 9745 `@<seconds>`
    // structured date; 1960-01-01 was a Friday.
    let issues =
        validate_route("    deprecation:\n      since: \"Fri, 01 Jan 1960 00:00:00 GMT\"\n");
    assert!(
        issues
            .iter()
            .any(|i| i.field == "deprecation.since" && i.message.contains("1970")),
        "{issues:?}"
    );
}

#[test]
fn validation_uri_requires_absolute_http_s_and_tolerates_case() {
    // Non-http(s) schemes and schemeless/relative values cannot carry a
    // migration notice.
    for bad in [
        "ftp://docs.example.com/deprecations",
        "/docs/deprecations",
        "http:///no-host",
    ] {
        let issues = validate_route(&format!(
            "    deprecation:\n      since: \"{SINCE}\"\n      uri: \"{bad}\"\n"
        ));
        assert!(
            issues
                .iter()
                .any(|i| i.field == "deprecation.uri" && i.message.contains("http(s) URL")),
            "uri {bad:?} must be rejected: {issues:?}"
        );
    }

    // Schemes and hosts are case-insensitive (RFC 3986; hyper lowercases
    // the scheme on parse), and the emitted Link keeps the configured
    // spelling verbatim — not an authoring error.
    let issues = validate_route(&format!(
        "    deprecation:\n      since: \"{SINCE}\"\n      uri: \"HTTPS://Docs.Example.COM/D\"\n"
    ));
    assert!(
        !issues.iter().any(|i| i.field == "deprecation.uri"),
        "{issues:?}"
    );
}

#[test]
fn validation_rejects_non_bare_media_type_accept_values() {
    // Splices into the route's `match` block (a bare route-level extra
    // would duplicate the `match` key, which YAML rejects before
    // validation ever runs).
    let issues = |accept: &str| {
        let yaml = format!(
            "routes:\n  - name: r\n    service: s\n    match:\n      path: {{ type: prefix, value: /x }}\n      accept: {accept}\n    action: {{ type: proxy }}\nservices:\n  - name: s\n    upstream: u\nupstreams:\n  - name: u\n    endpoints: [{{ address: 127.0.0.1, port: 9 }}]\n"
        );
        let gateway = dwara_core::config::parse_gateway(&yaml).expect("fixture parses");
        dwara_core::snapshot::validate(&gateway)
    };
    for bad in [
        "'*/*'",
        "'application/*'",
        "'application/json; q=1'",
        "'json'",
        "''",
    ] {
        let found = issues(bad);
        assert!(
            found
                .iter()
                .any(|i| i.field == "match.accept" && i.message.contains("bare media type")),
            "accept {bad} must be rejected: {found:?}"
        );
    }
    // A bare versioned media type is the supported shape.
    let found = issues("'application/vnd.acme.v2+json'");
    assert!(
        !found.iter().any(|i| i.field == "match.accept"),
        "{found:?}"
    );
}
