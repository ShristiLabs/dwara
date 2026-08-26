//! Authorization integration tests (DW-020, feature analysis 4.7/4.15).
//!
//! Drives `proxy::handle` directly: consumer allow/deny, groups, scopes
//! (space-separated AND array claims), exact-match claims, IP ACLs
//! (allow-list-only, deny-wins, closed default), the effective-IP
//! resolution through a trusted-proxy XFF chain, anonymous access on an
//! ip_acl-only route, and the 403-vs-401 semantics. Precedence-chain
//! merge (consumer deny beats route allow etc.) is unit-tested in
//! `dwara_core::authz` — the consumer/service/listener/global links
//! have no config attachment points yet, so only the route link is
//! exercisable end-to-end (documented-pending).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use dwara_core::snapshot::ConfigState;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use tokio::net::TcpListener;

mod support;

use support::dataplane_from;

/// Base config: one catch-all route with an `authorization` block
/// (YAML fragment) and an optional set of consumers / trusted proxies.
fn config_with(authz: &str, consumers: &str, trusted: &str) -> String {
    let trusted = if trusted.is_empty() {
        String::new()
    } else {
        format!("trusted_proxies:\n{trusted}")
    };
    format!(
        "{trusted}listeners: []
routes:
  - name: r
    service: svc
    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: respond, status: 200 }}
    authorization:
{authz}services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 1
{consumers}"
    )
}

fn one_consumer(name: &str, key: &str, groups: &[&str]) -> String {
    let groups = if groups.is_empty() {
        String::new()
    } else {
        format!("    groups: [{}]\n", groups.join(", "))
    };
    format!(
        "consumers:
  - name: {name}
{groups}    credentials:
      - type: api_key
        key: {key}
"
    )
}

fn two_consumers() -> String {
    format!(
        "{}  - name: beta\n    credentials:\n      - type: api_key\n        key: beta-key\n",
        one_consumer("acme", "acme-key", &["gold"])
    )
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

async fn send_from(
    dp: &DataPlane,
    peer: IpAddr,
    headers: Vec<(&str, &str)>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().uri("/x");
    for (n, v) in headers {
        builder = builder.header(n, v);
    }
    let req = builder.body(Full::new(Bytes::new())).unwrap();
    let resp = dwara_core::proxy::handle(dp, peer, req).await;
    let (parts, body) = resp.into_parts();
    let text =
        String::from_utf8(body.collect().await.expect("body read").to_bytes().to_vec()).unwrap();
    (parts.status, parts.headers, text)
}

async fn send(dp: &DataPlane, headers: Vec<(&str, &str)>) -> (StatusCode, HeaderMap, String) {
    send_from(dp, ip(10, 0, 0, 1), headers).await
}

// ---- consumer allow/deny + 401/403 semantics --------------------------------

#[tokio::test]
async fn consumer_allow_list_restricts_and_denies() {
    let yaml = config_with("      allowed_consumers: [acme]\n", &two_consumers(), "");
    let dp = dataplane_from(&yaml);
    // Allowed consumer passes.
    let (s, _, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::OK);
    // Other authenticated consumer: 403 (not 401 — authenticated).
    let (s, h, _) = send(&dp, vec![("x-api-key", "beta-key")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(
        !h.contains_key("www-authenticate"),
        "403 carries no challenge"
    );
    // Anonymous: identity rules imply authentication -> 401 WITH the
    // challenge.
    let (s, h, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(h.contains_key("www-authenticate"));
}

#[tokio::test]
async fn denied_consumer_beats_allowed_set() {
    let yaml = config_with(
        "      allowed_consumers: [acme, beta]\n      denied_consumers: [acme]\n",
        &two_consumers(),
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "deny wins within one Authz");
    let (s, _, _) = send(&dp, vec![("x-api-key", "beta-key")]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn empty_allowed_consumers_admits_any_authenticated_caller() {
    let yaml = config_with("      denied_consumers: [beta]\n", &two_consumers(), "");
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = send(&dp, vec![("x-api-key", "beta-key")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Anonymous is still rejected (identity rules present).
    let (s, _, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

// ---- groups -------------------------------------------------------------------

#[tokio::test]
async fn group_rules_evaluate_config_consumer_memberships() {
    let yaml = config_with("      allowed_groups: [gold]\n", &two_consumers(), "");
    let dp = dataplane_from(&yaml);
    // acme is in gold.
    let (s, _, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::OK);
    // beta has no groups: never satisfies an allowed_groups rule
    // (store-only consumers share this limitation — documented).
    let (s, _, _) = send(&dp, vec![("x-api-key", "beta-key")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn denied_group_beats_allowed_group() {
    let yaml = config_with(
        "      allowed_groups: [gold, silver]\n      denied_groups: [gold]\n",
        &format!(
            "{}  - name: beta\n    groups: [silver]\n    credentials:\n      - type: \
             api_key\n        key: beta-key\n",
            one_consumer("acme", "acme-key", &["gold"])
        ),
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = send(&dp, vec![("x-api-key", "beta-key")]).await;
    assert_eq!(s, StatusCode::OK);
}

// ---- JWT scopes + claims ------------------------------------------------------

struct JwtAuthz {
    dp: Arc<DataPlane>,
    enc: EncodingKey,
    kid: String,
}

async fn jwt_authz_setup(authz: &str) -> JwtAuthz {
    let key = rcgen::KeyPair::generate().unwrap();
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    let der = key.public_key_der();
    let body = &der[der.len() - 65..];
    let jwk = std::sync::Arc::new(serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": B64URL.encode(&body[1..33]), "y": B64URL.encode(&body[33..65]),
        "kid": "key-1", "alg": "ES256", "use": "sig",
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let jwks_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            let jwk = Arc::clone(&jwk);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let jwk = Arc::clone(&jwk);
                    async move {
                        let body = serde_json::json!({ "keys": [*jwk.clone()] }).to_string();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    let yaml = config_with(
        authz,
        "consumers:\n  - name: acme\n    credentials:\n      - type: jwt\n        issuer: https://idp.example\n",
        "",
    );
    let yaml = format!(
        "jwt_providers:\n  - name: idp\n    jwks_url: http://127.0.0.1:{jwks_port}\n    \
         algorithms: [ES256]\n    issuer: https://idp.example\n    audience: dwara-api\n{yaml}"
    );
    let dp = dataplane_from(&yaml);
    JwtAuthz {
        dp,
        enc: EncodingKey::from_ec_der(&key.serialize_der()),
        kid: "key-1".to_string(),
    }
}

fn token(setup: &JwtAuthz, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(setup.kid.clone());
    jsonwebtoken::encode(&header, claims, &setup.enc).unwrap()
}

fn base_claims() -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    serde_json::json!({
        "iss": "https://idp.example", "aud": "dwara-api", "sub": "user-1",
        "exp": now + 3600, "tenant": "acme",
    })
}

async fn bearer(setup: &JwtAuthz, claims: &serde_json::Value) -> (StatusCode, HeaderMap, String) {
    let tok = token(setup, claims);
    send(&setup.dp, vec![("authorization", &format!("Bearer {tok}"))]).await
}

#[tokio::test]
async fn required_scopes_accept_space_separated_and_array_claims() {
    let setup = jwt_authz_setup("      required_scopes: [read, write]\n").await;
    // Space-separated string claim.
    let mut claims = base_claims();
    claims["scope"] = serde_json::json!("read admin write");
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::OK, "space-separated scope claim must pass");
    // JSON array claim (flattened by authn to the same form).
    let mut claims = base_claims();
    claims["scope"] = serde_json::json!(["read", "write"]);
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::OK, "array scope claim must pass");
    // Missing one required scope.
    let mut claims = base_claims();
    claims["scope"] = serde_json::json!("read");
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // No scope claim at all.
    let (s, _, _) = bearer(&setup, &base_claims()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn required_claims_exact_match_and_absent() {
    let setup = jwt_authz_setup("      required_claims: { tenant: acme }\n").await;
    let (s, _, _) = bearer(&setup, &base_claims()).await;
    assert_eq!(s, StatusCode::OK);
    // Wrong value.
    let mut claims = base_claims();
    claims["tenant"] = serde_json::json!("other");
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Claim absent.
    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("tenant");
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// ---- IP ACL -------------------------------------------------------------------

#[tokio::test]
async fn ip_acl_allow_list_with_open_default() {
    let yaml = config_with(
        "      ip_acl:\n        allow: [10.0.0.0/8]\n",
        &two_consumers(),
        "",
    );
    let dp = dataplane_from(&yaml);
    // Peer inside the allow list: admitted (and anonymous — ip_acl-only
    // is the one anonymous-permitting shape).
    let (s, _, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::OK);
    // Peer outside both lists: default allow.
    let (s, _, _) = send_from(&dp, ip(203, 0, 113, 5), vec![]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn ip_acl_deny_list_wins_over_allow_list() {
    let yaml = config_with(
        "      ip_acl:\n        allow: [10.0.0.0/8]\n        deny: [10.9.9.9]\n",
        &two_consumers(),
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send_from(&dp, ip(10, 9, 9, 9), vec![]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "deny entry beats the allow CIDR");
    let (s, _, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn ip_acl_closed_default_denies_unmatched() {
    let yaml = config_with(
        "      ip_acl:\n        allow: [10.0.0.0/8]\n        default: deny\n",
        &two_consumers(),
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::OK);
    let (s, h, _) = send_from(&dp, ip(192, 0, 2, 1), vec![]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "closed mode: only the allow list passes"
    );
    assert!(!h.contains_key("www-authenticate"));
}

#[tokio::test]
async fn ip_acl_evaluates_the_effective_client_ip_behind_trusted_proxies() {
    // Peer 10.0.0.1 is a trusted proxy; the XFF chain resolves the
    // client to 198.51.100.7 (rightmost non-trusted entry).
    let yaml = config_with(
        "      ip_acl:\n        allow: [198.51.100.0/24]\n        default: deny\n",
        &two_consumers(),
        "  - 10.0.0.0/8\n",
    );
    let dp = dataplane_from(&yaml);
    // Trusted proxy + XFF client inside the allow list: admitted.
    let (s, _, _) = send(&dp, vec![("x-forwarded-for", "198.51.100.7, 10.0.0.5")]).await;
    assert_eq!(s, StatusCode::OK);
    // Trusted proxy + XFF client OUTSIDE the allow list: 403 (the XFF
    // client, not the trusted peer, is evaluated).
    let (s, _, _) = send(&dp, vec![("x-forwarded-for", "203.0.113.9")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // No XFF at all: effective IP is the trusted peer itself, outside
    // the allow list.
    let (s, _, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn spoofed_xff_from_untrusted_peer_is_ignored() {
    // No trusted proxies: the peer is the effective IP whatever the XFF
    // claims.
    let yaml = config_with(
        "      ip_acl:\n        allow: [10.0.0.0/8]\n        default: deny\n",
        &two_consumers(),
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send_from(
        &dp,
        ip(203, 0, 113, 5),
        vec![("x-forwarded-for", "10.0.0.1")],
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "untrusted peer cannot spoof its way into the allow list"
    );
}

#[tokio::test]
async fn ip_acl_only_route_admits_anonymous_from_allowed_ip_only() {
    let yaml = config_with(
        "      ip_acl:\n        allow: [10.0.0.0/8]\n        default: deny\n",
        "",
        "",
    );
    let dp = dataplane_from(&yaml);
    // Anonymous from the allowed network: admitted (the documented
    // anonymous-permitting case).
    let (s, _, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::OK);
    // Anonymous from elsewhere: 403, NOT 401.
    let (s, h, _) = send_from(&dp, ip(198, 51, 100, 1), vec![]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(!h.contains_key("www-authenticate"));
}

// ---- tester additions: edge coverage (DW-020 dispatch #21) --------------------
//
// Covers the gaps left by the initial suite: authz-vs-rate-limit
// ordering, auth_required interplay, empty-ACL closed mode for
// authenticated callers, IPv6 XFF/CIDR handling, the IPv4-mapped-IPv6
// family boundary, CIDR /0, superset scope arrays, numeric and
// non-scalar claim matching.

/// Full-config variant of [`config_with`] with extra route fields
/// (`auth_required`, `policies`) and a `policies:` section.
fn config_full(
    authz: &str,
    extra_route: &str,
    consumers: &str,
    trusted: &str,
    policies: &str,
) -> String {
    let trusted = if trusted.is_empty() {
        String::new()
    } else {
        format!("trusted_proxies:\n{trusted}")
    };
    let policies = if policies.is_empty() {
        String::new()
    } else {
        format!("policies:\n{policies}")
    };
    format!(
        "{trusted}{policies}listeners: []
routes:
  - name: r
    service: svc
{extra_route}    match:
      path: {{ type: regex, value: /.* }}
    action: {{ type: respond, status: 200 }}
    authorization:
{authz}services:
  - name: svc
    upstream: pool
upstreams:
  - name: pool
    endpoints:
      - address: 127.0.0.1
        port: 1
{consumers}"
    )
}

#[tokio::test]
async fn authz_denial_precedes_rate_limiting_and_consumes_no_budget() {
    // Ordering: authN -> authz -> rate limit. A 403 returns before the
    // rate-limit engine runs, so denied requests carry no rate headers
    // and never consume budget under a `credential`-keyed policy.
    let yaml = config_full(
        "      ip_acl:\n        deny: [10.9.9.9]\n",
        "    policies: [per-cred]\n",
        &two_consumers(),
        "  - 10.0.0.0/8\n",
        "  - name: per-cred\n    rate_limits:\n      - selector: \
         [credential]\n        requests_per: { minute: 2 }\n",
    );
    let dp = dataplane_from(&yaml);
    // Four denied requests (effective IP 10.9.9.9 is deny-listed):
    // 403 each, and no X-RateLimit-* headers on any of them.
    for _ in 0..4 {
        let (s, h, _) = send(
            &dp,
            vec![("x-api-key", "acme-key"), ("x-forwarded-for", "10.9.9.9")],
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(
            !h.contains_key("x-ratelimit-limit"),
            "an authz 403 is emitted before the rate-limit engine runs"
        );
    }
    // The same consumer (same rate key) is now allowed twice: had the
    // four 403s consumed budget, the FIRST of these would already 429.
    let (s, h, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.get("x-ratelimit-remaining").unwrap(), "1");
    let (s, h, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.get("x-ratelimit-remaining").unwrap(), "0");
    let (s, _, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_required_governs_anonymous_before_ip_deny() {
    // authN runs before authz: an anonymous request on an
    // auth_required route answers 401 even when its IP would also be
    // denied; an authenticated caller on the same route gets the authz
    // 403 (the IP gate applies regardless of identity).
    let yaml = config_full(
        "      ip_acl:\n        default: deny\n",
        "    auth_required: true\n",
        &two_consumers(),
        "",
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, h, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "authN gate precedes authz");
    assert!(h.contains_key("www-authenticate"));
    let (s, h, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "authenticated caller hits the closed IP ACL"
    );
    assert!(!h.contains_key("www-authenticate"));
}

#[tokio::test]
async fn empty_acl_with_default_deny_blocks_anonymous_and_authenticated() {
    // Allow and deny lists both empty, default deny: EVERYTHING is 403,
    // anonymous and authenticated alike (IP rules apply regardless of
    // identity).
    let yaml = config_full(
        "      ip_acl:\n        default: deny\n",
        "",
        &two_consumers(),
        "",
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, h, _) = send(&dp, vec![]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(!h.contains_key("www-authenticate"), "403, not a 401");
    let (s, _, _) = send(&dp, vec![("x-api-key", "acme-key")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ipv6_xff_chain_resolves_against_ipv6_cidr_rules() {
    // client 2001:db8::5 -> proxy fd00::2 (trusted) -> gateway peer
    // fd00::1 (trusted): the XFF chain resolves to the IPv6 client and
    // an IPv6 CIDR allow rule matches it. An all-trusted chain falls
    // back to the leftmost entry, which is outside the allow list.
    let yaml = config_full(
        "      ip_acl:\n        allow: ['2001:db8::/32']\n        default: deny\n",
        "",
        "",
        "  - fd00::/8\n",
        "",
    );
    let dp = dataplane_from(&yaml);
    let peer: IpAddr = "fd00::1".parse().unwrap();
    let (s, _, _) = send_from(&dp, peer, vec![("x-forwarded-for", "2001:db8::5, fd00::2")]).await;
    assert_eq!(s, StatusCode::OK, "IPv6 client inside the IPv6 CIDR");
    let (s, _, _) = send_from(&dp, peer, vec![("x-forwarded-for", "fd00::9, fd00::2")]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "all-trusted chain falls back to the leftmost entry, outside the allow list"
    );
}

#[tokio::test]
async fn ipv4_mapped_ipv6_peer_does_not_match_an_ipv4_cidr() {
    // Family boundary: CIDR matching is same-family only, so a
    // ::ffff:x.x.x.x mapped peer does NOT fall inside an IPv4 CIDR.
    let yaml = config_full(
        "      ip_acl:\n        allow: [10.0.0.0/8]\n        default: deny\n",
        "",
        "",
        "",
        "",
    );
    let dp = dataplane_from(&yaml);
    let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    let (s, _, _) = send_from(&dp, mapped, vec![]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an IPv4-mapped IPv6 peer is not an IPv4 match"
    );
    // Control: the plain IPv4 address does match.
    let (s, _, _) = send_from(&dp, ip(10, 0, 0, 2), vec![]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn ipv4_allow_cidr_admits_only_ipv4_and_still_blocks_ipv6() {
    // Family boundary under the /0-in-allow prohibition: a normal IPv4
    // CIDR (10.0.0.0/8) admits IPv4 peers in range and denies IPv6
    // peers via the closed default — an IPv4 CIDR never matches IPv6.
    let yaml = config_full(
        "      ip_acl:\n        allow: [10.0.0.0/8]\n        default: deny\n",
        "",
        "",
        "",
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send_from(&dp, ip(10, 203, 0, 113), vec![]).await;
    assert_eq!(s, StatusCode::OK, "IPv4 peer inside the allow CIDR");
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let (s, _, _) = send_from(&dp, v6, vec![]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an IPv4 CIDR does not admit IPv6 peers (family boundary)"
    );
}

#[tokio::test]
async fn ipv6_allow_cidr_admits_only_ipv6_and_still_blocks_ipv4() {
    // The mirrored family boundary from the IPv6 side: an IPv6 CIDR
    // admits an IPv6 peer and denies an out-of-family IPv4 peer.
    let yaml = config_full(
        "      ip_acl:\n        allow: ['2001:db8::/32']\n        default: deny\n",
        "",
        "",
        "",
        "",
    );
    let dp = dataplane_from(&yaml);
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let (s, _, _) = send_from(&dp, v6, vec![]).await;
    assert_eq!(s, StatusCode::OK, "IPv6 peer inside the allow CIDR");
    let (s, _, _) = send_from(&dp, ip(10, 0, 0, 1), vec![]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an IPv6 CIDR does not admit IPv4 peers (family boundary)"
    );
}

#[test]
fn cidr_zero_in_allow_is_rejected_but_zero_in_deny_is_accepted() {
    // Policy (reviewer-advisory, now frozen): an allow-all entry
    // (0.0.0.0/0 or ::/0) in ip_acl.allow is always an authoring
    // mistake — validation rejects it at publish with steering toward
    // `default: allow`; the same /0 in the DENY list is meaningful
    // (deny-all) and passes.
    let publish = |authz: &str| {
        let yaml = config_full(authz, "", "", "", "");
        let gateway = parse_gateway(&yaml).expect("parses");
        let state = Arc::new(ConfigState::new());
        state.compile_and_publish(&gateway)
    };
    // IPv4 /0 in allow: rejected with the steering message.
    let err = publish("      ip_acl:\n        allow: [0.0.0.0/0]\n")
        .expect_err("/0 in allow must fail validation");
    match err {
        dwara_core::snapshot::CompileError::Validation(issues) => {
            let i = issues
                .iter()
                .find(|i| i.field == "authorization.ip_acl.allow[0]")
                .expect("issue names the allow entry");
            assert!(
                i.message.contains("default: allow"),
                "issue steers to 'default: allow': {}",
                i.message
            );
        }
        other => panic!("expected CompileError::Validation, got {other:?}"),
    }
    // IPv6 /0 in allow: same rejection.
    let err = publish("      ip_acl:\n        allow: ['::/0']\n")
        .expect_err("::/0 in allow must fail validation");
    assert!(matches!(
        err,
        dwara_core::snapshot::CompileError::Validation(_)
    ));
    // /0 in deny is valid (deny-all): publishes and denies an IPv4 peer.
    // Runtime half is below; here pin that publish succeeds.
    publish("      ip_acl:\n        deny: [0.0.0.0/0]\n").expect("/0 in deny is valid");
}

#[tokio::test]
async fn cidr_zero_in_deny_denies_all_of_its_family_only() {
    // The accepted /0 shape: deny-all for the entry's family. IPv4
    // peers are denied by 0.0.0.0/0; IPv6 peers are not matched by an
    // IPv4 /0 (family boundary) and fall through to the open default.
    let yaml = config_full(
        "      ip_acl:\n        deny: [0.0.0.0/0]\n        default: allow\n",
        "",
        "",
        "",
        "",
    );
    let dp = dataplane_from(&yaml);
    let (s, _, _) = send_from(&dp, ip(203, 0, 113, 9), vec![]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "IPv4 /0 deny denies every IPv4");
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let (s, _, _) = send_from(&dp, v6, vec![]).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "an IPv4 /0 deny does not deny IPv6 peers (family boundary)"
    );
}

#[tokio::test]
async fn array_scope_claim_with_extra_scopes_is_a_passing_superset() {
    let setup = jwt_authz_setup("      required_scopes: [read, write]\n").await;
    let mut claims = base_claims();
    claims["scope"] = serde_json::json!(["admin", "read", "write", "extra"]);
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "a granted-scope superset of the required AND-set passes"
    );
}

#[tokio::test]
async fn numeric_claim_matches_its_stringified_requirement() {
    // authn stringifies number-valued claims, so required_claims "123"
    // matches a JSON number 123 (exact string equality after
    // stringification — pinned).
    let setup = jwt_authz_setup("      required_claims: { level: '123' }\n").await;
    let mut claims = base_claims();
    claims["level"] = serde_json::json!(123);
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::OK);
    let mut claims = base_claims();
    claims["level"] = serde_json::json!(124);
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_scalar_claims_never_match_except_flattened_string_arrays() {
    let setup = jwt_authz_setup("      required_claims: { perms: admin }\n").await;
    // Nested object: dropped by authn -> required claim absent -> 403.
    let mut claims = base_claims();
    claims["perms"] = serde_json::json!({ "role": "admin" });
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "object claims never match");
    // Array of numbers: dropped (only all-string arrays are flattened).
    let mut claims = base_claims();
    claims["perms"] = serde_json::json!([1, 2]);
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-string arrays never match");
    // Array of strings: flattened space-separated, exact match only.
    let mut claims = base_claims();
    claims["perms"] = serde_json::json!(["admin"]);
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "a single-element string array flattens to the exact value"
    );
    let mut claims = base_claims();
    claims["perms"] = serde_json::json!(["admin", "ops"]);
    let (s, _, _) = bearer(&setup, &claims).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "flattened 'admin ops' is not the exact required string"
    );
}

// ---- validation ---------------------------------------------------------------

#[test]
fn validation_rejects_bad_ip_entries_and_unresolved_refs() {
    let base = |authz: &str| config_with(authz, &two_consumers(), "");
    let publish = |yaml: &str| {
        let gateway = parse_gateway(yaml).expect("parses");
        dwara_core::snapshot::validate(&gateway)
    };
    // Bad CIDR.
    let issues = publish(&base("      ip_acl:\n        allow: [10.0.0.0/99]\n"));
    assert!(issues.iter().any(|i| i.field.contains("ip_acl")));
    // Unknown consumer ref.
    let issues = publish(&base("      allowed_consumers: [ghost]\n"));
    assert!(issues
        .iter()
        .any(|i| i.field == "authorization.allowed_consumers"));
    // Unknown group ref.
    let issues = publish(&base("      denied_groups: [nogroup]\n"));
    assert!(issues
        .iter()
        .any(|i| i.field == "authorization.denied_groups"));
    // Well-formed block: no authorization issues.
    let issues = publish(&base(
        "      allowed_consumers: [acme]\n      ip_acl:\n        deny: [10.0.0.99]\n",
    ));
    assert!(!issues.iter().any(|i| i.field.contains("authorization")));
}
