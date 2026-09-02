//! Canary, sticky, and blue-green (DW-040), end to end: weighted
//! service splits distributing traffic across two upstreams at the
//! configured ratio (verified statistically — the issue's
//! acceptance), cookie affinity pinning a session to one branch and
//! (through the branch's ip_hash ring) one endpoint across requests
//! AND across a reload, and the blue-green weight flip switching 100%
//! of traffic with nothing but a config generation swap.
//!
//! Every backend is a real HTTP double echoing its own port, so both
//! the branch and the endpoint that served a request are directly
//! observable in the response body. The split's pick is a
//! deterministic hash (FNV-1a of the dispatch key), so the
//! statistical assertions hold on fixed input sets with margins that
//! cannot invert mid-run.

use std::sync::Arc;

use bytes::Bytes;
use dwara_core::config::parse_gateway;
use dwara_core::proxy::DataPlane;
use http_body_util::Full;
use hyper::{Method, Response, StatusCode};

mod support;

use support::{body_of, h1_client, spawn_gateway, uri};

/// Gateway YAML: one route -> one split service over `stable`
/// (ip_hash, two endpoints) and `canary` (one endpoint); sticky
/// optional.
fn split_yaml(
    stable1: u16,
    stable2: u16,
    canary: u16,
    stable_weight: u32,
    canary_weight: u32,
    sticky: bool,
) -> String {
    let sticky_block = if sticky {
        "  sticky:\n    cookie: dwara_affinity\n"
    } else {
        ""
    };
    format!(
        "routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: stable\n\
         \x20     weight: {stable_weight}\n\
         \x20   - upstream: canary\n\
         \x20     weight: {canary_weight}\n{sticky_block}\
         upstreams:\n\
         - name: stable\n\
         \x20 load_balancer: ip_hash\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {stable1}\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {stable2}\n\
         - name: canary\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {canary}\n"
    )
}

/// Drive `n` requests through the gateway; returns each response body
/// as text (the serving backend's identity) and its Set-Cookie (first
/// response only, when sticky mints one).
type Client = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    Full<Bytes>,
>;

async fn drive(
    client: &Client,
    gw: u16,
    n: usize,
    cookie: Option<&str>,
) -> Vec<(String, Option<String>)> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut builder = hyper::Request::builder()
            .method(Method::GET)
            .uri(uri(gw, "/api/x"));
        if let Some(c) = cookie {
            builder = builder.header("cookie", c);
        }
        let resp = client
            .request(builder.body(Full::<Bytes>::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        let set_cookie = resp
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (status, body) = body_of(resp).await;
        assert_eq!(status, StatusCode::OK);
        out.push((String::from_utf8_lossy(&body).into_owned(), set_cookie));
    }
    out
}

// --- 1. split ratios hold statistically ----------------------------------------

#[tokio::test]
async fn a_weighted_split_distributes_at_the_configured_ratio() {
    let stable1 = identity_backend_on("stable-1").await;
    let stable2 = identity_backend_on("stable-2").await;
    let canary = identity_backend_on("canary").await;
    let yaml = split_yaml(stable1, stable2, canary, 60, 40, false);
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    // 2000 requests, no cookies: per-request dispatch keys (request
    // ids) hash uniformly; the canary share is 40% ± 5pp (a band the
    // deterministic FNV spread cannot leave at this N, even under
    // parallel CI load).
    let results = drive(&client, gw, 2_000, None).await;
    let canary_n = results.iter().filter(|(body, _)| body == "canary").count();
    let stable_n = 2_000 - canary_n;
    assert!(
        (1_100..=1_300).contains(&stable_n),
        "stable share off: {stable_n}/2000"
    );
    assert!(
        (700..=900).contains(&canary_n),
        "canary share off: {canary_n}/2000"
    );

    // Both stable endpoints served (ip_hash over 2000 distinct keys).
    let s1 = results.iter().filter(|(b, _)| b == "stable-1").count();
    let s2 = results.iter().filter(|(b, _)| b == "stable-2").count();
    assert!(s1 > 400 && s2 > 400, "endpoint spread: {s1}/{s2}");

    // The decision is observable per branch.
    let rendered = dp.observability().render();
    assert!(rendered.contains("dwara_split_picks_total"), "{rendered}");
}

// --- 2. sessions stick ----------------------------------------------------------

#[tokio::test]
async fn a_sticky_session_pins_its_branch_and_endpoint_across_requests_and_reload() {
    let stable1 = identity_backend_on("stable-1").await;
    let stable2 = identity_backend_on("stable-2").await;
    let canary = identity_backend_on("canary").await;
    let yaml = split_yaml(stable1, stable2, canary, 50, 50, true);
    let state = support::state_from(&yaml);
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    // First request: a cookie is minted and the branch picked IS the
    // branch the cookie pins (stickiness from the very first response).
    let first = drive(&client, gw, 1, None).await;
    let set_cookie = first[0].1.clone().expect("affinity cookie set");
    let value = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .expect("cookie has a value");
    let cookie_header = format!("dwara_affinity={value}");
    assert!(set_cookie.contains("Max-Age=3600"), "{set_cookie}");

    // Many requests WITH the cookie: one branch, one endpoint (the
    // stable branch is ip_hash and the cookie is its ring key).
    let pinned = drive(&client, gw, 40, Some(&cookie_header)).await;
    let identities: std::collections::BTreeSet<&str> =
        pinned.iter().map(|(b, _)| b.as_str()).collect();
    assert_eq!(
        identities.len(),
        1,
        "the session pinned one branch+endpoint: {identities:?}"
    );
    assert!(
        pinned.iter().all(|(_, c)| c.is_none()),
        "an existing cookie is never re-set"
    );
    assert_eq!(
        *identities.iter().next().unwrap(),
        first[0].0,
        "the pinned target is the one that served the first response"
    );

    // Across a reload (same weights): the same cookie, the same target.
    state
        .compile_and_publish(&parse_gateway(&yaml).unwrap())
        .expect("republish");
    dp.refresh();
    let after = drive(&client, gw, 20, Some(&cookie_header)).await;
    assert!(
        after.iter().all(|(b, _)| b == &first[0].0),
        "stickiness survives a reload"
    );
}

// --- 3. blue-green: the instant flip ---------------------------------------------

#[tokio::test]
async fn a_blue_green_flip_moves_all_traffic_by_generation_swap() {
    let stable1 = identity_backend_on("stable-1").await;
    let stable2 = identity_backend_on("stable-2").await;
    let canary = identity_backend_on("canary").await;
    let blue = split_yaml(stable1, stable2, canary, 100, 0, false);
    let state = support::state_from(&blue);
    let dp = DataPlane::new(Arc::clone(&state));
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    // Blue: 100/0 — everything stable.
    let blue_results = drive(&client, gw, 100, None).await;
    assert!(
        blue_results.iter().all(|(b, _)| b.starts_with("stable")),
        "100/0 means blue serves everything"
    );

    // The flip is a config swap: green weights, republish, refresh.
    let green = split_yaml(stable1, stable2, canary, 0, 100, false);
    state
        .compile_and_publish(&parse_gateway(&green).unwrap())
        .expect("green publish");
    dp.refresh();

    // Green: 0/100 — everything canary, no restart, effective on the
    // very next request.
    let green_results = drive(&client, gw, 100, None).await;
    assert!(
        green_results.iter().all(|(b, _)| b == "canary"),
        "0/100 means green serves everything after the swap"
    );
}

/// A real HTTP backend whose body is the fixed `identity` string: the
/// serving probe. (Distinct from `identity_backend`: the identity is
/// the label, not the port.)
async fn identity_backend_on(identity: &'static str) -> u16 {
    support::spawn_backend_full(Arc::new(move |_req| {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(identity.as_bytes())))
            .unwrap()
    }))
    .await
}

// --- 4. sticky branch pinning is independent of the branch balancer -----------

#[tokio::test]
async fn sticky_pins_the_branch_even_when_the_branch_is_round_robin() {
    // Branch affinity is the cookie's guarantee; endpoint affinity
    // additionally requires the branch to run ip_hash (documented).
    // With round_robin branches, the BRANCH still sticks — endpoints
    // may spread within it, which is the documented trade.
    let b1 = identity_backend_on("blue-1").await;
    let b2 = identity_backend_on("blue-2").await;
    let g1 = identity_backend_on("green-1").await;
    let g2 = identity_backend_on("green-2").await;
    let yaml = format!(
        "routes:\n\
         - name: api\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 split:\n\
         \x20   targets:\n\
         \x20   - upstream: blue\n\
         \x20     weight: 50\n\
         \x20   - upstream: green\n\
         \x20     weight: 50\n\
         \x20 sticky:\n\
         \x20   cookie: dwara_affinity\n\
         upstreams:\n\
         - name: blue\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {b1}\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {b2}\n\
         - name: green\n\
         \x20 endpoints:\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {g1}\n\
         \x20   - address: 127.0.0.1\n\
         \x20     port: {g2}\n"
    );
    let dp = support::dataplane_from(&yaml);
    let gw = spawn_gateway(Arc::clone(&dp)).await;
    let client = h1_client();

    let first = drive(&client, gw, 1, None).await;
    let value = first[0]
        .1
        .as_deref()
        .and_then(|c| c.split(';').next())
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .expect("cookie minted");
    let cookie = format!("dwara_affinity={value}");
    let pinned_branch = first[0].0.split('-').next().unwrap().to_string();

    let results = drive(&client, gw, 50, Some(&cookie)).await;
    assert!(
        results.iter().all(|(b, _)| b.starts_with(&pinned_branch)),
        "the branch sticks regardless of its balancer"
    );
    // Within the branch, round_robin is free to spread (both endpoints
    // serve) — that spread IS the documented behavior difference from
    // an ip_hash branch, so assert it appears.
    let endpoints: std::collections::BTreeSet<&str> =
        results.iter().map(|(b, _)| b.as_str()).collect();
    assert!(
        endpoints.len() >= 2,
        "round_robin spreads within the pinned branch: {endpoints:?}"
    );
}
