//! Complementary tests for config schema v1: enum coverage, defaults,
//! deep error paths, boundary values, and normalization idempotence.
//! Fixtures are inline strings; only behaviors not covered by
//! tests/config_schema.rs appear here.

use dwara_core::config::{
    gateway_to_yaml, json_schema, parse_gateway, Credential, Gateway, ListenerProtocol,
    LoadBalancer, PathMatchKind, RouteAction, TlsMode, UpstreamProtocol,
};

fn parse_ok(text: &str) -> Gateway {
    parse_gateway(text).unwrap_or_else(|e| panic!("expected valid config, got: {e}"))
}

fn parse_err(text: &str) -> dwara_core::config::ConfigError {
    match parse_gateway(text) {
        Err(e) => e,
        Ok(_) => panic!("expected invalid config, but it parsed"),
    }
}

// --- Enum coverage -----------------------------------------------------------

#[test]
fn all_load_balancer_variants_parse() {
    for (tag, expected) in [
        ("round_robin", LoadBalancer::RoundRobin),
        ("least_requests", LoadBalancer::LeastRequests),
        ("random", LoadBalancer::Random),
        ("ip_hash", LoadBalancer::IpHash),
    ] {
        let gw = parse_ok(&format!(
            "upstreams:\n  - name: u\n    load_balancer: {tag}\n    endpoints: []\n"
        ));
        assert_eq!(gw.upstreams[0].load_balancer, expected, "tag {tag}");
    }
}

#[test]
fn load_balancer_rejects_unknown_variant_with_path() {
    let err =
        parse_err("upstreams:\n  - name: u\n    load_balancer: round-robin\n    endpoints: []\n");
    assert_eq!(err.path, "upstreams[0].load_balancer");
    assert!(
        err.message.contains("round-robin"),
        "message: {}",
        err.message
    );
}

#[test]
fn all_upstream_protocol_variants_parse() {
    for (tag, expected) in [
        ("http1", UpstreamProtocol::Http1),
        ("http2", UpstreamProtocol::Http2),
        ("https", UpstreamProtocol::Https),
    ] {
        let gw = parse_ok(&format!(
            "upstreams:\n  - name: u\n    protocol: {tag}\n    endpoints: []\n"
        ));
        assert_eq!(gw.upstreams[0].protocol, expected, "tag {tag}");
    }
}

#[test]
fn all_path_match_kinds_parse() {
    for (tag, value, expected) in [
        ("exact", "/healthz", PathMatchKind::Exact),
        ("prefix", "/v1/", PathMatchKind::Prefix),
        ("regex", "/v1/.*", PathMatchKind::Regex),
    ] {
        let gw = parse_ok(&format!(
            "routes:\n  - name: r\n    service: s\n    match:\n      path:\n        type: {tag}\n        value: {value}\n    action: {{type: proxy}}\n"
        ));
        assert_eq!(gw.routes[0].r#match.path.kind, expected, "tag {tag}");
    }
}

#[test]
fn path_match_rejects_unknown_kind_with_path() {
    let err = parse_err(
        "routes:\n  - name: r\n    service: s\n    match:\n      path:\n        type: glob\n        value: /x\n    action: {type: proxy}\n",
    );
    assert_eq!(err.path, "routes[0].match.path.type");
}

#[test]
fn tls_mode_passthrough_parses_and_terminate_defaults() {
    let gw = parse_ok(
        "listeners:\n  - name: a\n    address: 0.0.0.0\n    port: 443\n    tls: {mode: passthrough}\n  - name: b\n    address: 0.0.0.0\n    port: 8443\n    tls: {}\n",
    );
    assert_eq!(
        gw.listeners[0].tls.as_ref().unwrap().mode,
        TlsMode::Passthrough
    );
    // Omitted mode defaults to terminate.
    assert_eq!(
        gw.listeners[1].tls.as_ref().unwrap().mode,
        TlsMode::Terminate
    );
}

#[test]
fn tls_rejects_unknown_mode() {
    let err = parse_err(
        "listeners:\n  - name: a\n    address: 0.0.0.0\n    port: 443\n    tls: {mode: both}\n",
    );
    assert_eq!(err.path, "listeners[0].tls.mode");
}

#[test]
fn listener_protocol_https_parses_and_http_defaults() {
    let gw = parse_ok(
        "listeners:\n  - name: a\n    address: 0.0.0.0\n    port: 1\n    protocol: https\n  - name: b\n    address: 0.0.0.0\n    port: 2\n",
    );
    assert_eq!(gw.listeners[0].protocol, ListenerProtocol::Https);
    assert_eq!(gw.listeners[1].protocol, ListenerProtocol::Http);
}

#[test]
fn all_credential_variants_parse() {
    let gw = parse_ok(
        "consumers:\n  - name: c\n    credentials:\n      - {type: api_key, key: k}\n      - {type: jwt, issuer: https://iss}\n      - {type: jwt, issuer: https://iss, audiences: [a, b]}\n      - {type: mtls, fingerprint: sha256:ab}\n",
    );
    let creds = &gw.consumers[0].credentials;
    assert_eq!(creds[0], Credential::ApiKey { key: "k".into() });
    assert_eq!(
        creds[1],
        Credential::Jwt {
            issuer: "https://iss".into(),
            audiences: vec![]
        }
    );
    assert_eq!(
        creds[2],
        Credential::Jwt {
            issuer: "https://iss".into(),
            audiences: vec!["a".into(), "b".into()]
        }
    );
    assert_eq!(
        creds[3],
        Credential::Mtls {
            fingerprint: "sha256:ab".into()
        }
    );
}

#[test]
fn credential_rejects_unknown_tag_with_path() {
    let err = parse_err("consumers:\n  - name: c\n    credentials:\n      - {type: oauth}\n");
    // Tag failure is reported at the tag field.
    assert!(
        err.path.starts_with("consumers[0].credentials[0]"),
        "path: {}",
        err.path
    );
}

#[test]
fn credential_rejects_unknown_field_inside_variant() {
    let err = parse_err(
        "consumers:\n  - name: c\n    credentials:\n      - {type: api_key, key: k, extra: 1}\n",
    );
    assert!(
        err.path.starts_with("consumers[0].credentials[0]"),
        "path: {}",
        err.path
    );
    assert!(err.message.contains("extra"), "message: {}", err.message);
}

#[test]
fn route_action_rejects_unknown_tag_with_path() {
    let err = parse_err(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {type: exact, value: /}\n    action: {type: teapot}\n",
    );
    assert!(
        err.path.starts_with("routes[0].action"),
        "path: {}",
        err.path
    );
}

#[test]
fn route_action_proxy_is_keyed_map_not_plain_string() {
    // A plain string action must be rejected: action is keyed `type: proxy`.
    let err = parse_err(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {type: exact, value: /}\n    action: proxy\n",
    );
    assert!(
        err.path.starts_with("routes[0].action"),
        "path: {}",
        err.path
    );
}

#[test]
fn route_action_respond_minimal_fields() {
    let gw = parse_ok(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {type: exact, value: /}\n    action: {type: respond, status: 503}\n",
    );
    assert_eq!(
        gw.routes[0].action,
        RouteAction::Respond {
            status: 503,
            body: None,
            headers: Default::default(),
        }
    );
}

#[test]
fn route_action_proxy_empty_map_parses_to_proxy_variant() {
    // Post-fix world: `{type: proxy}` is an empty struct variant and must
    // still parse after deny_unknown_fields landed on the enum.
    let gw = parse_ok(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {type: exact, value: /}\n    action: {type: proxy}\n",
    );
    assert_eq!(gw.routes[0].action, RouteAction::Proxy { rewrite: None });
}

// --- Unknown-field rejection inside every RouteAction variant ------------------

#[test]
fn route_action_proxy_rejects_unknown_field_inside_variant() {
    // Regression for the unit-variant hole: `Proxy {}` used to silently
    // ignore extra keys even with deny_unknown_fields on the enum.
    let err = parse_err(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {type: exact, value: /}\n    action: {type: proxy, extraneous: 1}\n",
    );
    assert!(
        err.path.starts_with("routes[0].action"),
        "path: {}",
        err.path
    );
    assert!(
        err.message.contains("extraneous"),
        "message: {}",
        err.message
    );
}

#[test]
fn route_action_redirect_rejects_unknown_field_inside_variant() {
    let err = parse_err(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {type: exact, value: /}\n    action: {type: redirect, host: x, bogus: true}\n",
    );
    assert!(
        err.path.starts_with("routes[0].action"),
        "path: {}",
        err.path
    );
    assert!(err.message.contains("bogus"), "message: {}", err.message);
}

#[test]
fn route_action_respond_rejects_unknown_field_inside_variant() {
    let err = parse_err(
        "routes:\n  - name: r\n    service: s\n    match:\n      path: {type: exact, value: /}\n    action: {type: respond, status: 503, extra: x}\n",
    );
    assert!(
        err.path.starts_with("routes[0].action"),
        "path: {}",
        err.path
    );
    assert!(err.message.contains("extra"), "message: {}", err.message);
}

// --- Hostile YAML regression guards (serde_yaml_ng + typed schema) -------------

#[test]
fn alias_heavy_document_parses_without_panicking_or_hanging() {
    // ~50 aliases of one chunky mapping: the parser must expand (or reject)
    // aliases deterministically without exponential blowup or panic.
    let chunk = "  - &chunk\n      name: u\n      endpoints:\n        - {address: 10.0.0.1, port: 80}\n        - {address: 10.0.0.2, port: 80}\n        - {address: 10.0.0.3, port: 80}\n    ";
    let mut doc = String::from("upstreams:\n");
    doc.push_str(chunk);
    for _ in 0..50 {
        doc.push_str("\n  - *chunk");
    }
    doc.push('\n');
    // Deterministic behavior: valid aliases expand to real values.
    let gw = parse_ok(&doc);
    assert_eq!(gw.upstreams.len(), 51, "anchor + 50 aliases");
    assert_eq!(gw.upstreams[0], gw.upstreams[50]);
}

#[test]
fn deep_nesting_does_not_stack_overflow() {
    // ~1000 levels of flow-nested mappings under an unknown key: the parser
    // must return a clean error (unknown field) rather than crashing the
    // test thread with a stack overflow.
    let mut doc = String::from("listeners: []\n");
    let depth = 1000;
    for _ in 0..depth {
        doc.push_str("{a: ");
    }
    doc.push('1');
    for _ in 0..depth {
        doc.push('}');
    }
    doc.push('\n');
    let result = parse_gateway(&doc);
    assert!(
        result.is_err(),
        "deeply nested unknown key must be rejected, not accepted"
    );
}

// --- Defaults ----------------------------------------------------------------

#[test]
fn upstream_and_endpoint_defaults_apply() {
    let gw = parse_ok(
        "upstreams:\n  - name: u\n    endpoints:\n      - {address: 10.0.0.1, port: 80}\n",
    );
    let up = &gw.upstreams[0];
    assert_eq!(up.load_balancer, LoadBalancer::RoundRobin);
    assert_eq!(up.protocol, UpstreamProtocol::Http1);
    assert_eq!(up.endpoints[0].weight, 1, "weight defaults to 1");
    assert!(up.timeouts.is_none());
}

// --- Deep / nested error paths -----------------------------------------------

#[test]
fn wrong_type_deep_inside_route_match_reports_full_path() {
    let err = parse_err(
        "routes:\n  - name: r\n    service: s\n    match:\n      path:\n        type: exact\n        value: [not, a, string]\n    action: {type: proxy}\n",
    );
    assert_eq!(err.path, "routes[0].match.path.value");
}

#[test]
fn wrong_type_inside_credential_reports_full_path() {
    let err = parse_err(
        "consumers:\n  - name: c\n    credentials:\n      - {type: api_key, key: [oops]}\n",
    );
    // Path is variant-scoped; the tag lookup fails before the field is named.
    assert!(
        err.path.starts_with("consumers[0].credentials[0]"),
        "path: {}",
        err.path
    );
}

#[test]
fn unknown_field_inside_policy_is_rejected_with_path() {
    let err = parse_err("policies:\n  - name: p\n    circuit_breaker: {}\n");
    assert_eq!(err.path, "policies[0].circuit_breaker");
    assert!(
        err.message.contains("circuit_breaker"),
        "message: {}",
        err.message
    );
}

#[test]
fn wrong_type_inside_rate_limit_reports_full_path() {
    let err =
        parse_err("policies:\n  - name: p\n    rate_limit: {requests: many, window_seconds: 60}\n");
    assert_eq!(err.path, "policies[0].rate_limit.requests");
}

#[test]
fn error_display_includes_both_path_and_message() {
    let err = parse_err("listeners:\n  - name: a\n    address: 0.0.0.0\n    port: not-a-number\n");
    let msg = err.to_string();
    assert!(
        msg.contains("listeners[0].port"),
        "display missing path: {msg}"
    );
    assert!(
        !err.message.is_empty() && msg.contains(&err.message),
        "display missing message: {msg}"
    );
}

// --- Boundary values ----------------------------------------------------------

#[test]
fn port_boundaries_zero_and_max_are_valid() {
    let gw = parse_ok(
        "listeners:\n  - {name: a, address: 0.0.0.0, port: 0}\n  - {name: b, address: 0.0.0.0, port: 65535}\n",
    );
    assert_eq!(gw.listeners[0].port, 0);
    assert_eq!(gw.listeners[1].port, 65535);
}

#[test]
fn port_above_max_is_rejected() {
    let err = parse_err("listeners:\n  - {name: a, address: 0.0.0.0, port: 65536}\n");
    assert_eq!(err.path, "listeners[0].port");
}

#[test]
fn negative_port_is_rejected() {
    let err = parse_err("listeners:\n  - {name: a, address: 0.0.0.0, port: -1}\n");
    assert_eq!(err.path, "listeners[0].port");
}

#[test]
fn weight_zero_and_large_timeouts_parse() {
    let gw = parse_ok(
        "upstreams:\n  - name: u\n    endpoints:\n      - {address: 10.0.0.1, port: 80, weight: 0}\n    timeouts: {connect_ms: 0, read_ms: 0, write_ms: 0}\n",
    );
    assert_eq!(gw.upstreams[0].endpoints[0].weight, 0);
    assert_eq!(
        gw.upstreams[0].timeouts,
        Some(dwara_core::config::Timeouts {
            connect_ms: Some(0),
            read_ms: Some(0),
            write_ms: Some(0),
        })
    );
}

#[test]
fn empty_string_name_and_unicode_values_parse_unchanged() {
    let gw = parse_ok(
        "listeners:\n  - {name: \"\", address: 0.0.0.0, port: 1}\nroutes:\n  - name: \"routé-ключ\"\n    service: s\n    match:\n      path: {type: prefix, value: /日本語/}\n    action: {type: proxy}\n",
    );
    assert_eq!(gw.listeners[0].name, "");
    assert_eq!(gw.routes[0].name, "routé-ключ");
    assert_eq!(gw.routes[0].r#match.path.value, "/日本語/");
}

#[test]
fn empty_endpoints_array_is_valid() {
    let gw = parse_ok("upstreams:\n  - name: u\n    endpoints: []\n");
    assert!(gw.upstreams[0].endpoints.is_empty());
}

#[test]
fn absent_collection_equals_empty_collection() {
    let absent = parse_ok(
        "listeners: []\nroutes: []\nservices: []\nupstreams: []\nconsumers: []\npolicies: []\n",
    );
    let empty_doc = parse_ok("");
    assert_eq!(absent, empty_doc);
}

#[test]
fn empty_document_normalizes_to_empty_mapping() {
    // Normalization of an all-defaults gateway is stable and omits empties.
    let gw = parse_ok("");
    let once = gateway_to_yaml(&gw).expect("serialize");
    let twice = gateway_to_yaml(&parse_ok(&once)).unwrap();
    assert_eq!(once, twice);
}

// --- Duplicate YAML keys (documented serde_yaml_ng behavior) ------------------

#[test]
fn duplicate_mapping_keys_are_rejected_by_the_parser() {
    // serde_yaml_ng rejects duplicate keys in mappings rather than
    // last-wins. Documented here so a silent switch is noticed.
    let err = parse_err("listeners: []\nlisteners: []\n");
    assert!(
        err.message.contains("duplicate"),
        "expected duplicate-key rejection, got: {}",
        err.message
    );
}

#[test]
fn duplicate_keys_inside_a_listener_are_rejected() {
    let err = parse_err("listeners:\n  - {name: a, name: b, address: 0.0.0.0, port: 1}\n");
    assert!(
        err.message.contains("duplicate"),
        "expected duplicate-key rejection, got: {}",
        err.message
    );
}

// --- Normalization idempotence on constructed values --------------------------

#[test]
fn normalization_is_idempotent_for_constructed_gateway_with_all_variants() {
    use dwara_core::config::*;
    let gw = Gateway {
        trusted_proxies: vec![],
        listeners: vec![Listener {
            name: "l".into(),
            address: "0.0.0.0".into(),
            port: 65535,
            protocol: ListenerProtocol::Https,
            tls: Some(ListenerTls {
                mode: TlsMode::Passthrough,
                cert_file: None,
                key_file: None,
                certificates: vec![],
                sni_routes: vec![],
            }),
        }],
        routes: vec![Route {
            name: "r".into(),
            service: "s".into(),
            r#match: RouteMatch {
                path: PathMatch {
                    kind: PathMatchKind::Regex,
                    value: "/.*".into(),
                },
                host: None,
                methods: vec![],
                headers: Default::default(),
                query: vec![],
                cookies: vec![],
            },
            action: RouteAction::Redirect {
                scheme: None,
                host: Some("x".into()),
                path: None,
                status: 308,
            },
            policies: vec![],
            priority: None,
        }],
        services: vec![],
        upstreams: vec![Upstream {
            name: "u".into(),
            load_balancer: LoadBalancer::IpHash,
            protocol: UpstreamProtocol::Https,
            endpoints: vec![Endpoint {
                address: "10.0.0.1".into(),
                port: 0,
                weight: 0,
            }],
            connection_cap: None,
            slow_start_ms: None,
            health: None,
            active_health: None,
            retries: None,
            timeouts: None,
            breaker: None,
            max_pending: None,
        }],
        consumers: vec![Consumer {
            name: "c".into(),
            credentials: vec![Credential::Mtls {
                fingerprint: "f".into(),
            }],
            policies: vec![],
            priority: None,
        }],
        policies: vec![Policy {
            name: "p".into(),
            rate_limit: Some(RateLimit {
                requests: 0,
                window_seconds: 0,
            }),
            timeouts: None,
        }],
        max_concurrent_requests: None,
    };
    let once = gateway_to_yaml(&gw).expect("serialize");
    let reparsed = parse_gateway(&once).expect("normalized text reparses");
    assert_eq!(gw, reparsed);
    let twice = gateway_to_yaml(&reparsed).unwrap();
    assert_eq!(once, twice, "normalize(normalize(x)) != normalize(x)");
}

// --- Schema structural sanity --------------------------------------------------

#[test]
fn json_schema_defines_all_collection_types_and_tagged_enums() {
    let schema = json_schema();
    let text = serde_json::to_string(&schema).expect("schema serializes");
    // $defs entries for every vocabulary type.
    for def in [
        "Listener",
        "ListenerTls",
        "Route",
        "RouteMatch",
        "PathMatch",
        "Service",
        "Upstream",
        "Endpoint",
        "Timeouts",
        "Consumer",
        "Credential",
        "Policy",
        "RateLimit",
    ] {
        assert!(
            text.contains(&format!("\"{def}\"")),
            "schema $defs missing {def}"
        );
    }
    // Tagged enums surface their tags.
    for tag in [
        "\"proxy\"",
        "\"redirect\"",
        "\"respond\"",
        "\"api_key\"",
        "\"jwt\"",
        "\"mtls\"",
    ] {
        assert!(text.contains(tag), "schema missing enum tag {tag}");
    }
}
