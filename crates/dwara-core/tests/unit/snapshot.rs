//! Unit tests for `snapshot` (relocated from src).

use dwara_core::config::{
    Endpoint, Gateway, Listener, ListenerProtocol, LoadBalancer, PathMatch, PathMatchKind,
    PathRewrite, Route, RouteAction, RouteMatch, Service, Upstream, UpstreamProtocol,
};
use dwara_core::snapshot::*;

fn good_gateway() -> Gateway {
    Gateway {
        trusted_proxies: vec![],
        listeners: vec![Listener {
            name: "main".into(),
            address: "0.0.0.0".into(),
            port: 8080,
            protocol: ListenerProtocol::Http,
            tls: None,
        }],
        routes: vec![
            Route {
                name: "users-get".into(),
                service: "users-api".into(),
                r#match: RouteMatch {
                    path: PathMatch {
                        kind: PathMatchKind::Exact,
                        value: "/v1/users/{id}".into(),
                    },
                    host: None,
                    methods: vec![],
                    headers: Default::default(),
                    query: vec![],
                    cookies: vec![],
                },
                action: RouteAction::Proxy { rewrite: None },
                policies: vec![],
                priority: None,
                auth_required: false,
                authorization: None,
            },
            Route {
                name: "static".into(),
                service: "users-api".into(),
                r#match: RouteMatch {
                    path: PathMatch {
                        kind: PathMatchKind::Prefix,
                        value: "/static".into(),
                    },
                    host: None,
                    methods: vec![],
                    headers: Default::default(),
                    query: vec![],
                    cookies: vec![],
                },
                action: RouteAction::Proxy { rewrite: None },
                policies: vec![],
                priority: None,
                auth_required: false,
                authorization: None,
            },
            Route {
                name: "legacy".into(),
                service: "users-api".into(),
                r#match: RouteMatch {
                    path: PathMatch {
                        kind: PathMatchKind::Regex,
                        value: r"/old/(foo|bar)".into(),
                    },
                    host: None,
                    methods: vec![],
                    headers: Default::default(),
                    query: vec![],
                    cookies: vec![],
                },
                action: RouteAction::Proxy { rewrite: None },
                policies: vec![],
                priority: None,
                auth_required: false,
                authorization: None,
            },
        ],
        services: vec![Service {
            name: "users-api".into(),
            upstream: "users-pool".into(),
            base_path: None,
            version: None,
            policies: vec![],
        }],
        upstreams: vec![Upstream {
            name: "users-pool".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: vec![Endpoint {
                address: "127.0.0.1".into(),
                port: 9001,
                weight: 1,
            }],
            connection_cap: None,
            slow_start_ms: None,
            health: None,
            active_health: None,
            retries: None,
            timeouts: None,
            breaker: None,
            max_pending: None,
            trusted_ca_file: None,
        }],
        consumers: vec![],
        policies: vec![],
        max_concurrent_requests: None,
        jwt_providers: Vec::new(),
        admin: None,
    }
}

#[test]
fn validate_reports_all_semantic_issues() {
    let mut gw = good_gateway();
    // Duplicate service name, dangling upstream ref, unknown policy,
    // duplicate listener port.
    gw.services.push(gw.services[0].clone());
    gw.services[0].upstream = "missing-pool".into();
    gw.routes[0].policies.push("nope".into());
    gw.listeners.push(Listener {
        name: "dupe".into(),
        address: "0.0.0.0".into(),
        port: 8080,
        protocol: ListenerProtocol::Http,
        tls: None,
    });
    let issues = validate(&gw);
    assert!(issues
        .iter()
        .any(|i| i.entity == "service" && i.field == "upstream"));
    assert!(issues
        .iter()
        .any(|i| i.entity == "service" && i.field == "name"));
    assert!(issues
        .iter()
        .any(|i| i.entity == "route" && i.field == "policies"));
    assert!(issues
        .iter()
        .any(|i| i.entity == "listener" && i.field == "port"));
    assert!(validate(&good_gateway()).is_empty());
}

#[test]
fn compile_builds_route_table_with_precedence() {
    let gw = good_gateway();
    let compiled = compile(&gw).expect("good config compiles");
    let rt = compiled.route_table();
    assert_eq!(rt.find("/v1/users/42"), Some(0), "exact/param match");
    assert_eq!(rt.find("/static/app.js"), Some(1), "prefix match");
    assert_eq!(rt.find("/static/css/a.css"), Some(1));
    assert_eq!(rt.find("/old/foo"), Some(2), "regex match");
    assert_eq!(rt.find("/healthz"), None, "no route");
    assert_ne!(compiled.content_hash(), 0);
}

#[test]
fn compile_rejects_invalid_regex() {
    let mut gw = good_gateway();
    gw.routes[2].r#match.path.value = "/old/(unclosed".into();
    match compile(&gw) {
        Err(CompileError::InvalidRegex { route, .. }) => assert_eq!(route, "legacy"),
        other => panic!("expected InvalidRegex, got {other:?}"),
    }
}

#[test]
fn compile_rejects_invalid_rewrite_regex_and_exposes_it_for_lookup() {
    let mut gw = good_gateway();
    gw.routes[0].action = RouteAction::Proxy {
        rewrite: Some(PathRewrite::Regex {
            pattern: "/bad/(unclosed".into(),
            substitution: "/x/$1".into(),
        }),
    };
    match compile(&gw) {
        Err(CompileError::InvalidRegex { route, .. }) => assert_eq!(route, "users-get"),
        other => panic!("expected InvalidRegex, got {other:?}"),
    }

    // Happy path: a compiling rewrite regex is stored for request-time
    // lookup (never compiled per request).
    gw.routes[0].action = RouteAction::Proxy {
        rewrite: Some(PathRewrite::Regex {
            pattern: r"/v1/users/(\d+)".into(),
            substitution: "/u/$1".into(),
        }),
    };
    let compiled = compile(&gw).expect("compiling rewrite regex");
    assert!(compiled.route_table().rewrite_regex(0).is_some());
    assert!(compiled.route_table().rewrite_regex(1).is_none());
}

#[test]
fn validate_rejects_malformed_rewrites_and_respond_headers() {
    let mut gw = good_gateway();
    gw.routes[0].action = RouteAction::Proxy {
        rewrite: Some(PathRewrite::ReplacePrefix {
            prefix: "api".into(),
            replacement: "/internal".into(),
        }),
    };
    assert!(validate(&gw)
        .iter()
        .any(|i| i.field == "action.rewrite.prefix"));

    let mut gw = good_gateway();
    gw.routes[0].action = RouteAction::Respond {
        status: 200,
        body: None,
        headers: [("bad header".to_string(), "v".to_string())].into(),
    };
    assert!(validate(&gw).iter().any(|i| i.field == "action.headers"));
}

#[test]
fn validate_rejects_malformed_rate_limit_rules() {
    use dwara_core::config::{Policy, RateLimitRule, RateLimitSelector, RateRequestsPer};
    fn rule(
        selector: Vec<RateLimitSelector>,
        requests_per: RateRequestsPer,
        burst: Option<u32>,
    ) -> RateLimitRule {
        RateLimitRule {
            name: None,
            selector,
            requests_per,
            burst,
        }
    }
    let full = || RateRequestsPer {
        per_second: Some(10),
        minute: Some(100),
        hour: Some(1_000),
    };
    fn with_policy(mut gw: Gateway) -> Gateway {
        gw.policies = vec![Policy {
            name: "p".into(),
            rate_limit: None,
            rate_limits: vec![],
            timeouts: None,
        }];
        gw
    }
    // Baseline: a well-formed rule adds no issues.
    let mut gw = with_policy(good_gateway());
    gw.policies[0].rate_limits = vec![rule(vec![RateLimitSelector::Ip], full(), Some(20))];
    assert!(!validate(&gw)
        .iter()
        .any(|i| i.field.contains("rate_limits")));

    // Empty selector.
    let mut gw = with_policy(good_gateway());
    gw.policies[0].rate_limits = vec![rule(vec![], full(), None)];
    assert!(validate(&gw)
        .iter()
        .any(|i| i.field == "rate_limits[0].selector"));

    // No window at all.
    let mut gw = with_policy(good_gateway());
    gw.policies[0].rate_limits = vec![rule(
        vec![RateLimitSelector::Route],
        RateRequestsPer::default(),
        None,
    )];
    assert!(validate(&gw)
        .iter()
        .any(|i| i.field == "rate_limits[0].requests_per"));

    // A zero window rate.
    let mut gw = with_policy(good_gateway());
    gw.policies[0].rate_limits = vec![rule(
        vec![RateLimitSelector::Route],
        RateRequestsPer {
            per_second: Some(0),
            ..RateRequestsPer::default()
        },
        None,
    )];
    assert!(validate(&gw)
        .iter()
        .any(|i| i.field == "rate_limits[0].requests_per.s"));

    // Burst of zero.
    let mut gw = with_policy(good_gateway());
    gw.policies[0].rate_limits = vec![rule(vec![RateLimitSelector::Ip], full(), Some(0))];
    assert!(validate(&gw)
        .iter()
        .any(|i| i.field == "rate_limits[0].burst"));
}

#[test]
fn publish_is_atomic_on_failure() {
    let state = ConfigState::new();
    assert_eq!(state.snapshot().generation(), 0);
    let info = state.compile_and_publish(&good_gateway()).unwrap();
    assert_eq!(info.generation, 1);
    let before = state.snapshot();
    assert_eq!(
        before.match_route("/v1/users/7").map(|r| r.name.as_str()),
        Some("users-get")
    );

    let mut bad = good_gateway();
    bad.routes[0].service = "missing".into();
    assert!(matches!(
        state.compile_and_publish(&bad),
        Err(CompileError::Validation(_))
    ));

    let after = state.snapshot();
    assert_eq!(after.generation(), 1, "failed publish must not swap");
    assert_eq!(after.content_hash(), before.content_hash());
    assert!(after.match_route("/old/bar").is_some());

    // Recovery: the next successful publish advances the generation.
    let info2 = state.compile_and_publish(&good_gateway()).unwrap();
    assert_eq!(info2.generation, 2);
}
