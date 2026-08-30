//! Integration tests for the DW-007 TLS validation rules added to
//! `dwara_core::snapshot::validate`: duplicate SNI server names, mode /
// field cross-references (certificates vs passthrough, sni_routes vs
//! terminate), dangling sni_routes upstream references, and the
//! terminate-without-certificate-material rule.
//!
//! Complements `snapshot_pipeline.rs` (which owns the pre-existing
//! validation rules) and `dwara-bin/tests/tls_listener.rs` (which owns
//! the process-level behavior). Here the rules are driven directly via
//! `validate` on typed configs.

use dwara_core::config::{
    Endpoint, Gateway, Listener, ListenerProtocol, ListenerTls, LoadBalancer, PathMatch,
    PathMatchKind, Route, RouteAction, RouteMatch, Service, SniRoute, TlsCertificate, TlsMode,
    Upstream, UpstreamProtocol,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn https_listener(name: &str, port: u16, tls: ListenerTls) -> Listener {
    Listener {
        name: name.into(),
        address: "127.0.0.1".into(),
        port,
        protocol: ListenerProtocol::Https,
        tls: Some(tls),
        proxy_protocol: false,
        policies: vec![],
        authorization: None,
    }
}

fn terminate_tls() -> ListenerTls {
    ListenerTls {
        mode: TlsMode::Terminate,
        client_ca_file: None,
        cert_file: Some("/certs/edge.crt.pem".into()),
        key_file: Some("/certs/edge.key.pem".into()),
        certificates: vec![],
        sni_routes: vec![],
    }
}

fn passthrough_tls(routes: Vec<SniRoute>) -> ListenerTls {
    ListenerTls {
        mode: TlsMode::Passthrough,
        client_ca_file: None,
        cert_file: None,
        key_file: None,
        certificates: vec![],
        sni_routes: routes,
    }
}

fn sni_route(names: &[&str], upstream: &str) -> SniRoute {
    SniRoute {
        server_names: names.iter().map(|n| n.to_string()).collect(),
        upstream: upstream.into(),
    }
}

fn tls_cert(names: &[&str]) -> TlsCertificate {
    TlsCertificate {
        server_names: names.iter().map(|n| n.to_string()).collect(),
        cert_file: "/certs/sni.crt.pem".into(),
        key_file: "/certs/sni.key.pem".into(),
    }
}

fn base_gateway(listener: Listener) -> Gateway {
    Gateway {
        trusted_proxies: vec![],
        listeners: vec![listener],
        routes: vec![Route {
            name: "r".into(),
            service: "svc".into(),
            cache: None,
            methods: vec![],
            slo: None,
            websocket: None,
            waf: None,
            request_validation: None,
            openapi: None,
            r#match: RouteMatch {
                path: PathMatch {
                    kind: PathMatchKind::Exact,
                    value: "/x".into(),
                },
                host: None,
                methods: vec![],
                headers: Default::default(),
                query: vec![],
                cookies: vec![],
                accept: None,
            },
            action: RouteAction::Proxy { rewrite: None },
            policies: vec![],
            priority: None,
            auth_required: false,
            cors: None,
            compression: None,
            limits: None,
            authorization: None,
            deprecation: None,
            maintenance: None,
            transforms: None,
            security_headers: None,
            masking: None,
        }],
        services: vec![Service {
            name: "svc".into(),
            upstream: Some("pool".into()),
            split: None,
            sticky: None,
            base_path: None,
            version: None,
            policies: vec![],
            authorization: None,
        }],
        upstreams: vec![Upstream {
            name: "pool".into(),
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
            oauth2_client_credentials: None,
        }],
        consumers: vec![],
        policies: vec![],
        global_policies: vec![],
        authorization: None,
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        allow_empty_routes: false,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
        license: None,
        oidc_providers: Vec::new(),
        redis_rate_limiter: None,
    }
}

fn assert_single_issue(gw: &Gateway, entity: &str, name: &str, field: &str) {
    let issues = dwara_core::snapshot::validate(gw);
    assert_eq!(
        issues.len(),
        1,
        "expected exactly one issue, got: {issues:?}"
    );
    let i = &issues[0];
    assert_eq!(i.entity, entity, "issue entity: {i}");
    assert_eq!(i.name, name, "issue name: {i:?}");
    assert_eq!(i.field, field, "issue field: {i:?}");
}

fn assert_no_issues(gw: &Gateway) {
    let issues = dwara_core::snapshot::validate(gw);
    assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
}

// ---------------------------------------------------------------------------
// certificates (terminate mode)
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_duplicate_server_name_within_one_certificate_entry() {
    let mut tls = terminate_tls();
    tls.certificates
        .push(tls_cert(&["a.example.com", "a.example.com"]));
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.certificates[0].server_names",
    );
}

#[test]
fn validation_rejects_duplicate_server_name_across_certificate_entries() {
    let mut tls = terminate_tls();
    tls.certificates.push(tls_cert(&["shared.example.com"]));
    tls.certificates
        .push(tls_cert(&["b.example.com", "shared.example.com"]));
    // The duplicate is reported against the second entry that re-uses it.
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.certificates[1].server_names",
    );
}

#[test]
fn validation_rejects_certificate_entry_with_empty_server_names_list() {
    let mut tls = terminate_tls();
    tls.certificates.push(tls_cert(&[]));
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.certificates[0].server_names",
    );
}

#[test]
fn validation_accepts_terminate_with_certificates_and_no_single_pair() {
    // certificates-only terminate (first entry becomes the fallback at
    // runtime) is a valid configuration.
    let mut tls = terminate_tls();
    tls.cert_file = None;
    tls.key_file = None;
    tls.certificates.push(tls_cert(&["a.example.com"]));
    tls.certificates.push(tls_cert(&["b.example.com"]));
    assert_no_issues(&base_gateway(https_listener("edge", 8443, tls)));
}

// ---------------------------------------------------------------------------
// terminate/passthrough mode cross-field rules
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_terminate_with_neither_single_pair_nor_certificates() {
    let tls = ListenerTls {
        mode: TlsMode::Terminate,
        client_ca_file: None,
        cert_file: None,
        key_file: None,
        certificates: vec![],
        sni_routes: vec![],
    };
    let issues = dwara_core::snapshot::validate(&base_gateway(https_listener("edge", 8443, tls)));
    assert_eq!(issues.len(), 2, "got: {issues:?}");
    let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
    assert!(fields.contains(&"tls.cert_file"), "{fields:?}");
    assert!(fields.contains(&"tls.key_file"), "{fields:?}");
}

#[test]
fn validation_rejects_sni_routes_in_terminate_mode() {
    let mut tls = terminate_tls();
    tls.sni_routes.push(sni_route(&["a.example.com"], "pool"));
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.sni_routes",
    );
}

#[test]
fn validation_rejects_certificates_in_passthrough_mode() {
    let mut tls = passthrough_tls(vec![sni_route(&["a.example.com"], "pool")]);
    tls.certificates.push(tls_cert(&["a.example.com"]));
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.certificates",
    );
}

// ---------------------------------------------------------------------------
// sni_routes upstream references
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_sni_route_referencing_unknown_upstream() {
    let tls = passthrough_tls(vec![sni_route(&["a.example.com"], "no-such-pool")]);
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.sni_routes[0].upstream",
    );
}

#[test]
fn validation_accepts_passthrough_route_to_known_upstream() {
    let tls = passthrough_tls(vec![sni_route(&["a.example.com"], "pool")]);
    assert_no_issues(&base_gateway(https_listener("edge", 8443, tls)));
}

// ---------------------------------------------------------------------------
// client_ca_file (#124): terminate-only client-certificate verification
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_client_ca_file_in_passthrough_mode() {
    let mut tls = passthrough_tls(vec![sni_route(&["a.example.com"], "pool")]);
    tls.client_ca_file = Some("/certs/client-ca.pem".into());
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.client_ca_file",
    );
}

#[test]
fn validation_rejects_missing_client_ca_bundle() {
    let mut tls = terminate_tls();
    tls.client_ca_file = Some("/no/such/client-ca.pem".into());
    assert_single_issue(
        &base_gateway(https_listener("edge", 8443, tls)),
        "listener",
        "edge",
        "tls.client_ca_file",
    );
}

#[test]
fn validation_accepts_real_client_ca_bundle_in_terminate_mode() {
    // A REAL PEM bundle (a self-signed rcgen CA) passes the compile-time
    // check exactly like trusted_ca_file (#121) does.
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "dwara-test-client-ca");
    let ca = params.self_signed(&key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client-ca.pem");
    std::fs::write(&path, ca.pem()).unwrap();
    let mut tls = terminate_tls();
    tls.client_ca_file = Some(path.display().to_string());
    assert_no_issues(&base_gateway(https_listener("edge", 8443, tls)));
}

#[test]
fn validation_rejects_mtls_credential_with_neither_subject_nor_fingerprint() {
    // #124: an mtls credential matches by subject CN or by fingerprint —
    // carrying neither can never match anything, so it is rejected.
    let mut gw = base_gateway(https_listener("edge", 8443, terminate_tls()));
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![dwara_core::config::Credential::Mtls {
            subject: None,
            fingerprint: None,
        }],
        ..base_consumer_rest()
    });
    assert_single_issue(&gw, "consumer", "c", "credentials[0]");
}

#[test]
fn validation_accepts_subject_only_mtls_credential() {
    let mut gw = base_gateway(https_listener("edge", 8443, terminate_tls()));
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![dwara_core::config::Credential::Mtls {
            subject: Some("acme-client".into()),
            fingerprint: None,
        }],
        ..base_consumer_rest()
    });
    assert_no_issues(&gw);
}

#[test]
fn validation_rejects_mtls_credential_with_both_subject_and_fingerprint() {
    // #124: "exactly one of subject / fingerprint" — both-set would
    // leave the fingerprint silently inert (only the subject is ever
    // matched), so it is rejected like both-empty.
    let mut gw = base_gateway(https_listener("edge", 8443, terminate_tls()));
    gw.consumers.push(dwara_core::config::Consumer {
        name: "c".into(),
        credentials: vec![dwara_core::config::Credential::Mtls {
            subject: Some("acme-client".into()),
            fingerprint: Some("sha256:9f2a7c1e...".into()),
        }],
        ..base_consumer_rest()
    });
    assert_single_issue(&gw, "consumer", "c", "credentials[0]");
}

/// The Consumer field spread for the credential-shape tests above.
fn base_consumer_rest() -> dwara_core::config::Consumer {
    dwara_core::config::Consumer {
        name: String::new(),
        credentials: vec![],
        policies: vec![],
        priority: None,
        groups: vec![],
        authorization: None,
        quotas: None,
    }
}
