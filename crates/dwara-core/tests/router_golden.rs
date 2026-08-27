//! Golden-file tests for the router (DW-010): every `router_golden/*.yaml`
//! file is one (config, request, expected outcome) case; this harness walks
//! them all.
//!
//! Each case file is a YAML document with:
//!
//! - the gateway config fields at the top level (`routes:`, ...), EXCEPT
//!   `request:` and `expect:`, which are reserved;
//! - `request:` — `method` (default GET), `path` (may carry a query
//!   string), optional `host`, optional `headers` (name -> value);
//! - `expect:` — `route`: the matched route's name, or `null` when the
//!   request must NOT match any route (path miss OR criteria miss), and
//!   optionally `upstream_path`: the path after the action's rewrite
//!   (proxy actions only; the raw path when no rewrite applies).
//!
//! The harness runs the real resolution pipeline minus the network:
//! `compile()` -> `RouteTable::find_full` -> `route_applies` ->
//! `apply_path_rewrite`. A default service `svc` / upstream `pool` is
//! injected for any route referencing a service the case does not define,
//! so case files stay focused on routing.
//!
//! These files are GOLDEN: an outcome change here is a behavior change and
//! must be a deliberate, reviewed edit, not a drive-by.

use std::collections::BTreeMap;
use std::path::PathBuf;

use dwara_core::config::{parse_gateway, Endpoint, Gateway, Service, Upstream};
use dwara_core::proxy::{apply_path_rewrite, route_applies};
use dwara_core::snapshot::compile;
use serde::Deserialize;

#[derive(Deserialize)]
struct RequestSpec {
    #[serde(default = "default_method")]
    method: String,
    path: String,
    host: Option<String>,
    /// A header value is either one string or a list of strings (a list
    /// produces repeated header lines, e.g. multiple `Cookie:` headers).
    #[serde(default)]
    headers: BTreeMap<String, HeaderValueSpec>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HeaderValueSpec {
    One(String),
    Many(Vec<String>),
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Deserialize)]
struct ExpectSpec {
    route: Option<String>,
    upstream_path: Option<String>,
}

fn yaml_str(value: &serde_yaml_ng::Value) -> String {
    serde_yaml_ng::to_string(value).expect("case fragment serializes")
}

/// Load one case file, splitting it into (gateway-config text, request,
/// expect). The reserved keys are lifted out of the document and the
/// remaining mapping is re-serialized as gateway YAML.
fn load_case(text: &str) -> (String, RequestSpec, ExpectSpec, String) {
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(text).expect("case file parses as YAML");
    let mut mapping = match doc {
        serde_yaml_ng::Value::Mapping(m) => m,
        other => panic!("case file must be a YAML mapping, got {other:?}"),
    };
    let name = text
        .lines()
        .find_map(|l| l.strip_prefix("# name: ").map(str::to_string))
        .unwrap_or_else(|| "<unnamed>".into());
    let request: RequestSpec = serde_yaml_ng::from_value(
        mapping
            .remove(serde_yaml_ng::Value::String("request".into()))
            .expect("case file has a request: key"),
    )
    .expect("request: parses");
    let expect: ExpectSpec = serde_yaml_ng::from_value(
        mapping
            .remove(serde_yaml_ng::Value::String("expect".into()))
            .expect("case file has an expect: key"),
    )
    .expect("expect: parses");
    let config = yaml_str(&serde_yaml_ng::Value::Mapping(mapping));
    (config, request, expect, name)
}

/// Append a service/upstream pair for every route service the case did not
/// define, so routing-focused case files need no service boilerplate.
fn inject_default_services(gateway: &mut Gateway) {
    let pool = Upstream {
        name: "pool".into(),
        load_balancer: dwara_core::config::LoadBalancer::RoundRobin,
        protocol: dwara_core::config::UpstreamProtocol::Http1,
        endpoints: vec![Endpoint {
            address: "127.0.0.1".into(),
            port: 9,
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
    };
    if !gateway.upstreams.iter().any(|u| u.name == "pool") {
        gateway.upstreams.push(pool);
    }
    let known: Vec<String> = gateway.services.iter().map(|s| s.name.clone()).collect();
    let mut added = Vec::new();
    for route in &gateway.routes {
        if !known.contains(&route.service) && !added.contains(&route.service) {
            added.push(route.service.clone());
        }
    }
    for name in added {
        gateway.services.push(Service {
            name,
            upstream: "pool".into(),
            base_path: None,
            version: None,
            policies: vec![],
            authorization: None,
        });
    }
}

fn case_files() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/router_golden");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("router_golden dir: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 15,
        "expected a full golden suite, found only {} files",
        files.len()
    );
    files
}

#[test]
fn router_golden_suite() {
    for file in case_files() {
        let text = std::fs::read_to_string(&file).expect("case file readable");
        let (config, request, expect, name) = load_case(&text);

        let mut gateway = parse_gateway(&config)
            .unwrap_or_else(|e| panic!("{name}: config does not parse: {e}\n{config}"));
        inject_default_services(&mut gateway);
        let compiled =
            compile(&gateway).unwrap_or_else(|e| panic!("{name}: config does not compile: {e}"));
        let table = compiled.route_table();

        let mut builder = hyper::Request::builder()
            .method(request.method.as_str())
            .uri(request.path.parse::<hyper::Uri>().unwrap_or_else(|e| {
                panic!("{name}: request path '{}' invalid: {e}", request.path)
            }));
        if let Some(host) = &request.host {
            builder = builder.header("host", host);
        }
        for (h, spec) in &request.headers {
            match spec {
                HeaderValueSpec::One(v) => builder = builder.header(h.as_str(), v.as_str()),
                HeaderValueSpec::Many(vs) => {
                    for v in vs {
                        builder = builder.header(h.as_str(), v.as_str());
                    }
                }
            }
        }
        let req = builder
            .body(())
            .unwrap_or_else(|e| panic!("{name}: request does not build: {e}"));

        let path_only = req.uri().path().to_string();
        let resolved = table.find_full(&path_only).and_then(|(idx, params)| {
            let route = &gateway.routes[idx];
            if route_applies(&route.r#match, &req) {
                Some((idx, params, route.name.clone()))
            } else {
                None
            }
        });

        let context = format!(
            "{name}: {} {}{}",
            request.method,
            request
                .host
                .as_deref()
                .map(|h| format!("{h} "))
                .unwrap_or_default(),
            request.path
        );
        match (&expect.route, &resolved) {
            (None, None) => {}
            (Some(want), Some((_, _, got))) => {
                assert_eq!(want, got, "{context}: expected route '{want}', got '{got}'")
            }
            (Some(want), None) => panic!("{context}: expected route '{want}', got NO match"),
            (None, Some((_, _, got))) => {
                panic!("{context}: expected NO match, got route '{got}'")
            }
        }

        if let Some(expected_path) = &expect.upstream_path {
            let (idx, params, _) = resolved
                .unwrap_or_else(|| panic!("{context}: upstream_path expects a matched route"));
            let route = &gateway.routes[idx];
            let got = apply_path_rewrite(route, table, idx, &path_only, &params);
            assert_eq!(
                &got, expected_path,
                "{context}: rewritten upstream path mismatch"
            );
        }
    }
}
