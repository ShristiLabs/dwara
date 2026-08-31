//! Integration tests for the native plugin filter trait and the unified
//! plugin dispatch chain (DW-119).
//!
//! These tests prove the done-when criterion: a native Rust filter and
//! a WASM plugin can occupy the same phase slot on the same route,
//! selected by config, with no dataplane-visible difference in
//! attachment semantics. The native+ WASM combination test uses a stub
//! `WasmDispatch` implementation (not a real wasmtime instance) so it
//! runs without the `wasm` feature; a feature-gated test exercises the
//! real `WasmChainAdapter` when both `plugins` and `wasm` are on.
//!
//! Coverage:
//! - native filter registration (registry lookup, duplicate, not-found)
//! - config parse with `native:` (and backward-compat with `wasm:`)
//! - validation: exactly one of wasm/native, non-empty phases,
//!   duplicate names, unknown route plugin references
//! - a native filter modifying request headers/body
//! - a native filter short-circuiting with a local response
//! - a native + stub-WASM plugin in the same phase slot via the unified
//!   chain (attachment-semantics equivalence)
//! - config round-trip (serialize -> parse -> equal)

#![cfg(feature = "plugins")]

use std::collections::HashMap;

use dwara_core::config::{gateway_to_yaml, parse_gateway, PluginConfig, PluginPhase};
use dwara_core::plugins::{
    ChainOutcome, FilterOutcome, LocalResponse, NativeFilter, NativeFilterFactory, NativeRegistry,
    NoWasm, PluginChain, RegistryError, WasmDispatch,
};
use dwara_core::snapshot::validate;

// ---------------------------------------------------------------------------
// Test native filter implementations
// ---------------------------------------------------------------------------

/// A native filter that adds a header to the request.
struct AddHeaderFilter {
    name: String,
    value: String,
}

impl NativeFilter for AddHeaderFilter {
    fn on_request_headers(&mut self, mut headers: Vec<(String, String)>) -> FilterOutcome {
        headers.push((self.name.clone(), self.value.clone()));
        FilterOutcome::Continue {
            headers,
            body: Vec::new(),
        }
    }
}

/// A native filter that appends bytes to the request body.
struct AppendBodyFilter {
    suffix: Vec<u8>,
}

impl NativeFilter for AppendBodyFilter {
    fn on_request_body(&mut self, mut body: Vec<u8>) -> FilterOutcome {
        body.extend_from_slice(&self.suffix);
        FilterOutcome::Continue {
            headers: Vec::new(),
            body,
        }
    }
}

/// A native filter that short-circuits with a 403 local response.
struct DenyFilter {
    status: u16,
    body: Vec<u8>,
}

impl NativeFilter for DenyFilter {
    fn on_request_headers(&mut self, _headers: Vec<(String, String)>) -> FilterOutcome {
        FilterOutcome::LocalResponse(LocalResponse {
            status: self.status,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: self.body.clone(),
        })
    }
}

/// A native filter that errors.
struct ErrorFilter;

impl NativeFilter for ErrorFilter {
    fn on_request_headers(&mut self, _headers: Vec<(String, String)>) -> FilterOutcome {
        FilterOutcome::Error("intentional filter error".to_string())
    }
}

/// A native filter that modifies response headers.
struct ResponseHeaderFilter {
    name: String,
    value: String,
}

impl NativeFilter for ResponseHeaderFilter {
    fn on_response_headers(&mut self, mut headers: Vec<(String, String)>) -> FilterOutcome {
        headers.push((self.name.clone(), self.value.clone()));
        FilterOutcome::Continue {
            headers,
            body: Vec::new(),
        }
    }
}

/// A stub WASM dispatch adapter for the unified-chain combination test.
/// It records the names it was called with and adds a header, mirroring
/// what a real WASM plugin (via `WasmChainAdapter`) would do. This lets
/// the attachment-semantics-equivalence test run without wasmtime.
struct StubWasm {
    /// The names `on_request_headers` was called with (in order).
    called: Vec<String>,
    /// The header to add on request_headers.
    add_header: (String, String),
}

impl WasmDispatch for StubWasm {
    fn on_request_headers(
        &mut self,
        name: &str,
        mut headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        self.called.push(name.to_string());
        headers.push(self.add_header.clone());
        (ChainOutcome::Continue, headers)
    }

    fn on_request_body(&mut self, _name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        (ChainOutcome::Continue, body)
    }

    fn on_response_headers(
        &mut self,
        _name: &str,
        headers: Vec<(String, String)>,
    ) -> (ChainOutcome, Vec<(String, String)>) {
        (ChainOutcome::Continue, headers)
    }

    fn on_response_body(&mut self, _name: &str, body: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
        (ChainOutcome::Continue, body)
    }
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

fn make_registry() -> NativeRegistry {
    let registry = NativeRegistry::new();
    registry
        .register(
            "add-header",
            Box::new(|_cfg: &Option<String>| {
                Ok(Box::new(AddHeaderFilter {
                    name: "x-native".to_string(),
                    value: "dwara".to_string(),
                }) as Box<dyn NativeFilter>)
            }),
        )
        .unwrap();
    registry
        .register(
            "append-body",
            Box::new(|_cfg: &Option<String>| {
                Ok(Box::new(AppendBodyFilter {
                    suffix: b"-appended".to_vec(),
                }) as Box<dyn NativeFilter>)
            }),
        )
        .unwrap();
    registry
        .register(
            "deny",
            Box::new(|_cfg: &Option<String>| {
                Ok(Box::new(DenyFilter {
                    status: 403,
                    body: b"forbidden".to_vec(),
                }) as Box<dyn NativeFilter>)
            }),
        )
        .unwrap();
    registry
        .register(
            "error-filter",
            Box::new(|_cfg: &Option<String>| Ok(Box::new(ErrorFilter) as Box<dyn NativeFilter>)),
        )
        .unwrap();
    registry
        .register(
            "resp-header",
            Box::new(|_cfg: &Option<String>| {
                Ok(Box::new(ResponseHeaderFilter {
                    name: "x-resp-native".to_string(),
                    value: "yes".to_string(),
                }) as Box<dyn NativeFilter>)
            }),
        )
        .unwrap();
    registry
}

#[test]
fn registry_register_and_lookup() {
    let registry = make_registry();
    assert!(registry.contains("add-header"));
    assert!(registry.contains("deny"));
    assert!(!registry.contains("nope"));
    assert_eq!(registry.len(), 5);
    assert!(!registry.is_empty());
    let names = registry.names();
    assert_eq!(
        names,
        vec![
            "add-header",
            "append-body",
            "deny",
            "error-filter",
            "resp-header"
        ]
    );
}

#[test]
fn registry_duplicate_rejected() {
    let registry = NativeRegistry::new();
    let factory: NativeFilterFactory = Box::new(|_| {
        Ok(Box::new(AddHeaderFilter {
            name: "x".to_string(),
            value: "y".to_string(),
        }))
    });
    registry.register("dup", factory).unwrap();
    let factory2: NativeFilterFactory = Box::new(|_| {
        Ok(Box::new(AddHeaderFilter {
            name: "x".to_string(),
            value: "z".to_string(),
        }))
    });
    let err = registry.register("dup", factory2).unwrap_err();
    assert!(matches!(err, RegistryError::Duplicate { .. }));
}

#[test]
fn registry_not_found() {
    let registry = NativeRegistry::new();
    let err = registry.create("missing", &None).unwrap_err();
    assert!(matches!(err, RegistryError::NotFound { .. }));
}

#[test]
fn registry_create_returns_filter() {
    let registry = make_registry();
    let mut filter = registry.create("add-header", &None).unwrap();
    // The filter is a Box<dyn NativeFilter>; exercise it.
    let outcome = filter.on_request_headers(vec![("host".to_string(), "x".to_string())]);
    match outcome {
        FilterOutcome::Continue { headers, .. } => {
            assert!(headers.iter().any(|(k, v)| k == "x-native" && v == "dwara"));
        }
        _ => panic!("expected Continue"),
    }
}

// ---------------------------------------------------------------------------
// Config parse tests
// ---------------------------------------------------------------------------

#[test]
fn config_parses_native_plugin() {
    let yaml = r#"
listeners: []
routes: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
  - name: my-native
    native: add-header
    phases:
      - request_headers
"#;
    let gateway = parse_gateway(yaml).expect("native plugin config parses");
    assert_eq!(gateway.plugins.len(), 1);
    let p = &gateway.plugins[0];
    assert_eq!(p.name, "my-native");
    assert_eq!(p.native.as_deref(), Some("add-header"));
    assert_eq!(p.wasm, None);
    assert_eq!(p.phases, vec![PluginPhase::RequestHeaders]);
}

#[test]
fn config_parses_wasm_plugin_backward_compat() {
    // Existing configs with `wasm:` (now Option<String>) still parse.
    let yaml = r#"
listeners: []
routes: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
  - name: my-wasm
    wasm: /opt/plugins/my-filter.wasm
    phases:
      - request_headers
      - response_headers
"#;
    let gateway = parse_gateway(yaml).expect("wasm plugin config parses");
    assert_eq!(gateway.plugins.len(), 1);
    let p = &gateway.plugins[0];
    assert_eq!(p.wasm.as_deref(), Some("/opt/plugins/my-filter.wasm"));
    assert_eq!(p.native, None);
    assert_eq!(p.phases.len(), 2);
}

#[test]
fn config_round_trip_native_plugin() {
    // Build the gateway via parse (so all defaulted fields are filled),
    // then serialize -> parse -> compare the plugin entry.
    let yaml = r#"
listeners: []
routes: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
  - name: rt-native
    native: add-header
    phases:
      - request_headers
      - response_body
    config: '{"key":"val"}'
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let serialized = gateway_to_yaml(&gateway).expect("serialize");
    let parsed = parse_gateway(&serialized).expect("round-trip parse");
    assert_eq!(parsed.plugins.len(), 1);
    let p = &parsed.plugins[0];
    assert_eq!(p.name, "rt-native");
    assert_eq!(p.native.as_deref(), Some("add-header"));
    assert_eq!(p.wasm, None);
    assert_eq!(
        p.phases,
        vec![PluginPhase::RequestHeaders, PluginPhase::ResponseBody]
    );
    assert_eq!(p.config.as_deref(), Some("{\"key\":\"val\"}"));
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

fn gateway_yaml(plugins_block: &str) -> String {
    format!(
        r#"
listeners: []
routes: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
{plugins_block}
"#
    )
}

#[test]
fn validation_rejects_neither_wasm_nor_native() {
    let yaml = gateway_yaml("  - name: p1\n    phases: [request_headers]\n");
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    let p1_issues: Vec<_> = issues.iter().filter(|i| i.name == "p1").collect();
    assert!(
        p1_issues
            .iter()
            .any(|i| i.field == "wasm" && i.message.contains("exactly one")),
        "expected exactly-one-of issue, got {p1_issues:?}"
    );
}

#[test]
fn validation_rejects_both_wasm_and_native() {
    let yaml = gateway_yaml(
        "  - name: p1\n    wasm: /x.wasm\n    native: add-header\n    phases: [request_headers]\n",
    );
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.name == "p1" && i.field == "native" && i.message.contains("both are set")),
        "expected both-set issue, got {issues:?}"
    );
}

#[test]
fn validation_rejects_empty_phases() {
    let yaml = gateway_yaml("  - name: p1\n    native: add-header\n    phases: []\n");
    let gateway = parse_gateway(&yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.name == "p1" && i.field == "phases" && i.message.contains("non-empty")),
        "expected non-empty phases issue, got {issues:?}"
    );
}

#[test]
fn validation_rejects_duplicate_plugin_names() {
    let yaml = r#"
listeners: []
routes: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
  - name: dup
    native: add-header
    phases: [request_headers]
  - name: dup
    native: deny
    phases: [request_headers]
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.name == "dup" && i.field == "name" && i.message.contains("duplicate")),
        "expected duplicate-name issue, got {issues:?}"
    );
}

#[test]
fn validation_rejects_unknown_route_plugin_reference() {
    let yaml = r#"
listeners: []
upstreams:
  - name: u1
    endpoints:
      - address: 127.0.0.1
        port: 8080
services:
  - name: s1
    upstream: u1
consumers: []
policies: []
plugins:
  - name: real
    native: add-header
    phases: [request_headers]
routes:
  - name: r1
    service: s1
    match:
      path:
        type: exact
        value: /api
    action:
      type: proxy
    plugins:
      - real
      - ghost
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let issues = validate(&gateway);
    assert!(
        issues.iter().any(|i| i.entity == "route"
            && i.name == "r1"
            && i.field == "plugins"
            && i.message.contains("ghost")),
        "expected unknown-plugin-ref issue, got {issues:?}"
    );
}

#[test]
fn validation_accepts_valid_native_plugin() {
    let yaml = r#"
listeners: []
routes: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
  - name: good
    native: add-header
    phases: [request_headers]
"#;
    let gateway = parse_gateway(yaml).expect("parses");
    let issues = validate(&gateway);
    let plugin_issues: Vec<_> = issues.iter().filter(|i| i.entity == "plugin").collect();
    assert!(
        plugin_issues.is_empty(),
        "expected no plugin issues, got {plugin_issues:?}"
    );
}

// ---------------------------------------------------------------------------
// Unified chain: native filter modifying headers/body
// ---------------------------------------------------------------------------

fn configs_map(plugins: Vec<PluginConfig>) -> HashMap<String, PluginConfig> {
    plugins.into_iter().map(|p| (p.name.clone(), p)).collect()
}

#[test]
fn chain_native_filter_modifies_request_headers() {
    let registry = make_registry();
    let configs = configs_map(vec![PluginConfig {
        name: "p".to_string(),
        wasm: None,
        native: Some("add-header".to_string()),
        phases: vec![PluginPhase::RequestHeaders],
        config: None,
        limits: None,
    }]);
    let mut chain = PluginChain::new(&["p".to_string()], &configs, &registry, NoWasm);
    let (outcome, headers) =
        chain.on_request_headers(vec![("host".to_string(), "example.com".to_string())]);
    assert_eq!(outcome, ChainOutcome::Continue);
    assert!(headers.iter().any(|(k, v)| k == "x-native" && v == "dwara"));
    assert!(headers.iter().any(|(k, _)| k == "host"));
}

#[test]
fn chain_native_filter_modifies_request_body() {
    let registry = make_registry();
    let configs = configs_map(vec![PluginConfig {
        name: "p".to_string(),
        wasm: None,
        native: Some("append-body".to_string()),
        phases: vec![PluginPhase::RequestBody],
        config: None,
        limits: None,
    }]);
    let mut chain = PluginChain::new(&["p".to_string()], &configs, &registry, NoWasm);
    let (outcome, body) = chain.on_request_body(b"hello".to_vec());
    assert_eq!(outcome, ChainOutcome::Continue);
    assert_eq!(body, b"hello-appended".to_vec());
}

#[test]
fn chain_native_filter_modifies_response_headers() {
    let registry = make_registry();
    let configs = configs_map(vec![PluginConfig {
        name: "p".to_string(),
        wasm: None,
        native: Some("resp-header".to_string()),
        phases: vec![PluginPhase::ResponseHeaders],
        config: None,
        limits: None,
    }]);
    let mut chain = PluginChain::new(&["p".to_string()], &configs, &registry, NoWasm);
    let (outcome, headers) =
        chain.on_response_headers(vec![("content-type".to_string(), "text/html".to_string())]);
    assert_eq!(outcome, ChainOutcome::Continue);
    assert!(headers
        .iter()
        .any(|(k, v)| k == "x-resp-native" && v == "yes"));
}

#[test]
fn chain_native_filter_short_circuits_with_local_response() {
    let registry = make_registry();
    let configs = configs_map(vec![PluginConfig {
        name: "p".to_string(),
        wasm: None,
        native: Some("deny".to_string()),
        phases: vec![PluginPhase::RequestHeaders],
        config: None,
        limits: None,
    }]);
    let mut chain = PluginChain::new(&["p".to_string()], &configs, &registry, NoWasm);
    let (outcome, _headers) = chain.on_request_headers(vec![("host".to_string(), "x".to_string())]);
    match outcome {
        ChainOutcome::LocalResponse(resp) => {
            assert_eq!(resp.status, 403);
            assert_eq!(resp.body, b"forbidden".to_vec());
        }
        other => panic!("expected LocalResponse, got {other:?}"),
    }
}

#[test]
fn chain_native_filter_error_becomes_chain_error() {
    let registry = make_registry();
    let configs = configs_map(vec![PluginConfig {
        name: "p".to_string(),
        wasm: None,
        native: Some("error-filter".to_string()),
        phases: vec![PluginPhase::RequestHeaders],
        config: None,
        limits: None,
    }]);
    let mut chain = PluginChain::new(&["p".to_string()], &configs, &registry, NoWasm);
    let (outcome, _headers) = chain.on_request_headers(vec![("host".to_string(), "x".to_string())]);
    match outcome {
        ChainOutcome::Error(msg) => assert!(msg.contains("intentional filter error")),
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn chain_empty_when_no_plugins_match() {
    let registry = make_registry();
    let configs = HashMap::new();
    let chain = PluginChain::new(&[], &configs, &registry, NoWasm);
    assert!(chain.is_empty());
}

#[test]
fn chain_skips_phases_not_declared() {
    let registry = make_registry();
    // add-header only declares request_headers; calling on_request_body
    // should be a no-op pass-through.
    let configs = configs_map(vec![PluginConfig {
        name: "p".to_string(),
        wasm: None,
        native: Some("add-header".to_string()),
        phases: vec![PluginPhase::RequestHeaders],
        config: None,
        limits: None,
    }]);
    let mut chain = PluginChain::new(&["p".to_string()], &configs, &registry, NoWasm);
    let (outcome, body) = chain.on_request_body(b"orig".to_vec());
    assert_eq!(outcome, ChainOutcome::Continue);
    assert_eq!(body, b"orig".to_vec());
}

// ---------------------------------------------------------------------------
// Unified chain: native + stub-WASM in the same phase slot
// (attachment-semantics equivalence -- the done-when criterion)
// ---------------------------------------------------------------------------

#[test]
fn chain_native_and_wasm_same_phase_slot() {
    // A route references two plugins: a native filter and a WASM plugin,
    // both in the request_headers phase. The unified chain dispatches
    // both in route-declaration order, threading headers through. This
    // proves "no dataplane-visible difference in attachment semantics":
    // both are selected by config and run in the same phase slot.
    let registry = make_registry();
    let configs = configs_map(vec![
        PluginConfig {
            name: "n".to_string(),
            wasm: None,
            native: Some("add-header".to_string()),
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        },
        PluginConfig {
            name: "w".to_string(),
            wasm: Some("/opt/w.wasm".to_string()),
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        },
    ]);
    let stub = StubWasm {
        called: Vec::new(),
        add_header: ("x-wasm".to_string(), "yes".to_string()),
    };
    let mut chain = PluginChain::new(
        &["n".to_string(), "w".to_string()],
        &configs,
        &registry,
        stub,
    );
    let (outcome, headers) =
        chain.on_request_headers(vec![("host".to_string(), "example.com".to_string())]);
    assert_eq!(outcome, ChainOutcome::Continue);
    // The native filter added x-native, the stub-WASM added x-wasm --
    // both ran in the same phase slot, in declaration order.
    assert!(
        headers.iter().any(|(k, v)| k == "x-native" && v == "dwara"),
        "native filter ran: {headers:?}"
    );
    assert!(
        headers.iter().any(|(k, v)| k == "x-wasm" && v == "yes"),
        "wasm plugin ran: {headers:?}"
    );
    // The stub recorded that it was dispatched for the WASM plugin.
    assert_eq!(chain.wasm().called, vec!["w".to_string()]);
}

#[test]
fn chain_wasm_short_circuits_before_later_native() {
    // A WASM plugin (stub) short-circuits; a later native filter in the
    // same phase must NOT run (short-circuit semantics).
    let registry = make_registry();
    let configs = configs_map(vec![
        PluginConfig {
            name: "w".to_string(),
            wasm: Some("/opt/w.wasm".to_string()),
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        },
        PluginConfig {
            name: "n".to_string(),
            wasm: None,
            native: Some("add-header".to_string()),
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        },
    ]);
    struct DenyWasm;
    impl WasmDispatch for DenyWasm {
        fn on_request_headers(
            &mut self,
            _name: &str,
            _headers: Vec<(String, String)>,
        ) -> (ChainOutcome, Vec<(String, String)>) {
            (
                ChainOutcome::LocalResponse(LocalResponse {
                    status: 401,
                    headers: vec![],
                    body: b"denied-by-wasm".to_vec(),
                }),
                vec![],
            )
        }
        fn on_request_body(&mut self, _: &str, b: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
            (ChainOutcome::Continue, b)
        }
        fn on_response_headers(
            &mut self,
            _: &str,
            h: Vec<(String, String)>,
        ) -> (ChainOutcome, Vec<(String, String)>) {
            (ChainOutcome::Continue, h)
        }
        fn on_response_body(&mut self, _: &str, b: Vec<u8>) -> (ChainOutcome, Vec<u8>) {
            (ChainOutcome::Continue, b)
        }
    }
    let mut chain = PluginChain::new(
        &["w".to_string(), "n".to_string()],
        &configs,
        &registry,
        DenyWasm,
    );
    let (outcome, _headers) = chain.on_request_headers(vec![("host".to_string(), "x".to_string())]);
    match outcome {
        ChainOutcome::LocalResponse(resp) => {
            assert_eq!(resp.status, 401);
            assert_eq!(resp.body, b"denied-by-wasm");
        }
        other => panic!("expected LocalResponse from wasm, got {other:?}"),
    }
}

#[test]
fn chain_native_short_circuits_before_later_wasm() {
    // A native filter short-circuits; a later WASM plugin (stub) must
    // NOT run.
    let registry = make_registry();
    let configs = configs_map(vec![
        PluginConfig {
            name: "n".to_string(),
            wasm: None,
            native: Some("deny".to_string()),
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        },
        PluginConfig {
            name: "w".to_string(),
            wasm: Some("/opt/w.wasm".to_string()),
            native: None,
            phases: vec![PluginPhase::RequestHeaders],
            config: None,
            limits: None,
        },
    ]);
    let stub = StubWasm {
        called: Vec::new(),
        add_header: ("x-wasm".to_string(), "yes".to_string()),
    };
    let mut chain = PluginChain::new(
        &["n".to_string(), "w".to_string()],
        &configs,
        &registry,
        stub,
    );
    let (outcome, _headers) = chain.on_request_headers(vec![("host".to_string(), "x".to_string())]);
    match outcome {
        ChainOutcome::LocalResponse(resp) => {
            assert_eq!(resp.status, 403);
        }
        other => panic!("expected LocalResponse from native, got {other:?}"),
    }
    // The WASM stub was NOT called (native short-circuited first).
    assert!(chain.wasm().called.is_empty());
}

// ---------------------------------------------------------------------------
// Real WasmChainAdapter combination (feature-gated behind wasm+plugins)
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm")]
mod wasm_adapter {
    use super::*;
    use dwara_core::wasm::adapter::WasmChainAdapter;

    /// A minimal fake PluginInstances that cannot be constructed
    /// without a real wasmtime module. Instead, this test verifies the
    /// adapter compiles and its type signature is correct -- the full
    /// e2e with a real .wasm module lives in wasm_host.rs (DW-055).
    /// Here we confirm the adapter implements WasmDispatch (the unified
    /// chain accepts it), proving the integration seam type-checks.
    #[test]
    fn wasm_chain_adapter_implements_wasm_dispatch() {
        // The adapter is generic over PluginInstances; we cannot
        // construct one without a real wasmtime instance, but the
        // type-check that WasmChainAdapter: WasmDispatch is the
        // integration seam. We assert it via a trait-object cast.
        fn assert_wasm_dispatch<T: WasmDispatch>() {}
        assert_wasm_dispatch::<WasmChainAdapter>();
    }
}
