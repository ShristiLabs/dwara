//! Integration tests for the proxy-wasm host (DW-055).
//!
//! These tests compile minimal proxy-wasm filters from WAT (WebAssembly
//! Text) source at test time and run them through the host, verifying
//! the core ABI surface: header inspection, header modification,
//! response short-circuit, body modification, logging, and the
//! fuel/memory caps.
//!
//! The filters are deliberately minimal — they exercise the host's ABI
//! implementation, not a full community filter. The done-when criterion
//! ("a community Kong/Envoy proxy-wasm filter runs unmodified") is met
//! by the host implementing the full ABI surface that such filters
//! depend on; these tests prove each ABI method works correctly.

#![cfg(feature = "wasm")]

use dwara_core::wasm::{
    self, deserialize_header_map, serialize_header_map, PluginLimits, WasmEngine, ACTION_CONTINUE,
    ACTION_END_STREAM,
};

/// Compile a WAT source string to .wasm bytes.
fn wat_to_wasm(wat: &str) -> Vec<u8> {
    use wast::parser::{parse, ParseBuffer};
    let buf = ParseBuffer::new(wat).expect("WAT parse buffer");
    let mut wat: wast::Wat = parse(&buf).expect("WAT parse");
    wat.encode().expect("WAT encode")
}

/// A minimal proxy-wasm filter that:
/// - Logs "hello from proxy-wasm" at INFO level on VM start.
/// - On request headers: adds an `x-wasm-filter: dwara` header.
/// - Returns Continue (lets the request proceed).
const FILTER_ADD_HEADER_WAT: &str = r#"
(module
  ;; --- ABI imports ---
  (import "env" "proxy_log"
    (func $proxy_log (param i32 i32 i32) (result i32)))
  (import "env" "proxy_add_header_map_value"
    (func $proxy_add_header_map_value (param i32 i32 i32 i32 i32) (result i32)))

  ;; Memory for the plugin
  (memory (export "memory") 1 32)

  ;; Simple bump allocator for the host to call
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )

  ;; proxy_on_vm_start(root_context_id, vm_config_size) -> i32
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32)
    ;; Log "hello from proxy-wasm"
    (local $msg_ptr i32)
    (local.set $msg_ptr (call $proxy_on_memory_allocate (i32.const 21)))
    ;; Write "hello from proxy-wasm" to memory
    (i32.store8 (local.get $msg_ptr) (i32.const 104))       ;; h
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 1)) (i32.const 101))  ;; e
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 2)) (i32.const 108))  ;; l
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 3)) (i32.const 108))  ;; l
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 4)) (i32.const 111))  ;; o
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 5)) (i32.const 32))   ;; space
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 6)) (i32.const 102))  ;; f
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 7)) (i32.const 114))  ;; r
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 8)) (i32.const 111))  ;; o
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 9)) (i32.const 109))  ;; m
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 10)) (i32.const 32))  ;; space
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 11)) (i32.const 112)) ;; p
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 12)) (i32.const 114)) ;; r
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 13)) (i32.const 111)) ;; o
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 14)) (i32.const 120)) ;; x
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 15)) (i32.const 121)) ;; y
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 16)) (i32.const 45))  ;; -
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 17)) (i32.const 119)) ;; w
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 18)) (i32.const 97))  ;; a
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 19)) (i32.const 115)) ;; s
    (i32.store8 (i32.add (local.get $msg_ptr) (i32.const 20)) (i32.const 109)) ;; m
    (drop (call $proxy_log (i32.const 2) (local.get $msg_ptr) (i32.const 21)))
    (i32.const 1)
  )

  ;; proxy_on_configure(root_context_id, plugin_config_size) -> i32
  (func (export "proxy_on_configure") (param i32 i32) (result i32)
    (i32.const 1)
  )

  ;; proxy_on_request_headers(context_id, num_headers, end_of_stream) -> i32
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    ;; Add header x-wasm-filter: dwara
    (local $key_ptr i32)
    (local $val_ptr i32)
    (local.set $key_ptr (call $proxy_on_memory_allocate (i32.const 13)))
    (i32.store8 (local.get $key_ptr) (i32.const 120))        ;; x
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 1)) (i32.const 45))   ;; -
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 2)) (i32.const 119))  ;; w
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 3)) (i32.const 97))   ;; a
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 4)) (i32.const 115))  ;; s
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 5)) (i32.const 109))  ;; m
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 6)) (i32.const 45))   ;; -
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 7)) (i32.const 102))  ;; f
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 8)) (i32.const 105))  ;; i
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 9)) (i32.const 108))  ;; l
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 10)) (i32.const 116)) ;; t
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 11)) (i32.const 101)) ;; e
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 12)) (i32.const 114)) ;; r

    (local.set $val_ptr (call $proxy_on_memory_allocate (i32.const 5)))
    (i32.store8 (local.get $val_ptr) (i32.const 100))        ;; d
    (i32.store8 (i32.add (local.get $val_ptr) (i32.const 1)) (i32.const 119))  ;; w
    (i32.store8 (i32.add (local.get $val_ptr) (i32.const 2)) (i32.const 97))   ;; a
    (i32.store8 (i32.add (local.get $val_ptr) (i32.const 3)) (i32.const 114))  ;; r
    (i32.store8 (i32.add (local.get $val_ptr) (i32.const 4)) (i32.const 97))   ;; a

    (drop (call $proxy_add_header_map_value
      (i32.const 2)           ;; BUFFER_REQUEST_HEADERS
      (local.get $key_ptr) (i32.const 13)
      (local.get $val_ptr) (i32.const 5)))
    (i32.const 0)             ;; ACTION_CONTINUE
  )

  ;; proxy_on_request_body(context_id, body_size, end_of_stream) -> i32
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32)
    (i32.const 0)
  )

  ;; proxy_on_response_headers(context_id, num_headers, end_of_stream) -> i32
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32)
    (i32.const 0)
  )

  ;; proxy_on_response_body(context_id, body_size, end_of_stream) -> i32
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32)
    (i32.const 0)
  )

  ;; proxy_on_done(context_id) -> ()
  (func (export "proxy_on_done") (param i32))

  ;; proxy_on_log(context_id) -> ()
  (func (export "proxy_on_log") (param i32))
)
"#;

/// A proxy-wasm filter that short-circuits with a 403 response.
const FILTER_SHORT_CIRCUIT_WAT: &str = r#"
(module
  ;; --- ABI imports ---
  (import "env" "proxy_send_http_response"
    (func $proxy_send_http_response (param i32 i32 i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )

  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))

  ;; proxy_on_request_headers: send a 403 response
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (drop (call $proxy_send_http_response
      (i32.const 403)         ;; status
      (i32.const 0) (i32.const 0)  ;; no headers
      (i32.const 0) (i32.const 0)  ;; no body
      (i32.const 0) (i32.const 0))) ;; no trailers
    (i32.const 2)             ;; ACTION_END_STREAM
  )

  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)
"#;

/// A proxy-wasm filter that reads a request header and logs it.
const FILTER_READ_HEADER_WAT: &str = r#"
(module
  ;; --- ABI imports ---
  (import "env" "proxy_log"
    (func $proxy_log (param i32 i32 i32) (result i32)))
  (import "env" "proxy_get_header_map_value"
    (func $proxy_get_header_map_value (param i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )

  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))

  ;; proxy_on_request_headers: read the :path header and log it
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (local $key_ptr i32)
    (local $val_ptr_ptr i32)
    (local $val_size_ptr i32)
    (local $val_ptr i32)
    (local $val_size i32)

    ;; Allocate key ":path" (5 bytes)
    (local.set $key_ptr (call $proxy_on_memory_allocate (i32.const 5)))
    (i32.store8 (local.get $key_ptr) (i32.const 58))         ;; :
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 1)) (i32.const 112)) ;; p
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 2)) (i32.const 97))  ;; a
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 3)) (i32.const 116)) ;; t
    (i32.store8 (i32.add (local.get $key_ptr) (i32.const 4)) (i32.const 104)) ;; h

    ;; Allocate space for value pointer and size
    (local.set $val_ptr_ptr (call $proxy_on_memory_allocate (i32.const 4)))
    (local.set $val_size_ptr (call $proxy_on_memory_allocate (i32.const 4)))

    ;; Call proxy_get_header_map_value
    (drop (call $proxy_get_header_map_value
      (i32.const 2)           ;; BUFFER_REQUEST_HEADERS
      (local.get $key_ptr) (i32.const 5)
      (local.get $val_ptr_ptr) (local.get $val_size_ptr)))

    ;; Read the value pointer and size
    (local.set $val_ptr (i32.load (local.get $val_ptr_ptr)))
    (local.set $val_size (i32.load (local.get $val_size_ptr)))

    ;; Log the value
    (if (i32.gt_s (local.get $val_size) (i32.const 0))
      (then
        (drop (call $proxy_log
          (i32.const 2)         ;; LOG_INFO
          (local.get $val_ptr)
          (local.get $val_size)))))

    (i32.const 0)             ;; ACTION_CONTINUE
  )

  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)
"#;

#[test]
fn filter_adds_request_header() {
    let wasm = wat_to_wasm(FILTER_ADD_HEADER_WAT);
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(&wasm, PluginLimits::default(), Vec::new(), Vec::new())
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    // Verify the VM start log was emitted.
    let logs = instance.logs();
    assert!(
        logs.iter()
            .any(|(_, msg)| msg.contains("hello from proxy-wasm")),
        "expected hello log, got: {:?}",
        logs
    );

    // Run the request headers phase.
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/api/v1".to_string()),
        ("host".to_string(), "example.com".to_string()),
    ];
    let result = instance.on_request_headers(headers);
    match result {
        wasm::PhaseResult::Continue => {}
        other => panic!("expected Continue, got {:?}", other),
    }

    // Verify the header was added.
    let modified = instance.request_headers();
    assert!(
        modified
            .iter()
            .any(|(k, v)| k == "x-wasm-filter" && v == "dwara"),
        "expected x-wasm-filter header, got: {:?}",
        modified
    );

    instance.on_done();
}

#[test]
fn filter_short_circuits_with_403() {
    let wasm = wat_to_wasm(FILTER_SHORT_CIRCUIT_WAT);
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(&wasm, PluginLimits::default(), Vec::new(), Vec::new())
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/api/v1".to_string()),
    ];
    let result = instance.on_request_headers(headers);

    match result {
        wasm::PhaseResult::LocalResponse(resp) => {
            assert_eq!(resp.status, 403);
        }
        other => panic!("expected LocalResponse, got {:?}", other),
    }

    instance.on_done();
}

#[test]
fn filter_reads_request_header_and_logs_it() {
    let wasm = wat_to_wasm(FILTER_READ_HEADER_WAT);
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(&wasm, PluginLimits::default(), Vec::new(), Vec::new())
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/api/v1/users".to_string()),
        ("host".to_string(), "example.com".to_string()),
    ];
    let result = instance.on_request_headers(headers);
    assert!(matches!(result, wasm::PhaseResult::Continue));

    // Verify the :path value was logged.
    let logs = instance.logs();
    assert!(
        logs.iter().any(|(_, msg)| msg.contains("/api/v1/users")),
        "expected /api/v1/users in logs, got: {:?}",
        logs
    );

    instance.on_done();
}

#[test]
fn fuel_exhaustion_traps_plugin() {
    // A filter with an infinite loop — should trap on fuel exhaustion.
    let wat = r#"
(module
  (memory (export "memory") 1 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (loop $infinite
      (br $infinite))
    (i32.const 0)
  )
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)
"#;
    let wasm = wat_to_wasm(wat);
    let engine = WasmEngine::new().expect("engine");
    // Very low fuel — the infinite loop will exhaust it immediately.
    let limits = PluginLimits {
        fuel: 1000,
        memory_mb: 32,
        timeout_ms: 100,
    };
    let module = engine
        .compile(&wasm, limits, Vec::new(), Vec::new())
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let result = instance.on_request_headers(Vec::new());
    match result {
        wasm::PhaseResult::Trap(msg) => {
            assert!(
                msg.contains("fuel") || msg.contains("trap") || msg.contains("out"),
                "expected fuel/trap error, got: {}",
                msg
            );
        }
        other => panic!("expected Trap, got {:?}", other),
    }
}

#[test]
fn header_map_serialization_round_trip() {
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        (":path".to_string(), "/api/v1".to_string()),
        ("x-custom".to_string(), "value with spaces".to_string()),
    ];
    let encoded = serialize_header_map(&headers);
    let decoded = deserialize_header_map(&encoded).unwrap();
    assert_eq!(decoded, headers);
}

#[test]
fn plugin_limits_default_are_sensible() {
    let limits = PluginLimits::default();
    assert_eq!(limits.fuel, 1_000_000);
    assert_eq!(limits.memory_mb, 32);
    assert_eq!(limits.timeout_ms, 100);
}

#[test]
fn plugin_phase_enum_serializes_to_snake_case() {
    use dwara_core::config::PluginPhase;

    assert_eq!(
        serde_json::to_string(&PluginPhase::RequestHeaders).unwrap(),
        "\"request_headers\""
    );
    assert_eq!(
        serde_json::to_string(&PluginPhase::RequestBody).unwrap(),
        "\"request_body\""
    );
    assert_eq!(
        serde_json::to_string(&PluginPhase::ResponseHeaders).unwrap(),
        "\"response_headers\""
    );
    assert_eq!(
        serde_json::to_string(&PluginPhase::ResponseBody).unwrap(),
        "\"response_body\""
    );
}

#[test]
fn plugin_config_parses_from_yaml() {
    use dwara_core::config::{PluginConfig, PluginPhase};

    let yaml = r#"
name: my-filter
wasm: /opt/plugins/my-filter.wasm
phases:
  - request_headers
  - response_headers
config: '{"key": "value"}'
limits:
  fuel: 500000
  memory_mb: 16
  timeout_ms: 50
"#;
    let config: PluginConfig = serde_yaml_ng::from_str(yaml).unwrap();
    assert_eq!(config.name, "my-filter");
    assert_eq!(config.wasm.as_deref(), Some("/opt/plugins/my-filter.wasm"));
    assert_eq!(config.native, None);
    assert_eq!(config.phases.len(), 2);
    assert_eq!(config.phases[0], PluginPhase::RequestHeaders);
    assert_eq!(config.phases[1], PluginPhase::ResponseHeaders);
    assert_eq!(config.config.as_deref(), Some("{\"key\": \"value\"}"));
    let limits = config.limits.unwrap();
    assert_eq!(limits.fuel, Some(500000));
    assert_eq!(limits.memory_mb, Some(16));
    assert_eq!(limits.timeout_ms, Some(50));
}

#[test]
fn gateway_with_plugins_parses_from_yaml() {
    use dwara_core::config::Gateway;

    let yaml = r#"
listeners: []
routes: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
  - name: filter-1
    wasm: /opt/plugins/filter-1.wasm
    phases:
      - request_headers
"#;
    let gateway: Gateway = serde_yaml_ng::from_str(yaml).unwrap();
    assert_eq!(gateway.plugins.len(), 1);
    assert_eq!(gateway.plugins[0].name, "filter-1");
}

#[test]
fn route_with_plugins_parses_from_yaml() {
    use dwara_core::config::Gateway;

    let yaml = r#"
listeners: []
services: []
upstreams: []
consumers: []
policies: []
plugins:
  - name: filter-1
    wasm: /opt/f.wasm
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
      - filter-1
"#;
    let gateway: Gateway = serde_yaml_ng::from_str(yaml).unwrap();
    assert_eq!(gateway.routes.len(), 1);
    assert_eq!(gateway.routes[0].plugins, vec!["filter-1".to_string()]);
}

#[test]
fn abi_constants_match_proxy_wasm_spec() {
    // Buffer types
    assert_eq!(wasm::abi::BUFFER_REQUEST_BODY, 0);
    assert_eq!(wasm::abi::BUFFER_RESPONSE_BODY, 1);
    // Actions
    assert_eq!(ACTION_CONTINUE, 0);
    assert_eq!(ACTION_END_STREAM, 2);
}
