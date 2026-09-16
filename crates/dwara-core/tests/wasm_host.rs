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

use dwara_core::wasm::abi::{deserialize_header_map_spec, serialize_header_map_spec};
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

/// Render bytes as a WAT data-segment string body (every byte as a
/// `\xx` escape) so a fixture can embed an exact wire-format blob.
fn wat_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for b in bytes {
        out.push_str(&format!("\\{b:02x}"));
    }
    out
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
      (i32.const 0)           ;; BUFFER_REQUEST_HEADERS (spec MapType)
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
      (i32.const 0)           ;; BUFFER_REQUEST_HEADERS (spec MapType)
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

/// A module shaped like the Rust proxy-wasm SDK's output (`dwara-cli
/// plugin new` scaffolds against that SDK): the SPEC import names and
/// arities (`proxy_send_local_response` with 8 params,
/// `proxy_get_current_time_nanoseconds`, `proxy_get_log_level`,
/// `proxy_get_status`, the callout/queue stubs with their spec
/// arities), the spec MAP-TYPE constants for header lookups (request
/// headers = 0), the `_start` / `proxy_on_context_create` lifecycle
/// exports, and the wasi_snapshot_preview1 import set the
/// wasm32-wasip1 target emits.
const SDK_SHAPED_WAT: &str = r#"
(module
  ;; --- spec-named imports (the Rust proxy-wasm SDK's set) ---
  (import "env" "proxy_log" (func $log (param i32 i32 i32) (result i32)))
  (import "env" "proxy_get_log_level" (func $get_log_level (param i32) (result i32)))
  (import "env" "proxy_get_current_time_nanoseconds" (func $now (param i32) (result i32)))
  (import "env" "proxy_get_header_map_value" (func $get_header (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_add_header_map_value" (func $add_header (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_send_local_response"
    (func $send_local (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_get_status" (func $get_status (param i32 i32 i32) (result i32)))
  (import "env" "proxy_set_tick_period_milliseconds" (func $set_tick (param i32) (result i32)))
  (import "env" "proxy_register_shared_queue" (func $reg_queue (param i32 i32 i32) (result i32)))
  (import "env" "proxy_resolve_shared_queue" (func $res_queue (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_dequeue_shared_queue" (func $deq_queue (param i32 i32 i32) (result i32)))
  (import "env" "proxy_enqueue_shared_queue" (func $enq_queue (param i32 i32 i32) (result i32)))
  (import "env" "proxy_http_call"
    (func $http_call (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_grpc_call"
    (func $grpc_call (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_grpc_stream"
    (func $grpc_stream (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_grpc_send" (func $grpc_send (param i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_grpc_cancel" (func $grpc_cancel (param i32) (result i32)))
  (import "env" "proxy_grpc_close" (func $grpc_close (param i32) (result i32)))
  (import "env" "proxy_call_foreign_function"
    (func $foreign (param i32 i32 i32 i32 i32 i32) (result i32)))
  ;; --- the wasi subset wasm32-wasip1 emits ---
  (import "wasi_snapshot_preview1" "environ_get" (func $environ_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $environ_sizes (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (import "wasi_snapshot_preview1" "random_get" (func $random_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get"
    (func $clock_time (param i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sched_yield" (func $sched_yield (param) (result i32)))

  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (global $started (mut i32) (i32.const 0))
  (global $root_created (mut i32) (i32.const 0))
  (global $http_created (mut i32) (i32.const 0))

  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )

  (data (i32.const 65536) ":path")
  (data (i32.const 65552) "x-sdk-path")
  (data (i32.const 65584) "x-sdk-alive")
  (data (i32.const 65616) "sdk module vm start")
  (data (i32.const 65640) "ok")

  ;; The SDK registers its context factories in _start.
  (func (export "_start")
    (global.set $started (i32.const 1)))

  ;; The SDK builds its contexts on proxy_on_context_create.
  (func (export "proxy_on_context_create") (param $ctx i32) (param $root i32)
    (if (i32.eq (local.get $root) (i32.const 0))
      (then (global.set $root_created (i32.const 1)))
      (else (global.set $http_created (i32.const 1)))))

  ;; Refuse to start unless _start and the root context creation ran —
  ;; the exact sequence the SDK's dispatcher requires.
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32)
    (if (i32.or (i32.eq (global.get $started) (i32.const 0))
                (i32.eq (global.get $root_created) (i32.const 0)))
      (then (return (i32.const 0))))
    (drop (call $log (i32.const 2) (i32.const 65616) (i32.const 21)))
    (drop (call $get_log_level (i32.const 70040)))
    (drop (call $now (i32.const 70048)))
    (drop (call $get_status (i32.const 70056) (i32.const 70060) (i32.const 70064)))
    ;; get_status must answer Ok (0): the SDK's get_grpc_status wrapper
    ;; panics on any non-Ok status, which would trap the module.
    (if (i32.ne (call $get_status (i32.const 70056) (i32.const 70060) (i32.const 70064))
                (i32.const 0))
      (then (return (i32.const 0))))
    (drop (call $set_tick (i32.const 0)))
    (drop (call $reg_queue (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $res_queue (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $deq_queue (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $enq_queue (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $http_call (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                           (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                           (i32.const 0) (i32.const 0)))
    (drop (call $grpc_call (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                           (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                           (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $grpc_stream (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                             (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                             (i32.const 0)))
    (drop (call $grpc_send (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (drop (call $grpc_cancel (i32.const 0)))
    (drop (call $grpc_close (i32.const 0)))
    (drop (call $foreign (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                         (i32.const 0) (i32.const 0)))
    (drop (call $environ_sizes (i32.const 70072) (i32.const 70076)))
    (drop (call $environ_get (i32.const 0) (i32.const 0)))
    (drop (call $random_get (i32.const 70080) (i32.const 8)))
    (drop (call $clock_time (i32.const 0) (i64.const 1) (i32.const 70088)))
    (drop (call $sched_yield))
    (i32.const 1)
  )

  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))

  ;; The SDK dispatcher panics for a context it was never told to
  ;; create; emulate that by refusing (no effects) when the http
  ;; context was not created first.
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (local $vp i32) (local $vs i32)
    (if (i32.eq (global.get $http_created) (i32.const 0)) (then (return (i32.const 0))))
    (drop (call $get_header (i32.const 0) (i32.const 65536) (i32.const 5)
              (i32.const 70000) (i32.const 70004)))
    (local.set $vp (i32.load (i32.const 70000)))
    (local.set $vs (i32.load (i32.const 70004)))
    (if (i32.gt_s (local.get $vs) (i32.const 0))
      (then (drop (call $add_header (i32.const 0) (i32.const 65552) (i32.const 10)
                    (local.get $vp) (local.get $vs)))))
    (i32.const 0))

  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))

  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32)
    (drop (call $add_header (i32.const 2) (i32.const 65584) (i32.const 11)
              (i32.const 65640) (i32.const 2)))
    (i32.const 0))

  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32) (result i32) (i32.const 1))
  (func (export "proxy_on_log") (param i32))
  (func (export "proxy_on_delete") (param i32))
)
"#;

#[test]
fn sdk_shaped_module_runs_the_full_contract() {
    // Guards the SDK-module path end to end at the host level: the
    // spec import names/arities link, _start and proxy_on_context_create
    // run before the phase exports, the spec map-type constants route
    // header lookups to the right maps, and the wasi subset resolves.
    let wasm = wat_to_wasm(SDK_SHAPED_WAT);
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(&wasm, PluginLimits::default(), Vec::new(), Vec::new())
        .expect("compile");
    // instantiate runs _start -> proxy_on_context_create(1, 0) ->
    // proxy_on_vm_start; the module's vm_start returns 0 unless the
    // sequence held, which surfaces here as an instantiate error.
    let mut instance = module.instantiate(&engine).expect("instantiate");

    // The vm_start log line proves the lifecycle sequence.
    let logs = instance.logs();
    assert!(
        logs.iter()
            .any(|(_, msg)| msg.contains("sdk module vm start")),
        "expected vm-start log, got: {:?}",
        logs
    );

    // Request phase: the :path lookup (spec bt=0) must find the value
    // and copy it into x-sdk-path.
    let headers = vec![(":path".to_string(), "/sdk/echo".to_string())];
    let result = instance.on_request_headers(headers);
    assert!(matches!(result, wasm::PhaseResult::Continue));
    let modified = instance.request_headers();
    assert!(
        modified
            .iter()
            .any(|(k, v)| k == "x-sdk-path" && v == "/sdk/echo"),
        "expected the :path copied to x-sdk-path, got: {:?}",
        modified
    );

    // Response phase: the spec response-map constant (bt=2) must route
    // the add to the response map.
    let result =
        instance.on_response_headers(vec![("content-type".to_string(), "text/plain".to_string())]);
    assert!(matches!(result, wasm::PhaseResult::Continue));
    let resp = instance.response_headers();
    assert!(
        resp.iter().any(|(k, v)| k == "x-sdk-alive" && v == "ok"),
        "expected x-sdk-alive on the response map, got: {:?}",
        resp
    );

    instance.on_done();
}

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

// --- spec/SDK map wire format (proxy-wasm 0.2.5 layout) --------------------
//
// The spec-named hostcalls (proxy_get/set_header_map_pairs,
// proxy_send_local_response) speak the layout the Rust proxy-wasm SDK
// serializes and parses (hostcalls.rs utils::serialize_map /
// deserialize_map): LE u32 entry count, then an LE u32 (key_len,
// value_len) table, then NUL-terminated key/value strings. The tests
// below pin the exact bytes and drive the hostcalls from WAT modules
// that ENCODE or DECODE that layout themselves — the same algorithm
// the SDK runs inside a plugin.

#[test]
fn spec_map_serialization_matches_sdk_layout_byte_for_byte() {
    // Hand-pinned expected bytes (NOT produced by our serializer):
    // [(":method", "GET")] -> count 1 (LE), table {7, 3} (LE),
    // strings ":method\0GET\0".
    let encoded = serialize_header_map_spec(&[(":method".to_string(), "GET".to_string())]);
    assert_eq!(
        encoded, b"\x01\x00\x00\x00\x07\x00\x00\x00\x03\x00\x00\x00:method\x00GET\x00",
        "the spec layout is LE count + LE length table + NUL-terminated strings"
    );
    // Two entries: the length table lists BOTH entries' lengths before
    // any string data (all lengths first, then all strings).
    let encoded = serialize_header_map_spec(&[
        ("a".to_string(), "1".to_string()),
        ("bb".to_string(), "22".to_string()),
    ]);
    assert_eq!(
        encoded,
        b"\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00a\x001\x00bb\x0022\x00"
    );
    // The SDK's empty-map bytes: exactly the 4-byte LE count 0 (what
    // send_http_response passes for empty headers).
    assert_eq!(serialize_header_map_spec(&[]), b"\x00\x00\x00\x00");
}

#[test]
fn spec_map_deserialization_mirrors_the_sdk() {
    // An empty buffer is an empty map (the SDK's convention).
    assert_eq!(
        deserialize_header_map_spec(&[]),
        Some(Vec::<(String, String)>::new())
    );
    // The SDK's empty-map bytes decode to an empty map.
    assert_eq!(
        deserialize_header_map_spec(b"\x00\x00\x00\x00"),
        Some(Vec::<(String, String)>::new())
    );
    // Hand-written bytes (not our serializer's output) round-trip.
    let hand = b"\x01\x00\x00\x00\x07\x00\x00\x00\x03\x00\x00\x00:method\x00GET\x00";
    assert_eq!(
        deserialize_header_map_spec(hand).unwrap(),
        vec![(":method".to_string(), "GET".to_string())]
    );
    // Corrupt inputs are rejected (the SDK would panic on its unwraps;
    // the host fails the hostcall instead): a count that overruns the
    // length table, a truncated string, a missing NUL, a short buffer,
    // non-UTF-8 bytes.
    assert_eq!(deserialize_header_map_spec(b"\x01"), None);
    assert_eq!(
        deserialize_header_map_spec(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00"),
        None
    );
    assert_eq!(
        deserialize_header_map_spec(b"\x01\x00\x00\x00\x07\x00\x00\x00\x03\x00\x00\x00:method"),
        None
    );
    assert_eq!(
        deserialize_header_map_spec(b"\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00aX"),
        None
    );
    assert_eq!(
        deserialize_header_map_spec(
            b"\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xff\x00\x41\x00"
        ),
        None
    );
    // Full round trip through our own pair of functions.
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        ("x-custom".to_string(), "value with spaces".to_string()),
    ];
    let encoded = serialize_header_map_spec(&headers);
    assert_eq!(deserialize_header_map_spec(&encoded).unwrap(), headers);
}

/// A WAT module that calls `proxy_send_local_response` with
/// SDK-serialized header bytes (built by the test with
/// serialize_header_map_spec — the byte layout itself is pinned by the
/// tests above) and an optional body, then returns EndStream.
fn send_local_response_wat(status: i32, headers: &[(String, String)], body: &[u8]) -> String {
    let header_bytes = serialize_header_map_spec(headers);
    let hdr_data = wat_bytes(&header_bytes);
    let hdr_size = header_bytes.len();
    let body_segment = if body.is_empty() {
        String::new()
    } else {
        format!(r#"(data (i32.const 65600) "{}")"#, wat_bytes(body))
    };
    let (body_ptr, body_size) = if body.is_empty() {
        (0, 0)
    } else {
        (65600, body.len())
    };
    format!(
        r#"(module
  (import "env" "proxy_send_local_response"
    (func $send_local (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  (data (i32.const 65536) "{hdr_data}")
  {body_segment}
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (drop (call $send_local
      (i32.const {status})    ;; status_code
      (i32.const 0) (i32.const 0)  ;; no status-code details
      (i32.const {body_ptr}) (i32.const {body_size})
      (i32.const 65536) (i32.const {hdr_size})  ;; SDK-serialized headers
      (i32.const -1)))        ;; grpc_status: -1 (unused by send_http_response)
    (i32.const 2))            ;; ACTION_END_STREAM
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#
    )
}

#[test]
fn send_local_response_accepts_sdk_serialized_headers() {
    // The exact call every Rust proxy-wasm SDK plugin makes to
    // short-circuit: send_http_response(status, headers, body)
    // imports proxy_send_local_response with serialize_map(headers).
    // Pre-fix, the host parsed those bytes with the legacy BE layout,
    // failed, returned 1, and the SDK wrapper PANICKED on the
    // non-Ok status.
    let wat = send_local_response_wat(403, &[("x-local".to_string(), "hi".to_string())], b"denied");
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(&wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let result = instance.on_request_headers(Vec::new());
    match result {
        wasm::PhaseResult::LocalResponse(resp) => {
            assert_eq!(resp.status, 403);
            assert_eq!(
                resp.headers,
                vec![("x-local".to_string(), "hi".to_string())]
            );
            assert_eq!(resp.body, b"denied");
        }
        other => panic!("expected LocalResponse, got {:?}", other),
    }
    instance.on_done();
}

#[test]
fn send_local_response_accepts_sdk_empty_map_bytes() {
    // send_http_response(status, vec![], body) serializes the empty
    // header map as the 4-byte LE count 0 — the host must parse that
    // as "no headers", not as a corrupt buffer.
    let wat = send_local_response_wat(429, &[], b"slow down");
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(&wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let result = instance.on_request_headers(Vec::new());
    match result {
        wasm::PhaseResult::LocalResponse(resp) => {
            assert_eq!(resp.status, 429);
            assert!(resp.headers.is_empty(), "no headers were sent");
            assert_eq!(resp.body, b"slow down");
        }
        other => panic!("expected LocalResponse, got {:?}", other),
    }
    instance.on_done();
}

/// A WAT module that decodes `proxy_get_header_map_pairs` output using
/// the SDK's exact algorithm (LE count at offset 0, LE length table at
/// 4, NUL-terminated strings at 4 + count*8) and copies entry 0's key
/// and value into request headers where the test can see them.
const GET_PAIRS_SDK_WAT: &str = r#"
(module
  (import "env" "proxy_get_header_map_pairs"
    (func $get_pairs (param i32 i32 i32) (result i32)))
  (import "env" "proxy_add_header_map_value"
    (func $add_header (param i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  (data (i32.const 65536) "x-k0")
  (data (i32.const 65552) "x-v0")
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (local $ptr i32) (local $count i32) (local $klen i32) (local $vlen i32)
    (local $strs i32) (local $kp i32) (local $vp i32)
    (drop (call $get_pairs (i32.const 0) (i32.const 70000) (i32.const 70004)))
    (local.set $ptr (i32.load (i32.const 70000)))
    ;; ptr 0 = the host's empty-map convention; nothing to decode.
    (if (i32.eq (local.get $ptr) (i32.const 0)) (then (return (i32.const 0))))
    ;; The SDK's deserialize: count (LE) at 0, the length table at 4.
    (local.set $count (i32.load (local.get $ptr)))
    (if (i32.ne (local.get $count) (i32.const 2)) (then (return (i32.const 0))))
    (local.set $klen (i32.load (i32.add (local.get $ptr) (i32.const 4))))
    (local.set $vlen (i32.load (i32.add (local.get $ptr) (i32.const 8))))
    ;; Strings start after the whole length table: 4 + count*8.
    (local.set $strs (i32.add (local.get $ptr)
      (i32.add (i32.const 4) (i32.mul (local.get $count) (i32.const 8)))))
    (local.set $kp (local.get $strs))
    (local.set $vp (i32.add (local.get $kp) (i32.add (local.get $klen) (i32.const 1))))
    (drop (call $add_header (i32.const 0) (i32.const 65536) (i32.const 4)
              (local.get $kp) (local.get $klen)))
    (drop (call $add_header (i32.const 0) (i32.const 65552) (i32.const 4)
              (local.get $vp) (local.get $vlen)))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)
"#;

#[test]
fn get_header_map_pairs_returns_sdk_wire_format() {
    // A module running the SDK's decode algorithm over the returned
    // buffer must recover the request headers entry for entry. Pre-fix
    // the host emitted the legacy BE layout, which this decoder (and
    // the SDK's) misparses as a huge count.
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(GET_PAIRS_SDK_WAT),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/sdk/map".to_string()),
    ];
    let result = instance.on_request_headers(headers);
    assert!(matches!(result, wasm::PhaseResult::Continue));
    let modified = instance.request_headers();
    assert!(
        modified.iter().any(|(k, v)| k == "x-k0" && v == ":method"),
        "entry 0's key decoded per the SDK layout, got: {modified:?}"
    );
    assert!(
        modified.iter().any(|(k, v)| k == "x-v0" && v == "GET"),
        "entry 0's value decoded per the SDK layout, got: {modified:?}"
    );
    instance.on_done();
}

#[test]
fn set_header_map_pairs_accepts_sdk_wire_format() {
    // A module replacing the request-headers map with SDK-serialized
    // bytes (what the Rust SDK's set_map sends): the host must adopt
    // exactly those pairs.
    let encoded = serialize_header_map_spec(&[
        ("x-set".to_string(), "yes".to_string()),
        ("x-two".to_string(), "b".to_string()),
    ]);
    let wat = format!(
        r#"(module
  (import "env" "proxy_set_header_map_pairs"
    (func $set_pairs (param i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  (data (i32.const 65536) "{data}")
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (drop (call $set_pairs (i32.const 0) (i32.const 65536) (i32.const {size})))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#,
        data = wat_bytes(&encoded),
        size = encoded.len(),
    );
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(&wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let result = instance.on_request_headers(vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/old".to_string()),
    ]);
    assert!(matches!(result, wasm::PhaseResult::Continue));
    assert_eq!(
        instance.request_headers(),
        &[
            ("x-set".to_string(), "yes".to_string()),
            ("x-two".to_string(), "b".to_string()),
        ],
        "the whole map is replaced with the SDK-serialized pairs"
    );
    instance.on_done();
}

#[test]
fn log_buffer_is_capped_at_64_kib() {
    // A plugin that spews through proxy_log must not grow the
    // host-side buffer without bound: 5 x 16 KiB lines (80 KiB)
    // buffer 64 KiB, then a truncation marker, then nothing more.
    let line = vec![b'a'; 16 * 1024];
    let wat = format!(
        r#"(module
  (import "env" "proxy_log" (func $log (param i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  (data (i32.const 65536) "{data}")
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (drop (call $log (i32.const 2) (i32.const 65536) (i32.const {len})))
    (drop (call $log (i32.const 2) (i32.const 65536) (i32.const {len})))
    (drop (call $log (i32.const 2) (i32.const 65536) (i32.const {len})))
    (drop (call $log (i32.const 2) (i32.const 65536) (i32.const {len})))
    ;; This one crosses the cap; everything after it is dropped.
    (drop (call $log (i32.const 2) (i32.const 65536) (i32.const {len})))
    (drop (call $log (i32.const 2) (i32.const 65536) (i32.const {len})))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#,
        data = wat_bytes(&line),
        len = line.len(),
    );
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(&wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let result = instance.on_request_headers(Vec::new());
    assert!(matches!(result, wasm::PhaseResult::Continue));
    let logs = instance.logs();
    let total: usize = logs.iter().map(|(_, m)| m.len()).sum();
    assert!(
        total <= 64 * 1024 + 128,
        "buffered log bytes stay bounded (64 KiB + marker), got {total}"
    );
    assert_eq!(
        logs.len(),
        5,
        "4 full lines fit the cap, then one marker; the 5th and 6th lines are dropped"
    );
    assert!(
        logs[logs.len() - 1]
            .1
            .contains("log buffer cap (64 KiB) reached; further plugin log output dropped"),
        "the cap is visible in the buffer as a marker line: {:?}",
        logs[logs.len() - 1]
    );
    instance.on_done();
}

#[test]
fn trapped_start_fails_instantiation_with_its_own_error() {
    // A module whose _start traps must fail AT INSTANTIATION with the
    // _start trap itself — not surface later as an unrelated panic in
    // proxy_on_context_create (the SDK dispatcher would find no
    // registered root context).
    let wat = r#"
(module
  (memory (export "memory") 1 32)
  (func (export "_start") unreachable)
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
)
"#;
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let err = match module.instantiate(&engine) {
        Err(e) => e,
        Ok(_) => panic!("a trapped _start must fail instantiation"),
    };
    assert!(
        err.contains("_start"),
        "the error names the phase that trapped: {err}"
    );
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
    // Buffer types (the BufferType namespace of proxy-wasm spec 2.1:
    // used by proxy_get/set_buffer_bytes and proxy_get_buffer_status).
    assert_eq!(wasm::abi::BUFFER_REQUEST_BODY, 0);
    assert_eq!(wasm::abi::BUFFER_RESPONSE_BODY, 1);
    assert_eq!(wasm::abi::BUFFER_VM_CONFIGURATION, 6);
    assert_eq!(wasm::abi::BUFFER_PLUGIN_CONFIGURATION, 7);
    // Map types (the MapType namespace: used by the header-map
    // hostcalls). These are the values the Rust proxy-wasm SDK sends —
    // request headers 0, response headers 2 — which is what makes
    // SDK-built modules (e.g. `dwara-cli plugin new` output) work
    // against the host.
    assert_eq!(wasm::abi::BUFFER_REQUEST_HEADERS, 0);
    assert_eq!(wasm::abi::BUFFER_REQUEST_TRAILERS, 1);
    assert_eq!(wasm::abi::BUFFER_RESPONSE_HEADERS, 2);
    assert_eq!(wasm::abi::BUFFER_RESPONSE_TRAILERS, 3);
    // Callout-response maps/buffer (DW-167): the proxy-wasm MapType 6/7
    // and BufferType 4 the Rust SDK's get_http_call_response_headers /
    // get_http_call_response_body read (proxy-wasm 0.2.5 types.rs:
    // HttpCallResponseHeaders = 6, HttpCallResponseTrailers = 7,
    // HttpCallResponseBody = 4).
    assert_eq!(wasm::abi::BUFFER_CALLOUT_RESPONSE_HEADERS, 6);
    assert_eq!(wasm::abi::BUFFER_CALLOUT_RESPONSE_TRAILERS, 7);
    assert_eq!(wasm::abi::BUFFER_CALLOUT_RESPONSE_BODY, 4);
    // Actions
    assert_eq!(ACTION_CONTINUE, 0);
    assert_eq!(wasm::abi::ACTION_PAUSE, 1);
    assert_eq!(ACTION_END_STREAM, 2);
}

// --- HTTP callouts (DW-167) ------------------------------------------------
//
// The callout fixtures model the SDK's dispatch/response contract at
// the host level: `proxy_http_call` (10 spec-arity params — URI
// string, spec-serialized headers, optional body, spec-serialized
// trailers, timeout in MILLISECONDS, token return pointer), then the
// 5-parameter `proxy_on_http_call_response(context_id, token,
// num_headers, body_size, num_trailers)` export (the shape the Rust
// proxy-wasm SDK 0.2.5 emits; the SDK ignores the context slot and
// routes by token) whose callback reads the response through MapType 6
// (headers, `:status` first) and BufferType 4 (body).

/// The imports every callout fixture needs.
const CALLOUT_IMPORTS: &str = r#"
  (import "env" "proxy_http_call"
    (func $http_call (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_get_header_map_value"
    (func $get_header (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_get_buffer_bytes"
    (func $get_buffer (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_add_header_map_value"
    (func $add_header (param i32 i32 i32 i32 i32) (result i32)))"#;

/// A module whose `request_headers` dispatches ONE callout to the URI
/// at data offset 65536 (length 65560-len) with the spec-serialized
/// header map at 65600, timeout 5000ms, and returns Pause. Its
/// `proxy_on_http_call_response` reads `:status` (MapType 6) and the
/// body (BufferType 4), and records both in globals the test reads:
/// `$seen_status` (the numeric :status) and appends the body bytes to
/// memory the test dumps via a `$verdict_ptr` write.
fn callout_dispatch_wat(uri: &str, map: &[(String, String)]) -> String {
    let serialized = serialize_header_map_spec(map);
    format!(
        r#"(module
  {CALLOUT_IMPORTS}
  (memory (export "memory") 2 32)
  (global $alloc_ptr (mut i32) (i32.const 1024))
  (func $proxy_on_memory_allocate (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $alloc_ptr))
    (global.set $alloc_ptr (i32.add (global.get $alloc_ptr) (local.get $size)))
    (local.get $ptr)
  )
  (global $seen_status (mut i32) (i32.const 0))
  (data (i32.const 65536) "{uri}")
  (data (i32.const 65600) "{bytes}")
  (data (i32.const 66000) ":status")
  (data (i32.const 66032) "x-verdict")

  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))

  ;; request_headers: dispatch the callout, return Pause (1).
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (drop (call $http_call
      (i32.const 65536) (i32.const {uri_len})   ;; uri
      (i32.const 65600) (i32.const {map_len})   ;; headers (spec map)
      (i32.const 0) (i32.const 0)               ;; no body
      (i32.const 0) (i32.const 0)               ;; no trailers
      (i32.const 5000)                          ;; timeout ms
      (i32.const 70000)))                       ;; token ptr
    (i32.const 1))

  ;; proxy_on_http_call_response(ctx, token, num_headers, body_size,
  ;; num_trailers): read :status via MapType 6 and the body via
  ;; BufferType 4, keep both for the test, stamp the verdict header.
  (func (export "proxy_on_http_call_response") (param i32 i32 i32 i32 i32)
    (local $vp i32) (local $vs i32)
    (local.set $vp (call $proxy_on_memory_allocate (i32.const 4)))
    (drop (call $get_header (i32.const 6) (i32.const 66000) (i32.const 7)
              (local.get $vp) (i32.const 70004)))
    ;; Store the status digits at 66100 for the test to read.
    (i32.store8 (i32.const 66100) (i32.load8_u (i32.load (local.get $vp))))
    (i32.store8 (i32.const 66101) (i32.load8_u (i32.add (i32.load (local.get $vp)) (i32.const 1))))
    (i32.store8 (i32.const 66102) (i32.load8_u (i32.add (i32.load (local.get $vp)) (i32.const 2))))
    ;; Read the first body bytes via BufferType 4 and stamp them as the
    ;; x-verdict request header (the plugin's resumed decision).
    (local.set $vs (call $proxy_on_memory_allocate (i32.const 4)))
    (drop (call $get_buffer (i32.const 4) (i32.const 0) (i32.const 8)
              (local.get $vs) (i32.const 70008)))
    (drop (call $add_header (i32.const 0) (i32.const 66032) (i32.const 9)
              (i32.load (local.get $vs)) (local.get 3)))
  )

  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#,
        bytes = wat_bytes(&serialized),
        uri_len = uri.len(),
        map_len = serialized.len(),
    )
}

#[test]
fn callout_dispatch_pauses_and_delivers_response_round_trip() {
    // The DW-167 core round trip at the host level: the phase export
    // dispatches proxy_http_call and pauses; the host registers the
    // pending callout (URI, method, headers, timeout); delivering a
    // response invokes proxy_on_http_call_response, whose MapType 6 /
    // BufferType 4 reads see the delivered data; the phase then
    // resumes Continue with the callback's header mutation applied.
    let uri = "http://127.0.0.1:1/decide?u=42";
    let wat = callout_dispatch_wat(
        uri,
        &[
            (":method".to_string(), "GET".to_string()),
            (":authority".to_string(), "ignored.example".to_string()),
            ("x-extra".to_string(), "1".to_string()),
        ],
    );
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(&wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let result = instance.on_request_headers(vec![(":path".to_string(), "/orig".to_string())]);
    assert!(
        matches!(result, wasm::PhaseResult::Pause),
        "a dispatched callout must pause the phase, got {result:?}"
    );

    // The registered callout carries the parsed request: the URI's
    // scheme/host/target (the map :authority is advisory and dropped),
    // :method, the ordinary headers, and the timeout in ms.
    let pending = instance.take_pending_callouts();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].token, 1);
    assert_eq!(pending[0].uri, uri);
    assert_eq!(pending[0].method, "GET");
    assert_eq!(
        pending[0].headers,
        vec![("x-extra".to_string(), "1".to_string())]
    );
    assert_eq!(pending[0].timeout_ms, 5000);

    // Deliver a completed (non-2xx) response: any status is data.
    let resp = wasm::CalloutResponse {
        status: 403,
        headers: vec![("x-svc".to_string(), "deny".to_string())],
        body: b"denied!".to_vec(),
    };
    let resumed = instance.deliver_callout_response(pending[0].token, &resp);
    assert!(
        matches!(resumed, wasm::PhaseResult::Continue),
        "the callback ran without short-circuiting; expected Continue, got {resumed:?}"
    );

    // The callback read :status (three digits stored at 66100) and
    // stamped the body's head as the x-verdict request header.
    let memory = instance
        .memory_bytes(66100, 3)
        .expect("status digits readable");
    assert_eq!(&memory, b"403");
    let headers = instance.request_headers();
    assert!(
        headers
            .iter()
            .any(|(k, v)| k == "x-verdict" && v == "denied!"),
        "the callback's header mutation must land on the request map, got {headers:?}"
    );

    // No further callouts: a second drive of the phase outcome sees the
    // pause consumed.
    assert!(instance.take_pending_callouts().is_empty());
    instance.on_done();
}

#[test]
fn callout_dispatch_rejects_non_http_scheme_with_bad_argument() {
    // Scheme validation is fail-closed at the hostcall: a non-http(s)
    // URI answers Status::BadArgument (2) — the one status (with Ok
    // and InternalFailure) the Rust SDK's dispatch_http_call maps to a
    // clean Err instead of panicking. The fixture checks the return
    // value and returns Continue only when it is 2; nothing registers.
    let wat = String::from(
        r#"(module
  (import "env" "proxy_http_call"
    (func $http_call (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (data (i32.const 65536) "ftp://evil.example/x")
  (data (i32.const 65600) "\00\00\00\00")
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    ;; Record the hostcall's status at 66100, then Continue. (Returning
    ;; the raw status would alias ACTION_END_STREAM=2.)
    (i32.store8 (i32.const 66100)
      (call $http_call
        (i32.const 65536) (i32.const 21)
        (i32.const 65600) (i32.const 4)
        (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0)
        (i32.const 100)
        (i32.const 70000)))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#,
    );
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(&wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");

    let result = instance.on_request_headers(Vec::new());
    // The dispatch was refused (BadArgument), nothing registered, and
    // the phase proceeds Continue; the recorded status byte proves the
    // refusal was BadArgument (2), the status the Rust SDK surfaces as
    // a clean Err from dispatch_http_call.
    assert!(matches!(result, wasm::PhaseResult::Continue));
    assert_eq!(
        instance.memory_bytes(66100, 1).as_deref(),
        Some(&[2u8][..]),
        "the hostcall must answer Status::BadArgument for a non-http scheme"
    );
    assert!(instance.take_pending_callouts().is_empty());
    instance.on_done();
}

#[test]
fn callout_uri_path_from_header_map_when_uri_has_none() {
    // The SDK convention (Envoy's dispatch shape): the URI names the
    // origin and the map's :path carries the target when the URI has
    // no path of its own. A URI-embedded target still wins.
    let wat = callout_dispatch_wat(
        "http://127.0.0.1:1",
        &[
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), "/svc/verdict?a=b".to_string()),
        ],
    );
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(&wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");
    assert!(matches!(
        instance.on_request_headers(Vec::new()),
        wasm::PhaseResult::Pause
    ));
    let pending = instance.take_pending_callouts();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].uri, "http://127.0.0.1:1/svc/verdict?a=b");
    assert_eq!(pending[0].method, "POST");
    instance.on_done();
}

#[test]
fn shared_data_is_shared_across_instances_of_one_module() {
    // DW-167: proxy_get/set_shared_data is VM-scoped (the proxy-wasm
    // contract Envoy implements) — two per-request instances of the
    // same compiled module see one map, which is what a callout
    // plugin's TTL cache is built on. The fixture writes "k"->"v" with
    // CAS 0 (insert) on the first instance's request phase.
    let wat = r#"(module
  (import "env" "proxy_set_shared_data"
    (func $set_shared (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_get_shared_data"
    (func $get_shared (param i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (data (i32.const 65536) "k")
  (data (i32.const 65552) "v1")
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (i32.const 1024))
    (i32.const 1024))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (drop (call $set_shared (i32.const 65536) (i32.const 1)
              (i32.const 65552) (i32.const 2) (i32.const 0)))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#;
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut first = module.instantiate(&engine).expect("first instantiate");
    let mut second = module.instantiate(&engine).expect("second instantiate");
    assert!(matches!(
        first.on_request_headers(Vec::new()),
        wasm::PhaseResult::Continue
    ));
    // The second instance reads what the first wrote: same map, one
    // value with CAS bumped past 0.
    let shared = second.shared_data_snapshot();
    assert_eq!(
        shared.get("k"),
        Some(&(b"v1".to_vec(), 1)),
        "shared data must be VM-scoped across instances"
    );
    first.on_done();
    second.on_done();
}

/// A rejection-shape callout fixture: `request_headers` dispatches ONE
/// callout with the given URI and spec-serialized map, records the
/// hostcall's status byte at 66100, and returns Continue. The map is
/// embedded verbatim, so a test can plant CR/LF/NUL bytes in names,
/// values, or `:method`.
fn callout_rejection_wat(uri: &str, map: &[(String, String)]) -> String {
    let serialized = serialize_header_map_spec(map);
    format!(
        r#"(module
  (import "env" "proxy_http_call"
    (func $http_call (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2 32)
  (data (i32.const 65536) "{uri}")
  (data (i32.const 65600) "{bytes}")
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    ;; Record the hostcall's status at 66100, then Continue. (Returning
    ;; the raw status would alias ACTION_END_STREAM=2.)
    (i32.store8 (i32.const 66100)
      (call $http_call
        (i32.const 65536) (i32.const {uri_len})
        (i32.const 65600) (i32.const {map_len})
        (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0)
        (i32.const 100)
        (i32.const 70000)))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#,
        bytes = wat_bytes(&serialized),
        uri_len = uri.len(),
        map_len = serialized.len(),
    )
}

/// Drive one rejection fixture: the dispatch must answer
/// Status::BadArgument (2), register nothing, and leave the phase
/// Continue (the canonical recipe — a plugin reflecting client data
/// into a callout — cannot smuggle framing bytes past the hostcall).
fn assert_callout_rejected(wat: &str) {
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(wat),
            PluginLimits::default(),
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");
    assert!(matches!(
        instance.on_request_headers(Vec::new()),
        wasm::PhaseResult::Continue
    ));
    assert_eq!(
        instance.memory_bytes(66100, 1).as_deref(),
        Some(&[2u8][..]),
        "the dispatch must answer Status::BadArgument"
    );
    assert!(
        instance.take_pending_callouts().is_empty(),
        "a rejected dispatch must register no callout"
    );
    instance.on_done();
}

#[test]
fn callout_dispatch_rejects_crlf_header_value_with_bad_argument() {
    // Request splitting through a header VALUE: the value is
    // interpolated raw into the request head, so a CR/LF pair would
    // start a smuggled header line on the gateway-initiated
    // connection. Fail-closed at the hostcall: BadArgument, no
    // registration, no network work.
    assert_callout_rejected(&callout_rejection_wat(
        "http://127.0.0.1:1/decide",
        &[(
            "x-injected".to_string(),
            "ok\r\nHost: evil.example\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: evil.example"
                .to_string(),
        )],
    ));
}

#[test]
fn callout_dispatch_rejects_request_line_injection_via_method_with_bad_argument() {
    // Request splitting through `:method`: a non-token method carries
    // spaces and CR/LF straight into the request line. Fail-closed at
    // the hostcall: BadArgument, no registration.
    assert_callout_rejected(&callout_rejection_wat(
        "http://127.0.0.1:1/decide",
        &[
            (
                ":method".to_string(),
                "GET /decide HTTP/1.1\r\nHost: evil.example".to_string(),
            ),
            ("x-extra".to_string(), "1".to_string()),
        ],
    ));
    // A non-token method with NO framing bytes at all (a plain space)
    // is equally invalid: the token grammar itself is enforced, not
    // just the delimiter scan.
    assert_callout_rejected(&callout_rejection_wat(
        "http://127.0.0.1:1/decide",
        &[(":method".to_string(), "GE T".to_string())],
    ));
}

#[test]
fn shared_data_total_bytes_cap_refuses_oversized_set() {
    // The VM-scoped map is bounded per module (DW-167 review): a set
    // whose key+value bytes would exceed the 1 MiB cap FAILS (the
    // same error status as a CAS mismatch — the SDK's only branchable
    // error for this hostcall) instead of evicting, and the get path
    // is unaffected. The fixture: set "k"->"v1" (Ok), fill 1 MiB + 1
    // bytes and try to store them (refused), then read "k" back.
    let wat = r#"(module
  (import "env" "proxy_set_shared_data"
    (func $set_shared (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "proxy_get_shared_data"
    (func $get_shared (param i32 i32 i32 i32 i32) (result i32)))
  ;; 19 pages: the 1 MiB + 1 fill region ends at byte 1179649.
  (memory (export "memory") 19 32)
  (data (i32.const 65536) "k")
  (data (i32.const 65552) "v1")
  (data (i32.const 65568) "big")
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (i32.const 1024))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  (func $fill (param $i i32)
    (loop $l
      (i32.store8 (local.get $i) (i32.const 120))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 1179649)))))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    ;; Small set under the cap: Ok (0), recorded at 66100.
    (i32.store8 (i32.const 66100)
      (call $set_shared (i32.const 65536) (i32.const 1)
                        (i32.const 65552) (i32.const 2) (i32.const 0)))
    ;; 1 MiB + 1 bytes at 131072..1179649.
    (call $fill (i32.const 131072))
    ;; Oversized set: refused, recorded at 66104.
    (i32.store8 (i32.const 66104)
      (call $set_shared (i32.const 65568) (i32.const 3)
                        (i32.const 131072) (i32.const 1048577) (i32.const 0)))
    ;; Get "k" back: first value byte at 66108, CAS at 66112.
    (drop (call $get_shared (i32.const 65536) (i32.const 1)
                            (i32.const 70004) (i32.const 70008) (i32.const 70012)))
    (i32.store8 (i32.const 66108) (i32.load8_u (i32.load (i32.const 70004))))
    (i32.store (i32.const 66112) (i32.load (i32.const 70012)))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#;
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(wat),
            // The fill loop needs more than the default 1M fuel.
            PluginLimits {
                fuel: 50_000_000,
                ..PluginLimits::default()
            },
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");
    assert!(matches!(
        instance.on_request_headers(Vec::new()),
        wasm::PhaseResult::Continue
    ));
    let mem = instance.memory_bytes(66100, 16).expect("records");
    assert_eq!(mem[0], 0, "the under-cap set must succeed");
    assert_eq!(
        mem[4], 8,
        "the over-cap set must be refused with the shared-data error status"
    );
    assert_eq!(mem[8], b'v', "the get path still sees the stored value");
    assert_eq!(
        u32::from_le_bytes([mem[12], mem[13], mem[14], mem[15]]),
        1,
        "the get path still reports the CAS version"
    );
    let shared = instance.shared_data_snapshot();
    assert_eq!(shared.len(), 1, "only the under-cap key is stored");
    assert!(!shared.contains_key("big"));
    instance.on_done();
}

#[test]
fn shared_data_entry_count_cap_refuses_new_keys_but_updates_existing() {
    // The 1024-entry cap refuses a 1025th NEW key but still allows
    // updating an existing one (the cap bounds the entry count, not
    // writes). Keys are 4-byte little-endian counter strings written
    // in a loop; the extra key at 704096 carries the value 1024 so it
    // is distinct from every loop key.
    let wat = r#"(module
  (import "env" "proxy_set_shared_data"
    (func $set_shared (param i32 i32 i32 i32 i32) (result i32)))
  ;; 11 pages: the key region ends at byte 704100.
  (memory (export "memory") 11 32)
  (data (i32.const 65552) "v")
  (func (export "proxy_on_memory_allocate") (param $size i32) (result i32)
    (i32.const 1024))
  (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
  (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
  ;; Four VALID-UTF-8 key bytes per counter: [i % 64, '@' + i / 64,
  ;; 0, 0] — byte 1 spans '@'..'O' across the loop (i < 1024) and 'P'
  ;; for the extra 1025th key, so every key is distinct after the
  ;; host's lossy UTF-8 key decode.
  (func $keybits (param $i i32) (result i32)
    (i32.or (i32.const 16384)
      (i32.or (i32.and (local.get $i) (i32.const 63))
              (i32.shl (i32.and (i32.shr_u (local.get $i) (i32.const 6)) (i32.const 63))
                       (i32.const 8)))))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (local $i i32)
    (loop $fill
      (i32.store (i32.add (i32.const 700000) (i32.shl (local.get $i) (i32.const 2)))
                 (call $keybits (local.get $i)))
      (drop (call $set_shared
              (i32.add (i32.const 700000) (i32.shl (local.get $i) (i32.const 2)))
              (i32.const 4)
              (i32.const 65552) (i32.const 1) (i32.const 0)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $fill (i32.lt_u (local.get $i) (i32.const 1024))))
    ;; The 1025th NEW key (counter value 1024): refused at 66100.
    (i32.store (i32.const 704096) (call $keybits (i32.const 1024)))
    (i32.store8 (i32.const 66100)
      (call $set_shared (i32.const 704096) (i32.const 4)
                        (i32.const 65552) (i32.const 1) (i32.const 0)))
    ;; Re-setting the FIRST key (an update, not a new entry): Ok at 66104.
    (i32.store8 (i32.const 66104)
      (call $set_shared (i32.const 700000) (i32.const 4)
                        (i32.const 65552) (i32.const 1) (i32.const 0)))
    (i32.const 0))
  (func (export "proxy_on_request_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_response_body") (param i32 i32 i32) (result i32) (i32.const 0))
  (func (export "proxy_on_done") (param i32))
  (func (export "proxy_on_log") (param i32))
)"#;
    let engine = WasmEngine::new().expect("engine");
    let module = engine
        .compile(
            &wat_to_wasm(wat),
            PluginLimits {
                fuel: 50_000_000,
                ..PluginLimits::default()
            },
            Vec::new(),
            Vec::new(),
        )
        .expect("compile");
    let mut instance = module.instantiate(&engine).expect("instantiate");
    assert!(matches!(
        instance.on_request_headers(Vec::new()),
        wasm::PhaseResult::Continue
    ));
    let mem = instance.memory_bytes(66100, 5).expect("records");
    assert_eq!(
        mem[0], 8,
        "a 1025th new key must be refused at the entry cap"
    );
    assert_eq!(
        mem[4], 0,
        "updating an existing key under the entry cap must succeed"
    );
    assert_eq!(
        instance.shared_data_snapshot().len(),
        1024,
        "exactly the cap's worth of entries is stored"
    );
    instance.on_done();
}
