# Nano-service ABI

Signature-level reference for the nano-service handler ABI: the
module exports, the host imports, the request wire format, and the
sandbox rules. Every entry below was extracted from
`crates/dwara-core/src/dataplane/nano_service.rs`.

A nano-service module implements this small dedicated handler ABI --
**not** proxy-wasm. For workflow-oriented prose (a complete worked
module, config wiring, testing) see
[Building a nano-service](./building-nano-service); for the
configuration and operations view see [Nano-services](./nano-services).

## Module exports

| Export | Signature | Semantics |
|---|---|---|
| `memory` | linear memory | The linear memory the host and module share. The host writes the serialized request into it and reads response bytes back out of it. |
| `alloc` | `alloc(size: i32) -> i32` | Allocate `size` bytes in linear memory and return a pointer. A simple bump allocator is fine; the host calls it once per request to place the serialized request. |
| `handle` | `handle(req_ptr: i32, req_len: i32) -> i32` | Handle the request serialized at `[req_ptr, req_ptr+req_len)`. Returns `0` on success (the response is what the module built through the host imports); any non-zero value answers `502`. |

Allocation details the host actually implements:

- If the module exports `alloc` with signature `(i32) -> i32`, the
  host calls it with the serialized request's length and uses the
  returned pointer when it is positive.
- If the export is absent, not of that shape, or returns a
  non-positive pointer, the host falls back to growing the module's
  memory by whole 64 KiB pages and using the tail -- but a module
  should always export `alloc`; the fallback path exists so trivial
  hand-written modules still instantiate.
- A trap inside `alloc` (including one caused by the memory cap)
  fails the request (502), like any other execution failure.

## Host imports

The host provides exactly four imports, under the module name
`dwara`. A module importing WASI functions does not instantiate --
the host provides nothing else.

| Import | Signature | Semantics |
|---|---|---|
| `dwara.response_status` | `response_status(status: i32)` | Set the HTTP response status. Only values in `1..=599` are honored; anything else is ignored and the previous status (default `200`) stands. |
| `dwara.response_header` | `response_header(k_ptr: i32, k_len: i32, v_ptr: i32, v_len: i32) -> i32` | Append one response header read from linear memory. Returns `0` on success, `1` on a negative length or an out-of-bounds key/value range. Headers accumulate; later calls append, they do not replace. Bytes are read lossily as UTF-8. |
| `dwara.response_body` | `response_body(ptr: i32, len: i32) -> i32` | Set the response body read from linear memory (replacing any previously set body). Returns `0` on success, `1` on a negative argument or an out-of-bounds range. |
| `dwara.log` | `log(ptr, len: i32) -> i32` | Emit a debug log line, surfaced through the gateway's tracing at `debug` level with the module path attached. Returns `0` on success, `1` on a bad range. Log lines from a successful request are flushed after `handle` returns. |

If the module never calls `response_status`, the response answers
`200`; a module that only writes a body still answers 200.

## Request wire format

The request is serialized into linear memory as a length-prefixed
binary blob. **Every length is a `u32` in big-endian byte order.**

```text
u32 method_len, method bytes (UTF-8)
u32 path_len,   path bytes   (UTF-8)
u32 headers_count
  repeated headers_count times:
    u32 key_len,   key bytes   (UTF-8)
    u32 value_len, value bytes (UTF-8)
u32 body_len,   body bytes (raw, may be arbitrary binary)
```

Rules the host's serializer follows (mirror them when parsing):

- Strings are UTF-8 bytes; the body is passed through verbatim.
- The whole blob is written in one `alloc` + copy: `req_len` in the
  `handle` call is the total serialized length, and `req_ptr` points
  at the first byte of `method_len`.
- A parser that runs off the end of the buffer (a length prefix
  pointing past `req_ptr + req_len`) must treat the request as
  corrupt: return non-zero from `handle`, which answers 502. A
  module only needs to parse as far as the fields it uses -- the
  remainder can be ignored.

The dwara-core source also carries a `deserialize_request` helper
(and round-trip tests) implementing exactly this layout; it is the
normative example of a correct parser.

## Sandbox and resource limits

A nano-service module has no host capabilities beyond the four
imports above: no network, no filesystem, no environment, no access
to the gateway's config, secrets, or other routes. The sandbox is
the security boundary. The runtime enforces:

| Resource | Enforcement |
|---|---|
| Linear memory | Capped at the route's `memory_limit` (default 1 MiB, max 64 MiB) through the wasmtime resource limiter; an allocation past the cap fails (502). |
| CPU | A fixed fuel budget of 1,000,000 units per `handle` call; exhaustion traps (502). |
| Wall clock | `execution_timeout_ms` (default 100, max 5000): `handle` runs on a blocking-pool thread wrapped in a timeout, so a busy-looping module is interrupted (504) rather than left hanging a worker. |
| Request body | The module receives the body whole; a body over 1 MiB answers 413 before the module is invoked. |

## Failure semantics

Every failure mode fails closed, on the nano-service route only:

| Condition | Client sees |
|---|---|
| Module missing or broken at handler construction | 502 `nano_service_unavailable` |
| `handle` returns non-zero, traps, or exhausts its fuel budget | 502 `nano_service_error` |
| `handle` exceeds `execution_timeout_ms` | 504 `nano_service_timeout` |
| Request body over 1 MiB | 413 `nano_service_body_too_large` |

## Where to go next

- [Nano-services](./nano-services) - the option landing page:
  configuration, when to use, observability.
- [Building a nano-service](./building-nano-service) - the building
  guide: a complete worked `no_std` module from scratch.
- [Extension API](../reference/extension-api) - the index of every
  extension surface's reference page.
