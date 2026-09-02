# gRPC-Web transcoding (DW-101)

> Implements issue DW-101 (M2, `edition/oss`, effort M) over the
> protocol-translation surface. Sources:
> `crates/dwara-core/src/dataplane/grpc_web.rs` (the gRPC-Web framing
> translator, the JSON-to-gRPC transcoder driven by prost descriptors,
> the gRPC status mapper -- its module docs carry the full contract),
> the config schema in `config/mod.rs` (`GrpcWeb`, `GrpcWebTranscoding`,
> `GrpcWebDescriptor`), validation in `snapshot/mod.rs`. Tests:
> `crates/dwara-core/tests/grpc_web.rs` (gRPC-Web <-> gRPC framing for
> unary and streaming, JSON <-> protobuf transcoding against a
> runtime-built FileDescriptorSet, gRPC status -> HTTP status mapping,
> and config-schema parsing/validation). Operator docs:
> [docs-site gRPC & WebSockets guide](../../docs-site/guide/grpc-websockets.md).

gRPC-Web is the browser-friendly variant of gRPC: it replaces HTTP/2
trailers with a trailing frame that carries the gRPC status as
pseudo-headers, and it frames every chunk with a 5-byte prefix (1 byte
flag + 4 bytes big-endian length). The gateway sits between a browser
(gRPC-Web) and a native gRPC upstream (HTTP/2 + trailers), translating
framing in both directions. With transcoding enabled, it also accepts
plain JSON and translates it to protobuf wire bytes, so a REST or JSON
client can call a gRPC backend without a gRPC library. The entire
module is feature-gated behind the `grpc_web` cargo feature; the config
schema is always present so configs round-trip without the feature.

## gRPC-Web framing

The flag byte distinguishes data frames (`0x00`) from trailer frames
(`0x80`). A unary response is one data frame followed by one trailer
frame; a streaming response is an arbitrary number of data frames
(each its own 5-byte-prefixed chunk) followed by a single trailer
frame.

On the forward path, `translate_grpc_web_to_grpc` strips the gRPC-Web
fring and reconstructs the native gRPC request body: it walks each
5-byte-prefixed frame, concatenates data-frame payloads, and rejects
trailer frames on the request path (browsers cannot send gRPC
trailers), truncated headers, overlong lengths, and unknown flag bytes
-- all as `MalformedFrame` errors.

On the response path, `translate_grpc_to_grpc_web` wraps the native
gRPC body plus a trailer payload into one data frame followed by one
trailer frame. For streaming responses, `translate_grpc_to_grpc_web_data_chunk`
wraps each upstream data chunk as its own gRPC-Web data frame, and
`translate_grpc_trailers_to_grpc_web` emits the final trailer frame at
stream end. `parse_trailers` and `build_trailers` round-trip the
`key: value\n` trailer text format.

## JSON-to-gRPC transcoding

When transcoding is enabled, the gateway accepts plain JSON requests
(`Content-Type: application/json`) and translates them to protobuf wire
bytes for the upstream, and translates the protobuf response back to
JSON. The mapping is driven by `.proto` descriptors supplied via config
(`FileDescriptorSet` files, as produced by `protoc
--descriptor_set_out=...`).

At config publish, `GrpcTranscoder::from_descriptors` loads the
descriptors, decodes each `FileDescriptorSet` via `prost::Message`,
resolves the named service's methods, and builds a method map keyed by
the fully-qualified gRPC method path
(`/{package}.{service}/{method}`). Each entry records the request and
response message type names.

Because the descriptors are supplied at runtime (not compiled in), the
transcoder works with the dynamic protobuf descriptor model: it reads
the `FileDescriptorSet`, resolves message types by name
(`resolve_message`, including nested types), and encodes/decodes fields
by walking the descriptor's field list. This avoids any build-time code
generation. The module defines the minimal subset of
`google.protobuf` descriptor types (`FileDescriptorProto`,
`DescriptorProto`, `FieldDescriptorProto`, etc.) via `prost::Message`
rather than pulling in the version-mismatched `prost-types` crate --
the same locked-dependency stance as the rest of the codebase.

`json_to_grpc` encodes a JSON object into protobuf wire bytes using the
request message descriptor; `grpc_to_json` decodes protobuf wire bytes
into JSON using the response message descriptor. Both handle scalar
types (string, bytes, bool, int32/64, uint32/64, float, double, enum),
nested messages (recursively resolved), and repeated fields. Bytes are
base64-encoded in JSON (the canonical proto3 JSON mapping).

## gRPC status mapping

`grpc_status_to_http` maps a gRPC status code (the `google.rpc.Code`
enum) to an HTTP status code and a `google.rpc.Status` JSON body
(`{ "code", "message", "details": [] }`) for non-gRPC clients. The
mapping follows the gRPC HTTP/JSON specification: OK -> 200,
NOT_FOUND -> 404, PERMISSION_DENIED -> 403, RESOURCE_EXHAUSTED -> 429,
DEADLINE_EXCEEDED -> 504, INTERNAL -> 500, UNAVAILABLE -> 503, and so
on. Unknown codes map to 500. `grpc_status_name` returns the canonical
name for logging and trailer display.

## Configuration and validation

```yaml
routes:
  - name: grpc-api
    service: backend
    match:
      path: { type: prefix, value: /api }
    action: { type: proxy }
    grpc_web:
      enabled: true
      transcoding:
        enabled: true
        descriptors:
          - file: /etc/dwara/echo.desc
            package: my.api
            service: EchoService
```

`GrpcWeb` is the route-scoped block: `enabled` is the master switch
(default false, allowing staged rollout), and `transcoding` is the
optional JSON-to-gRPC configuration. `GrpcWebTranscoding` carries its
own `enabled` flag (so the descriptor list can be staged before
activation) and a `descriptors` list of `GrpcWebDescriptor` entries
(each naming a file, package, and service).

Validation (`snapshot/mod.rs`) rejects, when transcoding is enabled, an
empty descriptor list and unreadable descriptor files (the
`check_file_readable` helper). The config schema is always present
regardless of the `grpc_web` cargo feature, so configs round-trip
across builds with and without the feature; when the feature is off the
block is accepted but inert (validation warns, the runtime translation
does not run).

The [gRPC and WebSocket polish](./grpc-websocket.md) page covers the
native gRPC-over-H2 path this feature bridges to; the
[dataplane and proxy](./dataplane-proxy.md) page covers the request
path.
