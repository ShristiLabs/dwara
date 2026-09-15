# gRPC-Web

Dwara can serve [gRPC-Web](https://github.com/grpc/grpc-web) (the gRPC
wire protocol adapted for browsers, which cannot speak HTTP/2 trailers
directly) to browser clients and bridge them to a gRPC upstream that speaks
native gRPC over HTTP/2. The gateway handles the framing translation in both
directions, so a browser `fetch` against the gateway looks like gRPC-Web
while the upstream sees a normal gRPC call.

::: info Status
The `grpc_web:` route block parses and validates in every build (there
is no `grpc_web` cargo feature), but the framing translation is not
yet dispatched from the proxy path — a route carrying the block
forwards traffic untranslated today. The framing and transcoding
translators are implemented and test-covered as library components.
See [Editions: scaffolded surfaces](./editions#scaffolded-surfaces).
:::

## When to use this

Use a `grpc_web` route when browser code needs to call a gRPC backend and you
do not want to run a separate gRPC-Web proxy (envoy, grpcwebproxy) alongside
the gateway. The gateway terminates the browser-facing framing and re-frames
for the upstream, applying the same routing, authn/authz, rate limits, and
analytics as any other route. A route without the block proxies native gRPC
unchanged -- it does not add gRPC-Web framing.

## Configuration

Add a `grpc_web` block to a route that fronts a gRPC upstream. `enabled`
turns framing translation on; the `transcoding` sub-block additionally
enables JSON-to-gRPC transcoding:

```yaml
routes:
  - name: browser-rpc
    service: grpc-svc
    match:
      path: { type: prefix, value: /pkg.Service/ }
    grpc_web:
      enabled: true
      transcoding:
        enabled: true
        descriptors:
          - file: /etc/dwara/protos/user-api.pb
            package: pkg
            service: UserService
    action:
      type: proxy
```

The upstream should declare `protocol: http2` (h2 with TLS; use
`trusted_ca_file` for a private CA) so the gateway dials it as native
gRPC. CORS for browser clients is the ordinary route-level
[CORS](./cors) block — there is no separate `cors` key inside
`grpc_web`.

## Framing and transcoding

`enabled: true` (the master switch; the block is inert when false)
translates gRPC-Web's base64-or-binary framed body into native gRPC
trailers-in-body and back. The gateway:

- accepts `Content-Type: application/grpc-web` and
  `application/grpc-web+proto` from the browser
- strips the gRPC-Web framing, reconstructs the gRPC message stream, and
  forwards it to the upstream as `application/grpc` over HTTP/2
- converts the upstream's gRPC trailers (`grpc-status`, `grpc-message`) into
  the gRPC-Web trailer frame the browser expects

`transcoding.enabled: true` additionally accepts a JSON request body
(`Content-Type: application/json`) and transcodes it to the protobuf message
the upstream expects, and transcodes the protobuf response back to JSON. This
lets a browser call the RPC with plain `fetch` and JSON, no protobuf
dependency on the client. The mapping follows the gRPC HTTP/JSON transcoding
convention driven by the `google.api.http` annotations in the `.proto`
descriptors listed under `transcoding.descriptors` (each entry: `file` — a
`FileDescriptorSet` as produced by `protoc --descriptor_set_out=...`,
`package`, and `service`).

## Streaming

gRPC-Web server-streaming RPCs are supported: the gateway relays the upstream
stream to the browser as a chunked gRPC-Web response, applying the same
backpressure as any streaming proxy. Client-streaming and bidi-streaming RPCs
are not representable in gRPC-Web and are rejected with `400` before the
upstream is contacted -- the browser cannot open them, so surfacing the error
at the edge avoids a half-open upstream call.

## Observability

gRPC-Web decisions surface in [`/metrics`](./observability) as
`dwara_grpc_web_total{route,mode,outcome}` with outcomes `framed`,
`transcoded`, and `rejected`. The underlying gRPC status from the upstream is
preserved in the gRPC-Web trailer frame, so a failed RPC surfaces as
`UNAVAILABLE` or `DEADLINE_EXCEEDED` in the browser, not a proxy error.

## Runnable demo

Run this feature against a live gateway: [`demos/12-protocol-translation/`](https://github.com/shristilabs/dwara/tree/main/demos/12-protocol-translation) (test
scripts: `test-01-grpc-web-framing.sh`, `test-02-json-transcoding.sh`) in the repository.
The category README covers prerequisites and teardown.
