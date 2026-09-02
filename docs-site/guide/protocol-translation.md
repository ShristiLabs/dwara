# Protocol translation

Dwara can translate between API protocols at the route boundary, so a client
speaking one protocol can reach an upstream speaking another without either
side changing. The gateway owns the impedance mismatch: it parses the
inbound request in the client's protocol, produces the equivalent request in
the upstream's protocol, and translates the response back.

## When to use this

Use protocol translation when you are modernizing an estate incrementally --
a REST client that must reach a new gRPC backend, a GraphQL frontend that
needs data from a legacy SOAP service, a mobile client speaking REST while
the upstream team has moved to gRPC. The gateway does the translation at the
edge so neither the client nor the upstream carries the translation logic. A
route without a `translation` block forwards traffic in its native protocol
unchanged.

## Configuration

Add a `translation` block to the route. The `from` and `to` fields name the
client-facing and upstream-facing protocols; the gateway validates that the
pair is a supported translation.

```yaml
routes:
  - name: legacy-to-grpc
    service: grpc-svc
    match:
      path: { type: prefix, value: /v1/users }
    translation:
      from: rest
      to: grpc
      mapping: /etc/dwara/protos/user-api.yaml
      grpc_service: pkg.UserService
    action:
      type: proxy
      upstream:
        protocol: http2
        trusted_ca_file: /etc/dwara/upstream-ca.pem
```

## Supported translations

| From | To | Notes |
| --- | --- | --- |
| `rest` | `grpc` | REST path/query/body mapped to a gRPC request via the mapping file; response protobuf trans-coded to JSON. |
| `rest` | `graphql` | REST parameters become GraphQL variables; the gateway issues a fixed query from the mapping file and returns the selection as JSON. |
| `soap` | `rest` | SOAP/XML envelope parsed into JSON fields; REST response re-wrapped into a SOAP envelope for the client. |

The `mapping` file is the contract between the two protocols. For REST-to-gRPC
it follows the gRPC HTTP/JSON transcoding convention driven by
`google.api.http` annotations, so the same `.proto` annotations that power
[gRPC-Web transcoding](./grpc-web) apply here. For REST-to-GraphQL it pairs a
REST path with a named GraphQL operation and a variable binding. For
SOAP-to-REST it maps WSDL operations to REST verbs and XML element paths to
JSON fields.

## Error handling

Translation failures are deliberate and closed:

- a request body the gateway cannot parse in the `from` protocol returns
  `400` to the client and never reaches the upstream
- a mapping that does not resolve (unknown field, missing binding) returns
  `400` with a pointer to the offending field
- an upstream response the gateway cannot translate back returns `502` --
  the client sees a gateway error, not a malformed payload in its own
  protocol

Retries replay the translated upstream request, and authentication that signs
the body (see [HMAC signing](./hmac-signing)) verifies against the client's
original bytes before translation runs.

## Streaming

Translation is request/response only. A streaming RPC (gRPC server-streaming,
GraphQL subscriptions, SOAP with attachments) is not translated -- the
gateway rejects it with `400` rather than silently dropping frames. For
streaming cross-protocol needs, terminate the stream in its native protocol
and translate at a separate route.

## Observability

Translation decisions surface in [`/metrics`](./observability) as
`dwara_translation_total{route,from,to,outcome}` with outcomes `translated`,
`request_rejected`, and `response_untranslatable`. The access log records
both the client-facing path and the upstream-facing call, so analytics can
attribute a single client request to its translated upstream RPC.
