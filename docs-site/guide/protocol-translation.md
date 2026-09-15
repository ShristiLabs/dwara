# Protocol translation

Dwara can translate between API protocols at the route boundary, so a client
speaking one protocol can reach an upstream speaking another without either
side changing. The gateway owns the impedance mismatch: it parses the
inbound request in the client's protocol, produces the equivalent request in
the upstream's protocol, and translates the response back.

::: info Status
The `translation:` route block parses and validates in every build
(there are no `protocol_translation`/`soap` cargo features), but the
runtime translators are not yet dispatched from the proxy path — a
route carrying a `translation` block forwards traffic untranslated
today. The GraphQL and SOAP translators are implemented and
test-covered as library components; wiring them into the request path
is landing iteratively. See
[Editions: scaffolded surfaces](./editions#scaffolded-surfaces).
:::

## When to use this

Use protocol translation when you are modernizing an estate incrementally --
a REST client that must reach a new gRPC backend, a GraphQL frontend that
needs data from a legacy SOAP service, a mobile client speaking REST while
the upstream team has moved to gRPC. The gateway does the translation at the
edge so neither the client nor the upstream carries the translation logic. A
route without a `translation` block forwards traffic in its native protocol
unchanged.

## Configuration

Add a `translation` block to the route. The `kind` selects the direction;
the `graphql`/`soap` sub-blocks carry the direction-specific config:

```yaml
routes:
  - name: users-via-graphql
    service: graphql-svc
    match:
      path: { type: prefix, value: /v1/users }
    translation:
      kind: rest_to_graphql
      graphql:
        query_template: "query($id: ID!) { user(id: $id) { name email } }"
        upstream_path: /graphql
    action:
      type: proxy
```

The upstream protocol is set on the upstream itself (e.g.
`protocol: https` with `trusted_ca_file`), not on the route action.

## Supported translations

| `kind` | Direction | Notes |
| --- | --- | --- |
| `rest_to_graphql` | REST/JSON client -> GraphQL upstream | The gateway builds a GraphQL query from `query_template` and the REST JSON body (`$variable` references resolve from the body's top-level fields and are also sent as the `variables` map). |
| `graphql_to_rest` | GraphQL client -> REST upstream | The gateway unwraps the GraphQL `data` envelope into a REST JSON body on the response path. |
| `rest_to_soap` | REST/JSON client -> SOAP/XML upstream | The gateway wraps the JSON body in a SOAP envelope with the configured `operation` name and `namespace`. |
| `soap_to_rest` | SOAP/XML client -> REST/JSON upstream | The gateway parses the SOAP envelope and converts the Body's payload element to JSON. |

REST-to-gRPC is not a `translation` kind — JSON-to-gRPC transcoding is
part of [gRPC-Web](./grpc-web) (`grpc_web.transcoding`, driven by
`google.api.http` annotations in `.proto` descriptors).

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

## Runnable demo

Run this feature against a live gateway: [`demos/12-protocol-translation/`](https://github.com/shristilabs/dwara/tree/main/demos/12-protocol-translation) (test
scripts: `test-02-json-transcoding.sh`, `test-03-protocol-translation.sh`) in the repository.
The category README covers prerequisites and teardown.
