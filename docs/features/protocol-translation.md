# Protocol translation framework (DW-100)

> Implements issue DW-100 (M2, `edition/oss`, effort L). Sources:
> `crates/dwara-core/src/dataplane/translation.rs` (the shared,
> protocol-agnostic seam: the `ProtocolTranslator` trait, the
> `TranslatedRequest` / `TranslatedResponse` / `TranslationBody` types,
> the `TranslationError` enum, and the `TranslationRegistry` keyed by
> content-type pair), `crates/dwara-core/src/dataplane/translation_graphql.rs`
> (the REST-to-GraphQL / GraphQL-to-REST translator: the query-template
> variable resolver, the `data`-envelope unwrap, the `errors`-to-502
> mapping), `crates/dwara-core/src/dataplane/translation_soap.rs` (the
> SOAP-to-REST / REST-to-SOAP translator: the hand-rolled bounded XML
> parser, the XML-to-JSON convention, the envelope builder), the config
> schema in `crates/dwara-core/src/config/mod.rs` (`Translation`,
> `TranslationKind`, `GraphqlTranslation`, `SoapTranslation`), and
> validation in `src/snapshot/mod.rs`. Tests: the GraphQL-awareness
> suite `crates/dwara-core/tests/graphql.rs` (DW-099, the checker the
> translator sits beside) and the snapshot-pipeline validation matrix
> in `crates/dwara-core/tests/snapshot_pipeline.rs` (the inert-feature
> warnings and the `translation` block acceptance). Operator docs:
> [docs-site routing guide](../../docs-site/guide/routing.md).

The gateway can sit between clients and upstreams that speak different
protocols and translate the request and response bodies on the fly. A
route carrying a `translation` block opts its requests into a
buffer-and-convert path: the inbound body is converted to the upstream's
wire format, sent upstream, and the response body is converted back to
the client's wire format before it leaves. A route without the block
streams untouched -- translation is an explicitly buffering step (the
same posture as the DW-028 body transform and the DW-061 aggregation
plugin), never a tax on the zero-buffering proxy path.

## The shared seam

Every translator does the same two things on a route: convert the
inbound request body to the upstream's wire format, and convert the
upstream's response body back to the client's wire format. DW-100
factors that into one trait so the dataplane dispatches by content-type
pair through a single registry, and a new translator (a future Thrift
or AMQP bridge) plugs in without touching the request path.

`ProtocolTranslator` is synchronous and operates on fully-buffered
bodies (`TranslationBody`, a `Bytes` wrapper that implements
`hyper::body::Body` so a translated body hands off to the rest of the
dataplane). `translate_request` returns the converted method, path,
headers, and body to send upstream; `translate_response` returns the
converted status, headers, and body to send the client.
`content_type_in` is the media type the client sends and expects back;
`content_type_out` is the media type the upstream expects and sends
back. The `TranslationRegistry` maps `(content_type_in,
content_type_out)` pairs to translators (case-insensitive on both media
types), built at config publish and held behind an `Arc` by the request
path. A route's `translation.kind` resolves to one entry.

`TranslationError` carries three closed cases: `InvalidBody` (malformed
JSON/XML, an envelope without a Body), `SchemaNotFound` (a GraphQL
translation without a query template, a gRPC method not in the loaded
descriptors), and `TranslationFailed` (a template variable the request
body did not supply, an XML element the converter could not map). Each
fails closed -- the request never reaches the upstream with a dangling
variable or a half-converted body.

## REST-to-gRPC transcoding

The gRPC-Web transcoding engine in `dataplane/grpc_web` (DW-101)
already translates JSON to protobuf; the `protocol_translation` feature
(which implies `grpc_web`) reuses it through the shared trait.

## REST-to-GraphQL translation

`kind: rest_to_graphql` fronts a GraphQL upstream with a REST client.
The translator builds a GraphQL request from a config-supplied query
template: each `$variable` is resolved from the JSON body's top-level
field of the same name, the resolved values are placed in the
`variables` map, and the substituted query plus the variables map
become the GraphQL-over-HTTP POST body (`application/graphql+json`).
The request path is rewritten to the configured `upstream_path`
(default `/graphql`), the method forced to `POST`. A `$name` the body
does not supply fails closed -- the request never reaches the upstream
with a dangling variable.

The response path unwraps the GraphQL `data` envelope into the REST
JSON body the client expects. A GraphQL `errors` array (non-null) maps
to a 502 with the errors serialized as the body -- the upstream
reported the failure, the gateway surfaces it. The reverse direction
(`kind: graphql_to_rest`) wraps a REST upstream's JSON response in the
`{ "data": ... }` envelope a GraphQL client expects; the request path
passes the client's GraphQL body through unchanged (the response path
does the work).

The template syntax is plain GraphQL text with `$variable` references
scanned by a hand-rolled recognizer (`[A-Za-z_][A-Za-z0-9_]*` after the
`$`, first-reference order, deduplicated). Substitution renders JSON
values as GraphQL literals: strings quoted with minimal escaping,
numbers and booleans bare, null bare, objects and arrays inlined. The
substituted query is sent verbatim alongside the `variables` map.

## SOAP-to-REST translation

`kind: soap_to_rest` bridges a SOAP/XML client to a REST/JSON upstream.
The translator parses the SOAP envelope, extracts the `Body`'s first
child element whose local name matches the configured `operation`
(namespace prefixes ignored), and converts its XML children to a JSON
body. The reverse direction (`kind: rest_to_soap`) wraps a REST JSON
body in a SOAP 1.1 envelope (`Envelope > Body > {operation}`) with the
configured operation name and namespace, converting the JSON to XML.

The XML parser is hand-rolled -- a full XML library would be a new
dependency (and a deny.toml review). SOAP envelopes are a narrow XML
subset: elements with optional attributes, text content, and nested
elements, no DTDs, no entity expansion, no processing instructions. The
parser handles that subset and rejects everything else (fail-closed
against anything it cannot prove well-formed), bounded by a
`PARSE_DEPTH_CAP` of 256 against element-nesting DoS. The XML-to-JSON
convention is deterministic: a text-only element becomes a JSON scalar
(number/bool recognized), an element with children becomes an object
(repeated tags become an array), and attributes become `@attr` keys.
Compiled under the separate `soap` cargo feature (which implies
`protocol_translation`) for binary size.

## Configuration

```yaml
routes:
  - name: users-gql
    service: user-svc
    match:
      path: { type: prefix, value: /users }
    translation:
      kind: rest_to_graphql
      graphql:
        query_template: |
          query GetUser($id: ID!) { user(id: $id) { id name } }
        upstream_path: /graphql
    action: { type: proxy }
```

The `translation` block is additive and default-off. `kind` selects the
translator and which sub-block (`graphql` or `soap`) carries the config.
The config schema is always present so configs round-trip without the
feature; when `protocol_translation` is off the block is accepted but
inert (validation warns, the runtime translation does not run). The
SOAP kinds additionally require the `soap` cargo feature. Validation
rejects a `rest_to_graphql` without a `query_template`, a `soap_to_rest`
without an `operation`, and a `rest_to_soap` without both.

The [dataplane and proxy](./dataplane-proxy.md) page covers the
streaming path this feature opts out of; the [gRPC and
WebSocket](./grpc-websocket.md) page covers the gRPC-Web transcoding
engine the REST-to-gRPC translator reuses.
