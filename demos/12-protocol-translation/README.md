# Category 12: Protocol Translation

Demonstrates the protocol-translation family of dwara surfaces: a
native **gRPC** upstream (TLS + ALPN h2) fronted by the gateway for
**gRPC-Web** framing and **JSON transcoding**, route-level **protocol
translation**, **GraphQL awareness** (fully enforced), **API
aggregation**, **OpenAPI import** and response validation, and the
**API lifecycle** block.

This category is a maturity map as much as a demo: one of these
surfaces is enforced end to end at runtime (GraphQL), one is a host-side
CLI flow (OpenAPI import), and the rest are config-schema + library
components whose runtime dispatch has not landed yet. Every test states
which half it is exercising, and the live tests prove the transport
chain (TLS + h2 ingress, TLS + h2 SPKI-pinned upstream, gRPC trailers)
that the unwired translators will sit on.

## Architecture

```
                       ┌─────────────────────────────────────┐
 grpcurl (native gRPC) │  dwara gateway                      │
 ───── TLS + ALPN h2 ─►│  :8443 edge-https  ─┐               │
                       │                      │ TLS + ALPN h2 │ (SPKI pin)
 curl / python3        │  :8080 edge-http ───┤               │
 ───── plaintext ─────►│                      ▼               │
                       │            grpc :8443 (gRPC, TLS)   │
                       │            static :80 (JSON files)   │
                       │            echo :8080 (reflection)   │
                       └─────────────────────────────────────┘
```

- `dwara` — the gateway (`dwara:demo`): plaintext HTTP on :8080 and a
  TLS listener on :8443 whose ALPN offers `h2`, so native gRPC clients
  (grpcurl) can call through the gateway.
- `grpc` — `dwara-demo/grpc`, the `dwdemo.DemoService` upstream
  (`SayHello`, `ToUpper`, `Count`) with reflection and the standard
  gRPC health service. Serves plaintext :8080 and TLS :8443 (the
  quickstart cert pair); the gateway's `protocol: http2` upstream
  dials the TLS port — dwara has no plaintext-h2c upstream protocol.
- `static` — `dwara-demo/static` (nginx): `/api/users.json`,
  `/api/products.json`, `/healthz`.
- `echo` — `dwara-demo/echo`: reflects the request as JSON (stands in
  for the GraphQL server / translation target).

### The gRPC TLS trust chain

The quickstart server certificate's SAN is `localhost`/`127.0.0.1`,
which cannot match the in-network hostname `grpc` under CA +
hostname verification. The `grpc-tls` upstream therefore pins the
certificate's SPKI SHA-256 instead (`cert_pinning.pins[]`,
SEC-04/DW-109 — fail-closed, no CA fallback, no hostname check). The
pin in `dwara.yaml` matches the generated quickstart cert; if you
re-run `gen-certs.sh`, recompute it:

```sh
openssl x509 -in certs/server.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256
```

## Prerequisites

```sh
# Images (prebuilt by demos/_shared):
docker compose -f ../_shared/docker-compose.yml build
# TLS material (quickstart certs, symlinked at ../_shared/certs):
../_shared/gen-certs.sh          # only if certs/ is missing
# Operator CLI for test-06 / test-08 (optional; tests skip cleanly):
cargo build -p dwara-cli
```

Host `python3` (stdlib only) drives the gRPC-Web framing bytes;
`fullstorydev/grpcurl` (docker) drives native gRPC. The compiled
`FileDescriptorSet` for transcoding is committed at `protos/dwdemo.pb`
(regenerate with the grpc image: see the comment in `test-02`).

`dwara.yaml` uses RELATIVE file paths (`certs/`, `protos/`,
`openapi.yaml`) and the gateway runs with `working_dir: /etc/dwara`,
where compose mounts the same layout — so the identical config
validates on the host:

```sh
cd demos/12-protocol-translation && ../../target/debug/dwara-cli validate dwara.yaml
# ok: 8 routes
```

## Layout

```
12-protocol-translation/
  docker-compose.yml     gateway + grpc + static + echo
  dwara.yaml             2 listeners, 8 routes, 3 upstreams, lifecycle block
  openapi.yaml           demo OpenAPI 3.0 spec (import + validation target)
  protos/dwdemo.pb       compiled FileDescriptorSet (dwdemo.DemoService)
  certs -> ../_shared/certs  quickstart TLS material (host-side validation)
  test-01-grpc-web-framing.sh
  test-02-json-transcoding.sh
  test-03-protocol-translation.sh
  test-04-graphql-awareness.sh
  test-05-api-aggregation.sh
  test-06-openapi-import.sh
  test-07-openapi-response-validation.sh
  test-08-api-lifecycle.sh
```

## Running

```sh
docker compose up -d --build
./test-01-grpc-web-framing.sh
./test-02-json-transcoding.sh
# ...or run them all:
for t in test-*.sh; do ./"$t"; done
```

The gateway listens on `http://localhost:8080` (plaintext tests) and
`https://localhost:8443` (TLS + ALPN h2; grpcurl uses `-insecure`
because the quickstart cert is self-signed). No auth is configured on
any route. Categories share host ports — run one demo stack at a time.

## Routes

| Route | Match | Upstream | Protocol block |
|---|---|---|---|
| `healthz` | exact `/healthz` | - (respond 200) | - |
| `grpc-native` | prefix `/dwdemo.` | grpc-service | none — native gRPC passthrough |
| `grpc-web-rpc` | prefix `/rpc/` (strip) | grpc-service | `grpc_web: { enabled: true }` |
| `grpc-transcode` | prefix `/t/` (strip) | grpc-service | `grpc_web` + `transcoding` + descriptors |
| `rest-to-graphql` | prefix `/translate/` (strip) | echo-service | `translation: { kind: rest_to_graphql, graphql: { query_template } }` |
| `graphql` | exact `/graphql` (POST) | echo-service | `graphql: { enabled, depth_limit: 4, complexity_limit: 12 }` |
| `graphql-apq` | exact `/graphql-apq` (POST) | echo-service | `graphql` + `persisted_queries` (1-entry store) |
| `api` | prefix `/api/` | static-service | none |

## Test summary

| Test | Asserts | Wired? |
|---|---|---|
| 01 gRPC-Web framing | native gRPC via grpcurl through :8443 returns `hello, gateway!` (TLS+h2 in, pinned TLS+h2 out); the gRPC-Web POST is NOT translated (no framed greeting in the response) | limitation |
| 02 JSON transcoding | `GET /t/v1/hello/world` and `POST /t/v1/upper` are NOT transcoded (no JSON greeting); the same RPCs answer via native grpcurl | limitation |
| 03 protocol translation | `/translate/` route serves traffic with the block accepted; echo receives the original REST JSON (no GraphQL query synthesized) | limitation |
| 04 GraphQL awareness | passing query proxied (200); depth bomb → 400 `graphql_depth_exceeded`; wide query → 400 `graphql_complexity_exceeded`; persisted store hit → 200, miss → 400 `graphql_persisted_query_required` | **live** |
| 05 API aggregation | both fragments reachable through the gateway (200 + arrays); composed response skipped | limitation |
| 06 OpenAPI import | `dwara-cli import openapi` emits listUsers/listProducts/healthCheck routes + metadata; the emitted config validates (`ok: 3 routes`) | **live** (host CLI) |
| 07 OpenAPI response validation | `/api/*.json` responses conform to the spec (200, JSON, required fields); enforce/dry-run rejection paths skipped | limitation |
| 08 API lifecycle | gateway boots with the `lifecycle` block; `dwara-cli validate` prints `ok: 8 routes`; `/portal` (configured, enabled) returns 404 | partial |

## Documented limitations (maturity map)

All config surfaces below are accepted by the schema and the gateway
boots with them; the runtime halves differ. The corresponding guides
(`docs-site/guide/*.md`) describe the target behavior — these tests
record what the default `dwara:demo` build actually does today.

| Surface | Config schema | Library/engine | Proxy dispatch | Demo evidence |
|---|---|---|---|---|
| GraphQL limits + persisted queries (`routes[].graphql`) | yes | yes | **yes** | test-04 (400s enforced) |
| OpenAPI import (`dwara-cli import openapi`) | n/a (CLI) | yes | n/a | test-06 (host flow) |
| gRPC-Web framing (`routes[].grpc_web`) | yes (validates, descriptor files checked) | yes (`dataplane/grpc_web.rs`, test-covered) | no | test-01 (passthrough observed) |
| JSON→gRPC transcoding (`routes[].grpc_web.transcoding`) | yes (validates, descriptor files checked) | yes (dynamic protobuf↔JSON) | no | test-02 (passthrough observed) |
| Protocol translation (`routes[].translation`) | yes (kind + sub-blocks validated) | yes (`dataplane/translation*.rs`; SOAP translator not dispatched, per its own docs) | no | test-03 (passthrough observed) |
| API aggregation (`aggregations:` / `type: aggregate`) | **no** (block not in schema) | yes (`aggregation/`, test-covered) | no | test-05 (fragments only) |
| OpenAPI response validation (`openapi_validation:`) | **no** (block not in schema) | yes (engine test-covered) | no | test-07 (conformance only) |
| API lifecycle (`lifecycle:` portal/profiles/journey) | yes | yes (`lifecycle/` modules) | no (server binary does not serve/apply/record) | test-08 (404 at /portal) |

Notes:

- **REST→gRPC translation is the transcoding engine.** The
  `translation` block has no `rest_to_grpc` kind; per
  `dataplane/translation.rs` the REST↔gRPC direction reuses the DW-101
  `grpc_web` engine (test-02). The `translation` kinds that exist are
  `rest_to_graphql`, `graphql_to_rest`, `rest_to_soap`, `soap_to_rest`.
- The gRPC-Web/transcoding/translation blocks pass validation because
  validation checks the config shape (and that descriptor files exist);
  the proxy never consults the blocks, so requests are forwarded
  verbatim — which is exactly what tests 01–03 observe and assert.
- Aggregation and response validation cannot even be expressed:
  their blocks are rejected as unknown fields by `dwara-cli validate`,
  so those configs stay out of `dwara.yaml` (target surface quoted in
  the tests/README instead).
- The descriptor file (`protos/dwdemo.pb`) is checked for existence at
  config publish only; regenerate it with:
  ```sh
  docker run --rm -v "$PWD/protos:/out" dwara-demo/grpc sh -c \
    'PROTO_DIR=$(python -c "import google.api.annotations_pb2 as m, os; print(os.path.dirname(os.path.dirname(os.path.dirname(m.__file__))))") && \
     python -m grpc_tools.protoc -I/app/protos -I"$PROTO_DIR" \
     --descriptor_set_out=/out/dwdemo.pb /app/protos/dwdemo.proto'
  ```

## Teardown

```sh
docker compose down -v --remove-orphans
```

State (SQLite) lives in the `./data` bind mount (gitignored runtime
state; safe to delete). On Linux the directory must be writable by UID
65532: `sudo chown -R 65532:65532 data`.
