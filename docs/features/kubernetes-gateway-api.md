# Kubernetes Gateway API Translator (DW-064)

## Overview

dwara supports translating Kubernetes Gateway API v1 resources into
its config model. This is the core translation layer; the actual K8s
controller wiring (watching the API server via informers) is a
separate effort that composes on top of this translator.

## Enabling

Build with the `k8s` feature:

```sh
cargo build --features k8s
```

## Gateway API v1

The Gateway API v1 standard channel (v1.5) includes:
- `GatewayClass`: the kind of Gateway (dwara is a controller).
- `Gateway`: a listener configuration (ports, TLS, hostname).
- `HTTPRoute`: HTTP routing rules (matches, filters, backends).

## Translation

The translator maps:
- `Gateway` -> `Listener` (one per Gateway listener).
- `HTTPRoute` -> `Route` (one per HTTPRoute rule).
- `HTTPRoute` backendRefs -> `Service` + `Upstream` + `Endpoint`.

## API

### Resource types

The module provides Gateway API v1 resource types:
- `GatewayClass`, `GatewayClassSpec`
- `Gateway`, `GatewaySpec`, `GatewayListener`
- `HttpRoute`, `HttpRouteSpec`, `HttpRouteRule`, `HttpRouteMatch`
- `ParentReference`, `HttpBackendRef`, `HttpPathMatch`, `HttpHeaderMatch`
- `ListenerTlsConfig`, `SecretObjectReference`
- `ObjectMeta`

### translate

```rust
use dwara_core::k8s_gateway::{translate, Gateway, HttpRoute};
use std::collections::HashMap;

let result = translate(&gateway, &routes, &endpoints)?;
// result.gateway is a dwara Gateway config
// result.warnings is a list of translation warnings
```

The `endpoints` parameter is a map from `<namespace>/<service>:<port>`
to a list of dwara Endpoints (typically from EndpointSlices, resolved
by DW-042's discovery or a K8s informer).

## Supported features

- Protocols: HTTP, HTTPS, TLS
- TLS modes: Terminate, Passthrough
- Path matches: Exact, PathPrefix
- Route attachment via parentRefs
- Multiple listeners per Gateway
- Multiple rules per HTTPRoute
- Multiple endpoints per backend
- Warnings for missing endpoints, missing backends, unknown protocols,
  and unknown TLS modes

## Not yet supported

- The actual K8s controller wiring (kube-rs, informers, watch loops)
- Conformance suite pass against the v1.5 standard channel
- Implementation listing on k8s.io
- HTTPRoute filters (request headers, response headers, URL rewrite,
  request mirror, extension refs)
- GRPCRoute, TCPRoute, TLSRoute
- Cross-namespace route attachment (requires GatewayClass allowedRoutes)
- Weighted backend refs (ServiceSplit)

## Feature gate

The `k8s` cargo feature must be enabled. Without it, the module is
not compiled.
