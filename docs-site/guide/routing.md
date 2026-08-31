# Routing and request handling

How Dwara matches an incoming request to an upstream, and how it can
shape the request and response along the way. These are the
route-level building blocks you compose to expose your services:
edge policies, transforms, caching, versioning, traffic splitting,
protocol handling, discovery, and config scaffolding from an OpenAPI
spec.

The core routing vocabulary (Listener, Route, Service, Upstream,
Endpoint) is covered in [Configuration](./configuration); this section
covers the optional route blocks that go on top.

## In this section

- [CORS, compression, and request limits](./edge-policies) - the three
  edge blocks that answer browsers, shrink bodies, and cap request size.
- [Transforms and security headers](./transforms) - rewrite headers,
  query strings, and JSON bodies; stamp security headers on responses.
- [Response field masking](./masking) - redact named fields per consumer
  group before anything else touches the body.
- [Response caching](./caching) - replay identical GET responses to cut
  upstream load and tail latency.
- [API versioning](./api-versioning) - express versions with routing,
  match on `Accept`, and deprecate a version with standard headers.
- [Traffic splitting and sticky sessions](./traffic-splitting) - weighted
  canary/blue-green splits plus a sticky-session cookie.
- [gRPC and WebSockets](./grpc-websockets) - proxying both protocols on
  the same listeners, and the one WebSocket origin gate.
- [Dynamic upstream discovery](./dynamic-discovery) - DNS-based live
  endpoint discovery for autoscaling upstreams.
- [OpenAPI import and mock mode](./openapi-import) - scaffold a config
  from an OpenAPI spec and mock endpoints with no backend yet.
