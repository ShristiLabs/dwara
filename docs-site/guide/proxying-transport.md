# Proxying and transport

The wire level: how Dwara accepts a connection, what protocols it
speaks, and how it reaches the upstream. Everything here is about
moving bytes between a client and a backend -- the matching, shaping,
policy, and identity layers sit on top.

Dwara is a streaming reverse proxy by default. HTTP/1.1 and HTTP/2
bodies pass through under frame-based backpressure with no buffering,
so SSE streams and large uploads work without tuning. TLS terminates
with multi-SNI certificate selection, or the ClientHello SNI can be
passed through to a backend that terminates its own TLS.

## In this section

- [Routing and matching](./routing) - exact (with path parameters),
  regex, and prefix matching with fixed precedence; host, method,
  header, query, and cookie criteria; rewrites, redirects, and direct
  responses.
- [Load balancing and traffic splitting](./traffic-splitting) -
  round-robin, least-requests, random, ip-hash, and peak-EWMA
  strategies; canary and blue-green splits; sticky sessions.
- [Dynamic upstream discovery](./dynamic-discovery) - DNS-based
  endpoint discovery so upstream pools track changing backends without
  a reload.
- [gRPC proxying](./grpc) - native gRPC over h2 with trailer
  passthrough and deadline handling.
- [WebSockets](./websockets) - managed tunnels with an origin
  allowlist and frame-rate policing.
- [HTTP/3 ingress](./http3) - h3 over QUIC listeners with 0-RTT early
  data policy and Alt-Svc advertisement.
- [H3/QUIC upstream transport](./h3-quic-upstream) - dial upstreams
  over QUIC for reduced connection latency and head-of-line blocking
  avoidance.
- [L4 TCP/UDP proxying](./l4-proxying) - SNI-based routing reuse for
  non-HTTP protocols. Partially wired; see the page for current
  status.
- [Post-quantum TLS](./post-quantum-tls) - hybrid key exchange
  (X25519 + ML-KEM) for forward secrecy against future quantum
  adversaries.

## Runnable demo

The [`demos/01-routing/`](https://github.com/shristilabs/dwara/tree/main/demos/01-routing) and `demos/10-tls-transport/` directories in
the repository run live stacks for the features in this section --
routing match types and actions in the former; TLS termination,
multi-SNI certificate selection, and HTTP/2 via ALPN
(`test-05-http2.sh`) in the latter. Each category README covers
prerequisites, test scripts, and teardown.

## Where to go next

- [Request and response control](./request-response-control) - the
  application-level shaping that runs after matching.
- [Traffic policy and resilience](./traffic-policy) - the protective
  layer in front of upstreams.
- [Architecture: connection and TLS](../architecture/connection-and-tls)
  - the internal design of the listener and TLS subsystems.
