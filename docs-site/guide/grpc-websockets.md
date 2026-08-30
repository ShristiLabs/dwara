# gRPC and WebSockets

The gateway proxies gRPC and WebSocket traffic on the same listeners
as everything else — no special mode, no separate port. This page
covers what the gateway does for each protocol and the one
WebSocket-specific setting.

## gRPC

A gRPC client (grpcurl, grpc-go, and friends) points at the gateway
like any upstream: TLS listeners serve gRPC via h2 ALPN, and cleartext
listeners serve it via h2c prior knowledge. Nothing is configured per
protocol — routes match gRPC paths (`/package.Service/Method`) like
any path.

Two gRPC specifics are handled for you:

- **Trailers pass through.** gRPC carries its status in HTTP trailers
  (`grpc-status`); the gateway forwards them untouched, so a failed
  RPC surfaces as `DEADLINE_EXCEEDED`/`UNAVAILABLE` in your client,
  not a proxy error.
- **`grpc-timeout` is enforced.** When the client's request carries a
  `grpc-timeout` header, the gateway treats it as the call's total
  budget: the upstream attempt (and the response stream) is cut when
  the budget expires, and the client receives `504` with
  `grpc-status: 4` (the deadline-exceeded marker) in the response
  headers.

For a gRPC upstream, set the upstream's `protocol: http2` (TLS with
h2 ALPN) and, for a private CA, `trusted_ca_file` — the same trust
model as any https upstream.

## WebSocket origin allowlists

By default a WebSocket upgrade is transparent: the gateway relays the
handshake and splices the connection. To restrict which sites may
open connections, add a `websocket` block to the route:

```yaml
routes:
  - name: chat
    service: chat-svc
    match:
      path: { type: prefix, value: /chat }
    websocket:
      origins:
        - https://app.example.com
    action: { type: proxy }
```

A non-empty `origins` list admits ONLY exact matches (scheme and host
must match exactly — `https://` and `http://` are different origins).
A handshake with no `Origin` header is REJECTED: browsers always send
one, so a missing origin means a non-browser client you did not name.
Denied handshakes get `403` and never reach the backend. Omit the
block (or leave the list empty) to allow every origin.

## WebSocket rate policing

To protect a backend from a flooding client, cap the frame rate on
the upgraded connection:

```yaml
    websocket:
      origins: [https://app.example.com]
      max_frames_per_sec: 100
```

The allowance is sustained data frames (text/binary/continuation)
per second from the CLIENT, with a one-second burst of the same size.
A client past its allowance is closed with close code `1008` (policy
violation) and disconnected; well-behaved clients that stay under the
rate never notice. The cap applies client-to-upstream only. Both
settings are independent — either can be set alone.

Decisions are observable in [`/metrics`](./observability) as
`dwara_websocket_policy_total{route,outcome}` with outcomes
`origin_denied` and `rate_closed`.
