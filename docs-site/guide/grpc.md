# gRPC proxying

Dwara proxies native [gRPC](https://en.wikipedia.org/wiki/GRPC) -- a
high-performance RPC framework over HTTP/2 -- on the same listeners as
everything else: no special mode, no separate port. A gRPC client
(grpcurl, grpc-go, and friends) points at the gateway as it would any
upstream, and routes match gRPC paths like any path.

Two gRPC specifics are handled for you, so RPC semantics survive the
proxy hop: trailers pass through untouched (a failed RPC surfaces as a
gRPC status in your client, not a proxy error), and the client's
`grpc-timeout` header is enforced as the call's total budget.

This page covers native gRPC over HTTP/2. Browsers cannot speak
HTTP/2 trailers directly, so browser clients use gRPC-Web framing,
which the gateway translates separately -- see
[gRPC-Web](./grpc-web). WebSocket connections are tunneled on the
same listeners as well; see [WebSockets](./websockets).

## When to use this

Point a gRPC client at the gateway when RPC traffic should get the
same routing, policy, and observability as the rest of the API. There
is no special config to enable: TLS listeners serve gRPC via
[h2 ALPN](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation)
(HTTP/2 negotiated over TLS via ALPN), cleartext listeners serve it
via h2c prior knowledge (HTTP/2 over cleartext, where the client
assumes h2 without negotiation), and routes match gRPC paths
(`/package.Service/Method`) like any path.

## Configuration

On the listener side nothing is gRPC-specific. What you configure is
the upstream: set the upstream's `protocol: http2` (TLS with h2 ALPN)
and, for a private CA, `trusted_ca_file` -- the same trust model as
any `https` upstream.

```yaml
routes:
  - name: orders-rpc
    service: grpc-svc
    match:
      path: { type: prefix, value: /package.orders.Orders/ }
    action:
      type: proxy
      upstream:
        protocol: http2
        trusted_ca_file: /etc/dwara/upstream-ca.pem
```

| Field | Default | Description |
|---|---|---|
| `upstream.protocol` | -- | Transport used to dial the upstream. `http2` (TLS with h2 ALPN) is what a native gRPC upstream speaks. |
| `upstream.trusted_ca_file` | -- | PEM CA bundle, set when the upstream's certificate is issued by a private CA. Without it the standard `https` trust model applies. |

## How it works

1. The gRPC client connects to an existing listener. On TLS the
   client negotiates HTTP/2 via h2 ALPN; on cleartext it uses h2c
   prior knowledge. Nothing is configured per protocol.
2. The gateway matches the RPC path (`/package.Service/Method`)
   against routes like any path -- there is no gRPC-specific routing
   mode.
3. The matched upstream is dialed with `protocol: http2`, and the
   request and response streams are relayed end to end, trailers
   included.

## Trailers

**Trailers pass through.** gRPC carries its status in HTTP
[trailers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer)
(headers sent after the body, used by gRPC to carry its status)
(`grpc-status`); the gateway forwards them untouched, so a failed RPC
surfaces as `DEADLINE_EXCEEDED`/`UNAVAILABLE` in your client, not a
proxy error.

## Deadlines

**`grpc-timeout` is enforced.** When the client's request carries a
`grpc-timeout` header, the gateway treats it as the call's total
budget: the upstream attempt (and the response stream) is cut when
the budget expires, and the client receives `504` with
`grpc-status: 4` (the deadline-exceeded marker) in the response
headers.

For the gateway's own request-timeout configuration, see
[Timeouts](./timeouts).
