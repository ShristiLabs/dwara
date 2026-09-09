# WebSockets

Dwara tunnels [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
traffic on the same listeners as everything else -- no special mode,
no separate port. A WebSocket app points at the gateway as it would
any upstream: by default an upgrade is transparent, with the gateway
relaying the handshake and splicing the connection into a managed
tunnel.

The one WebSocket-specific surface is an optional `websocket` block
on the route with two independent controls: an origin allowlist that
restricts which sites may open connections, and a frame-rate cap (a
frame is a WebSocket message unit) that protects a backend from a
flooding client.

Native gRPC over HTTP/2 is proxied on the same listeners too -- see
[gRPC proxying](./grpc).

## When to use this

Point a WebSocket app at the gateway when it should be reached
through the same listeners and routes as the rest of the API -- no
special config is needed for tunneling itself. Add the `websocket`
block when you need to restrict which sites may open connections
(origin allowlist) or protect a backend from a flooding client
(frame-rate cap).

## Configuration

Both settings live on the route's `websocket` block. They are
independent -- either can be set alone:

```yaml
routes:
  - name: chat
    service: chat-svc
    match:
      path: { type: prefix, value: /chat }
    websocket:
      origins:
        - https://app.example.com
      max_frames_per_sec: 100
    action: { type: proxy }
```

| Field | Default | Description |
|---|---|---|
| `websocket.origins` | `[]` (every origin) | Exact-match allowlist of origins that may open a connection. Omit the block or leave the list empty to allow every origin. |
| `websocket.max_frames_per_sec` | unset (no cap) | Cap on sustained data frames (text/binary/continuation) per second from the client, with a one-second burst of the same size. Applies client-to-upstream only. |

## Origin matching

A non-empty `origins` list admits **only** exact matches -- scheme
and host must match exactly, and `https://` and `http://` are
different origins. A handshake with no `Origin` header is
**rejected**: browsers always send one, so a missing origin means a
non-browser client you did not name. Denied handshakes get `403` and
never reach the backend.

## How it works

1. A client requests a WebSocket
   [upgrade](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/101)
   (Switching Protocols -- the handshake response that upgrades to
   WebSocket). The gateway relays the handshake and, once it
   succeeds, splices the two connections; traffic then flows through
   the tunnel.
2. If `origins` is non-empty, the handshake's `Origin` header must
   match an entry exactly. A denied handshake gets `403` and never
   reaches the backend.
3. If `max_frames_per_sec` is set, the gateway counts sustained data
   frames (text/binary/continuation) per second from the client on
   the upgraded connection, with a one-second burst of the same size.
4. A client past its allowance is closed with close code `1008`
   (policy violation) and disconnected; well-behaved clients that
   stay under the rate never notice. The cap applies
   client-to-upstream only.

## Observability

WebSocket policy decisions are observable in
[`/metrics`](./observability) as
`dwara_websocket_policy_total{route,outcome}` with outcomes
`origin_denied` and `rate_closed`.

For request-level limits on HTTP traffic, see
[Rate limiting](./rate-limiting).

## Runnable demo

A WebSocket echo upstream is proxied in `demos/05-request-response/`
(test script: `test-09-websocket.sh`) in the repository, behind a
route with an origin check and a frame-rate cap. The script verifies
the `/ws` route is reachable (a plain GET draws a 400/426, not a
404); a manual `websocat ws://localhost:8080/ws` session exercises
the echo. The category README covers prerequisites and teardown.
