# gRPC and WebSocket polish (DW-039)

> Implements issue DW-039 (M2, `edition/oss`, effort M) over the
> generic protocol upgrade path shipped by DW-009. Sources:
> `crates/dwara-core/src/dataplane/websocket.rs` (the origin gate,
> the RFC 6455 frame scanner, the policer — its module docs carry the
> full contract), the gRPC arm in `dataplane/proxy.rs`
> (`grpc_request`, `parse_grpc_timeout`, the per-attempt deadline
> wrap, the TE carve-out in `strip_hop_by_hop`), the body-deadline
> addition in `dataplane/upstream.rs` (`UpstreamBody::set_deadline`,
> `DeadlineExceeded`), validation in `snapshot/mod.rs`, the metric in
> `observability.rs`. Tests:
> `crates/dwara-core/tests/grpc_websocket.rs` (end to end: the gRPC
> round trip with trailers against a TLS-h2 double, deadline-bounded
> hangs incl. a retry that cannot fit, the origin matrix, burst and
> refill policing, mixed-token upgrades, transparency) and
> `crates/dwara-core/tests/unit/websocket.rs` (token detection, origin
> semantics, scanner across all length classes and chunk boundaries,
> control-frame interleave, the timeout grammar, the validation
> matrix). Operator docs:
> [docs-site gRPC & WebSockets guide](../../docs-site/guide/grpc-websockets.md).

Two protocol-polish items over the M1 foundations. gRPC over H2: the
gateway was already protocol-transparent for h2 traffic, but gRPC's
specifics needed teaching — the spec's `TE: trailers` request header
was stripped as hop-by-hop, and nothing honored `grpc-timeout`. And
the generic 101 tunnel (DW-009) worked for WebSocket but was
unmanaged: any origin could upgrade, and an abusive client could
flood an upstream at line rate. DW-039 closes both: gRPC deadlines
are enforced end to end, and WebSocket upgrades are gated and policed
— all with zero new dependencies (no tonic, no tokio-tungstenite; the
frame scanner hand-rolls exactly the RFC 6455 header grammar and not
one byte more).

## gRPC over H2

Routing needed no change — an h2 gRPC request (`content-type:
application/grpc` family) matches routes by `:path` like any request,
and response trailers (the `grpc-status`/`grpc-message` end-of-stream
frame) already flow through untouched: `UpstreamBody` and `ProxyBody`
forward body frames verbatim, so the upstream's trailer frame reaches
the h2 client as long as the route doesn't configure the stages that
buffer (response compression, caching, masking — the same
streaming-preservation rules as ever). The pinned round trip
exercises the full shape: h2c client -> gateway -> TLS-h2 upstream
(rcgen private CA, the `trusted_ca.rs` fixture pattern) with
`grpc-status: 0` read from the client's trailers.

Two things changed:

- **`TE: trailers` is forwarded for gRPC requests.** `strip_hop_by_hop`
  still drops `TE` for everything else (the pre-DW-039 stance: there
  was nothing a `TE` could license), but a gRPC request's spec-mandated
  header rides through — conformant servers check for it, and h2
  carries trailers natively anyway (the header is the courtesy
  contract, not the mechanism).
- **`grpc-timeout` is the RPC's total budget** (value grammar:
  1..=8 decimal digits + unit `H`/`M`/`S`/`m`/`u`/`n`, case-exact;
  overflow saturates at one day; garbage is ignored — a malformed
  timeout is the caller's bug). The armed deadline bounds TWO phases:
  the forward (each upstream attempt runs inside the REMAINING slice —
  a retry that cannot fit before the deadline is cut by the timeout,
  not started in vain) and the response body (`UpstreamBody` gained an
  absolute deadline checked in its existing poll loop, so a server
  that answers headers and then starves the stream is cut at the same
  instant). Expiry answers 504 with `grpc-status: 4`
  (DEADLINE_EXCEEDED) in the response HEADERS — the trailers-only
  shape — plus the standard JSON envelope for non-gRPC tooling.

Health-report split (deliberate, documented at the arm site): a
BODY-phase deadline crossing reports a passive-health failure (the
endpoint accepted the RPC and then starved it); a FORWARD-phase cut
does not (the client's own budget expired — the gateway cancelling on
the caller's clock is not endpoint misbehavior, and the operator's
`timeouts.read_ms` still bounds genuinely hung endpoints).

## WebSocket: the origin gate

`routes[].websocket.origins` is an exact-match allowlist evaluated in
the proxy action — after authn/authz/rate limit (the documented
request-path order; the origin allowlist is a route policy about the
upgrade, not an identity claim) and BEFORE any upstream contact (no
dial, no pick, no breaker observation). Semantics:

- Empty or absent list: every origin upgrades (the transparent
  DW-009 default).
- Non-empty list: ONLY exact matches upgrade. A MISSING `Origin`
  header is denied — browsers always send one on a WebSocket
  handshake, so an originless handshake is a non-browser client the
  operator did not name; fail closed (403, envelope code
  `websocket_origin_denied`).
- The literal `null` (the sandboxed-document origin) matches by exact
  string comparison if listed.

## WebSocket: post-upgrade policing

`routes[].websocket.max_frames_per_sec` arms a token bucket on the
UPGRADED CLIENT side of the tunnel: `rate` tokens per second,
capacity `rate` (a one-second burst), one token per DATA frame
(text/binary/continuation; ping/pong/close are free — they are the
protocol's housekeeping). The `WsPoliceIo` wrapper passes bytes
through unmodified while a frame-boundary scanner tracks where each
frame ends; on the first unfunded frame it queues the four-byte close
frame (opcode 8, status 1008, policy violation) for the CLIENT
direction — written ahead of any pending upstream bytes — and returns
EOF on the client reads, ending the tunnel.

Design points, each pinned by tests:

- **The scanner reads headers only.** 2..=14 bytes per frame
  (opcode + mask bit + 7/16/64-bit length; the 4 mask bytes are folded
  into the payload skip). It never unmasks, never validates opcodes
  beyond the data/control split, never allocates on hostile input —
  a 64-bit length of 2^63 is just a number to skip past. Extended
  (16/64-bit) lengths are data frames by construction: RFC 6455 caps
  control frames at 125 payload bytes.
- **Fragmented messages count per frame.** A client fragmenting every
  message gets policed harder, not softer; the conservative direction
  is the safe one.
- **Policing is one-directional.** It protects upstreams from abusive
  clients; an abusive upstream is the operator's backend problem.
- **The upstream's 101 decides.** Policing keys off the protocol the
  UPSTREAM actually upgraded (its 101 names it), never the client's
  offered tokens — a mixed-token request (`Upgrade: foo, websocket`)
  whose backend upgrades `foo` gets the generic tunnel, unpoliced, so
  no WS frame is ever parsed into (or a close frame injected into) a
  non-WebSocket stream.
- **Transparency is the default.** Without a `websocket` block, the
  tunnel is the byte-exact DW-009 splice (pinned: a 50-frame burst
  echoes whole, unpoliced).

## Configuration and metrics

```yaml
routes:
  - name: chat
    service: chat-svc
    match:
      path: { type: prefix, value: /chat }
    websocket:
      origins: [https://app.example.com]   # exact match; missing Origin denied
      max_frames_per_sec: 100              # 1..=100000; absent = unpoliced
    action: { type: proxy }
```

Validation rejects empty or over-256-byte/non-printable origins and
rates outside `1..=limits::MAX_WEBSOCKET_FRAMES_PER_SEC`. The knobs
are independent — either may be set alone.

Decisions land in `dwara_websocket_policy_total{route,outcome}` with
the closed set `origin_denied` (gate, before upstream contact) and
`rate_closed` (policer; counted when the tunnel task completes, so a
process exit mid-tunnel can undercount). The route label is the
config-declared route name — the same cardinality class as
`requests_total`.

The [dataplane and proxy](./dataplane-proxy.md) page covers the
generic tunnel this feature manages; [protocol
hardening](./protocol-hardening.md) covers the parser bounds that
already bound both protocols' handshakes.
