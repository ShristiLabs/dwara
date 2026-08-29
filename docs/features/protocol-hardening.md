# Protocol hardening

Source: `crates/dwara-core/src/dataplane/hardening.rs` (DW-023).
Tests: `protocol_hardening` (dwara-bin). Applied identically to every
serving surface — data-plane listeners and the admin listener alike
(see [Admin API: hardening posture](./admin-api.md#hardening-posture-and-its-one-asymmetry)
for the one deliberate exception). The module also hosts DW-027's
route-scoped request limits and the `merge_vary` helper — those are
per-route config, not env knobs, and are covered in
[edge policies](./edge-policies.md).

Pass 2 (DW-030) added three protocol-edge features that live in their
own modules but share this page's posture: PROXY protocol acceptance
([`dataplane::proxy_proto`](#proxy-protocol-acceptance-dw-030)), the
per-route method allowlist
([below](#per-route-method-allowlist-dw-030)), and RFC 8305
happy-eyeballs dialing
([below](#happy-eyeballs-dialing-dw-030)).

The end-user-facing knob table already lives at
[docs-site: Operations](../../docs-site/guide/operations.md#protocol-hardening)
and is covered from the proxy's-eye view in
[Dataplane and proxy](./dataplane-proxy.md#protocol-hardening) — this
page is the implementation-focused version: two independent defense
families, why each bound is where it is, and how the pieces compose.

## Two families of defense

```mermaid
flowchart TB
    subgraph Family1[1. Parser / amplification bounds]
        H1[HTTP/1: max headers,\nmax buffer, header timeout]
        H2[HTTP/2: max concurrent streams,\nstream/connection windows,\nmax send buffer]
    end
    subgraph Family2[2. Request-body inactivity gap]
        IB[InboundBody wrapper\nerrors on stalled body frames]
    end
    Conn[Every accepted connection] --> Family1
    Conn --> Family2
```

**1. Parser/amplification bounds** on hyper's connection builders, so
a single hostile connection can't pin unbounded memory or parse cost.
Each bound targets one specific attack shape:

| Knob (env) | Default | Attack it bounds |
| --- | --- | --- |
| `DWARA_HTTP1_MAX_HEADERS` | 100 | header-count bombs (N header lines per request) |
| `DWARA_HTTP1_MAX_BUF_KIB` | 64 KiB | single-header/line size bombs — hyper's read-buffer cap; an oversized header line is a 431-class parse failure, not unbounded allocation |
| `DWARA_HTTP1_HEADER_TIMEOUT_MS` | 10000 | slowloris — a connection sending headers slower than this is closed before it ever reaches a route |
| `DWARA_H2_MAX_CONCURRENT_STREAMS` | 128 | stream floods over one h2 connection (also advertised to the peer in `SETTINGS`, so a well-behaved peer self-limits before even trying) |
| `DWARA_H2_STREAM_WINDOW_KIB` | 1024 (1 MiB) | per-stream receive buffering a malicious h2 peer can force by withholding window updates |
| `DWARA_H2_CONNECTION_WINDOW_KIB` | 4096 (4 MiB) | connection-wide h2 receive buffering |
| `DWARA_H2_MAX_SEND_BUF_KIB` | 1024 (1 MiB) | outbound h2 send buffer per connection — write amplification / memory pinning by a peer that advertises a window but never actually reads |

**Deliberately left at hyper's own defaults, not exposed as knobs:**
`max_frame_size` (16 KiB — the *minimum legal value* per the HTTP/2
spec; hyper already refuses anything larger, so there's no smaller
value to expose) and HTTP/2 `max_headers` (hyper-util's h2 builder has
no such knob at all — the header list size is already bounded
indirectly by the flow-control windows above, so there was nothing to
add a redundant cap for).

A `TokioTimer` is explicitly installed on the HTTP/1 connection
builder for one specific reason: hyper disables `header_read_timeout`
entirely when no timer is configured, so without this, the slowloris
knob above would silently do nothing.

**2. Request-body inactivity gap** (`DWARA_REQUEST_BODY_TIMEOUT_MS`,
default 30000, `0` disables): the inbound request body handed to the
dataplane is wrapped in `InboundBody`, which errors when the gap
between two consecutive body frames exceeds the configured duration.
This is deliberately a **gap** timeout, not a total-time budget — the
semantics mirror the response-side `write_ms` wrapper
(`UpstreamBody`) on purpose, so a contributor who understands one
already understands the other. A legitimate slow upload (a large file
crawling over a poor connection) that keeps making *some* progress
every few seconds never trips it; a client that sends headers and then
holds the connection open indefinitely — pinning a concurrency slot
and an upstream connection for nothing — gets cut off once the gap
elapses. When it fires, the in-flight upstream attempt fails as a
transport-class error (the proxy answers 502 and closes), and the
request's global concurrency slot releases immediately rather than
waiting out whatever budget the stalled client might otherwise have
consumed.

## CL+TE smuggling needs no code here

Deliberately absent from this module: any explicit check for a
request carrying both `Content-Length` and `Transfer-Encoding`.
hyper 1.x's own HTTP/1 parser already rejects such a request (400,
connection closed) before it reaches any dwara code, and the gateway
never hands raw bytes to an upstream — every forwarded request is
rebuilt from hyper's already-parsed parts (see
[Dataplane and proxy: protocol hardening](./dataplane-proxy.md#protocol-hardening)),
so a "smuggled second request" would require hyper itself to
mis-parse the first one. Both of those properties (hyper's rejection,
and the rebuild-not-passthrough forwarding model) are pinned by a
smuggling-corpus integration test suite in `dwara-bin`, rather than
re-verified here — this module's job is the bounds above, not
re-implementing a defense hyper already provides.

## How the sniff and hyper's own timeout compose

There's a subtlety worth internalizing before touching
`DWARA_HTTP1_HEADER_TIMEOUT_MS`: the pre-parse sniff that inspects a
connection's first request head is a **per-read** timeout, not a
total-head budget. A client that trickles exactly one byte at a time,
each individual byte arriving just inside the configured timeout,
keeps every single sniff read "successful" — the sniff alone would
never catch that pattern. The actual defense for that specific case is
hyper's own **per-head** `header_read_timeout`, installed on the
connection builder with the *same* knob value and the `TokioTimer`
noted above — it bounds the total time one request head may take,
regardless of how the bytes are paced. The two compose deliberately:
the sniff owns judging each individual read (and is what lets dwara
hand a connection off to hyper instead of racing hyper for the same
bytes), while hyper owns the head as a whole — so neither a single
stalled read nor a slow byte-at-a-time trickle can hold a listener
resource hostage indefinitely.

## One posture, resolved once, logged once

Every knob above is an environment variable read **once at startup**
and applied **process-wide** — not per-listener, and not
per-request. An invalid value falls back to its documented default
rather than failing startup, on the reasoning that hardening exists to
make the gateway *more* robust, and a typo in a hardening knob should
never be the reason the whole process refuses to start. The resolved
values (whatever they ended up being, defaults or overrides) are
logged once at startup under the `protocol_hardening` code, so an
operator debugging "why did this connection get closed" can always
find out exactly what bound was actually in effect without having to
cross-reference environment variables against documentation defaults.

## PROXY protocol acceptance (DW-030)

Source: `crates/dwara-core/src/dataplane/proxy_proto.rs`; wiring in
`crates/dwara-bin/src/listeners.rs` (`proxy_phase`). Tests:
`tests/unit/proxy_proto.rs` (header policy, all classify branches and
bounds), `protocol_hardening` (real binary: v1/v2 address flow,
malformed 400, opt-out no-sniffing, and the TLS-terminate ordering —
header before handshake, and fail-closed before TLS when absent).

A listener with `proxy_protocol: true` expects a PROXY protocol
header (HAProxy specification; v1 text or v2 binary) as the FIRST
bytes of every connection — before the TLS handshake in terminate
mode, because the L4 load balancer in front wraps the whole stream.
The header's source address then replaces the accepted socket peer
for everything downstream that consumes it: the authz IP ACL's
effective-client-IP base, rate-limit keying, and the
`X-Forwarded-For`/`X-Real-IP` values stamped on the forwarded
request. Bytes read past the header (a sender pipelining TLS records
or the HTTP head behind it) are replayed via
`hardening::PrefixedStream` — the same replay wrapper the smuggling
sniff uses.

The security posture, frozen with the design:

- **Opt-in per listener.** No sniffing: a listener without the flag
  serves PROXY bytes as ordinary HTTP input (they are parse garbage).
  The spoofing boundary is exactly the config — the same trust model
  as `gateway.trusted_proxies` for XFF.
- **Fail closed.** A malformed header (bad signature, bad lengths,
  Unix address family, datagram protocol on this stream listener,
  over-ceiling) is answered with the 400 error envelope and the
  connection is closed — the bytes are never handed to HTTP parsing.
  A connection that stalls mid-header or drops is closed silently
  (nothing parseable to answer), bounded by the DW-023 slowloris
  header timeout — the same attack one layer earlier, as a
  WHOLE-header bound (a partial PROXY line can never be handed on).
- **Bounded.** v1 ≤ 107 bytes, v2 ≤ 16 + 65535; a prefix that
  matches neither version signature is malformed immediately.
  Parsing itself is delegated to the `ppp` crate (Apache-2.0,
  allow-listed in `deny.toml`); this module owns the async framing
  read, the deadline, the caps, and the fail-closed policy.
- **Spec fallbacks honored.** A v2 `LOCAL` command (the LB's own
  health check) and a v1 `UNKNOWN` line keep the REAL peer address.

The flag is part of the restart-only bind set (toggling takes a
restart, like address/port) and cannot combine with
`tls.mode passthrough` — validation rejects it: a passthrough
listener splices raw bytes and never runs the pipeline that consumes
the address.

## Per-route method allowlist (DW-030)

Source: `crates/dwara-core/src/dataplane/proxy.rs` (the
`method_not_allowed` arm). Tests: `method_allowlist` (dwara-core,
end-to-end matrix).

A non-empty `methods` list on a route answers `405` + `Allow` for
every method not in it. Placement mirrors the DW-041 maintenance
argument: the allowlist is a statement about the ROUTE, not the
request's shape, so it runs after route resolution and the
maintenance 503, before the route limits and authentication. A CORS
preflight is exempt exactly like the maintenance 503 (the preflight
is a Fetch-protocol handshake about the gateway's cross-origin
policy; failing it would surface in the browser as an opaque CORS
error) — and the 405 itself is CORS-decorated and security-stamped
so a browser can read it. `Allow` echoes the configured methods
verbatim in configured order (RFC 9110 10.2.1). Matching is
case-insensitive; HEAD is NOT implicitly granted by GET (the
allowlist is exhaustive by design — implicit grants would leak
methods the operator never named). Validation enforces the HTTP
method-token grammar and rejects case-insensitive duplicates.
Distinct from `match.methods`, which gates ROUTE RESOLUTION (a miss
falls through to other routes); this list gates the already-matched
route.

## Happy-eyeballs dialing (DW-030)

Source: `crates/dwara-core/src/dataplane/upstream.rs`
(`happy_dial`/`happy_race`/`interleave_order`). Tests:
`tests/unit/upstream.rs` (ordering and race semantics, driven
through the `#[doc(hidden)]` test seams — real dials cannot make
"the first address hangs" deterministic on loopback),
`upstream_client` (dual-stack end-to-end).

`upstreams[].timeouts.happy_eyeballs_ms` (default 250 per RFC 8305,
`0` disables racing, validated ≤ 10 minutes): when an endpoint's
authority resolves to multiple addresses, the first is dialed
immediately and each subsequent address — the other address family
alternating in after the resolver's first — is dialed one delay
after the previous START; RFC 8305 §5.2 failure fast-forward starts
the next attempt immediately when an attempt fails with nothing else
in flight; the first success wins and dropping the race's `JoinSet`
cancels the losers. Two accounting rules are frozen: the upstream's
`connect_ms` bounds the WHOLE dial (resolution + every interleaved
attempt + the TLS handshake), and exactly ONE outcome per dial
reaches breaker and passive-health accounting — a losing arm is
never an endpoint failure. Active health probes dial through the
same discipline (one dialing discipline per upstream). IPv6
IP-literal authorities are stripped of their `Uri::host()` brackets
before resolution and SNI (`[::1]` → `::1`) — the strip hyper-util's
old resolver did internally, now ours because the dial is ours.
