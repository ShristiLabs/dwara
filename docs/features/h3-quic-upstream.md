# HTTP/3 (QUIC) upstream transport (DW-108)

> Implements issue DW-108 over the H3 ingress listener shipped by
> DW-088. Sources: `crates/dwara-core/src/dataplane/upstream_h3.rs`
> (the H3 egress connector -- `QuicStreamPool`, `H3UpstreamHandle`,
> `h3_request`, `H3Error`, the module docs carry the full transport
> contract), `crates/dwara-core/src/dataplane/upstream.rs` (the
> TCP/TLS pooled client, `UpstreamBody`, `UpstreamError`,
> `UpstreamStats` -- the shared layers the H3 path maps onto), the
> `UpstreamProtocol::H3` variant in `crates/dwara-core/src/config/mod.rs`,
> the shared rustls client config in `security::tls`
> (`https_h3_client_config`). Tests: the H3 upstream integration
> suite (the QUIC round trip against a real h3 server, connection
> pooling, idle sweep, the feature-off fail-closed path). Operator
> docs: [docs-site HTTP/3 guide](../../docs-site/guide/http3.md).

The mirror of the DW-088 H3 ingress listener: an H3 egress connector
that dials upstream endpoints over QUIC and speaks HTTP/3 on
bidirectional QUIC streams. A route whose upstream is configured
`protocol: h3` dispatches through `upstream_h3` instead of the
TCP/TLS pooled client in `upstream`. Everything in the module is
behind `#[cfg(feature = "h3")]`; when the feature is off,
`protocol: h3` upstreams are accepted at validation but inert (every
dispatch fails closed with `UpstreamError::H3Unavailable`).

## How it differs from HTTP/3 ingress

DW-088 is the ingress side: the gateway accepts H3 from clients (a
QUIC listener bound to a UDP port, ALPN `h3`). DW-108 is the egress
side: the gateway dials upstreams over QUIC. The two share the same
dependency stack (quinn, h3, h3-quinn) and the same rustls client
config shape, but they are independent code paths. An H3 ingress
request can be proxied to a TCP/TLS upstream, and a TCP/HTTP ingress
request can be proxied to an H3 upstream -- the ingress and egress
transports are decoupled.

## The dependency stack

The `h3` cargo feature pulls in three crates:

- **quinn** -- the QUIC transport (UDP sockets, connection management,
  congestion control). `QuicStreamPool` binds one quinn client endpoint
  (an ephemeral `0.0.0.0:0` UDP socket) for all dials.
- **h3** -- the HTTP/3 protocol layer (frame parsing, QPACK headers,
  stream management). `h3::client::new` wraps a quinn connection.
- **h3-quinn** -- the bridge (`h3_quinn::Connection` wraps a
  `quinn::Connection`; `OpenStreams` is the quinn stream type param).

## Transport model: the inverted pool

QUIC multiplexes many streams over one connection, so the pool shape
is inverted relative to HTTP/1.1: a QUIC connection is the pooled
resource, and each request opens a fresh bidirectional stream within
it. `QuicStreamPool` keeps a bounded set of QUIC connections per
endpoint address (`max_conns_per_endpoint`, default
`DEFAULT_H3_CONNECTION_CAP` = 8 -- lower than the TCP/TLS default of
64 because one QUIC connection carries many streams). It hands out a
cheaply cloneable `h3::client::SendRequest` handle per request (one
stream per `send_request` call) and reaps connections idle past
`DEFAULT_H3_IDLE_TIMEOUT_MS` (30 s).

`acquire` is the fast path: a live connection is available under the
lock, take a clone of its `SendRequest` (h3 counts clones and keeps
the QUIC connection alive until the last clone drops) and bump its
last-used clock. If no live connection exists, dial a new one outside
the lock (async, bounded by `connect_timeout`). Dead entries (driver
task finished) are reaped opportunistically in `acquire` and in the
periodic `sweep`. The sweep task runs at half the idle window so a
connection is reaped within ~1.5x idle_timeout of its last stream.

Each pooled connection has a driver task (`ConnEntry::driver`) that
pumps h3 control frames (GOAWAY, settings) via
`h3::client::Connection::wait_idle`. Its completion signals the
connection is closed; `is_live()` is the liveness probe `acquire` uses
to skip dead entries without dialing through them.

## TLS and 0-RTT

QUIC mandates TLS 1.3, so every H3 upstream negotiates TLS with ALPN
`h3`. The trust roots are the SAME ones the pooled https connector
uses (#121): the Mozilla webpki public set by default, or the
upstream's `trusted_ca_file` bundle when configured. The shared
rustls client-config shape lives in `security::tls`
(`https_h3_client_config`) so the connector and the QUIC active health
probe can never disagree about trust.

0-RTT is deliberately NOT used for upstream dialing: 0-RTT early data
is replayable, and a replayed non-idempotent upstream request is a
footgun the gateway must not expose by default.

## The request/response exchange

`h3_request` sends an HTTP/3 request over a QUIC stream (one
`send_request` call = one bidirectional stream) and reads the full
response. The request body is sent as a single `DATA` frame; the
response body is collected into one `Bytes`. Trailers are discarded;
the stream is drained to close it cleanly.

`H3UpstreamHandle::send` is the per-attempt entry point: resolve the
endpoint address (`resolve_one`, the first `getaddrinfo` result --
happy-eyeballs racing across QUIC addresses is a follow-up), acquire a
sender from the pool, send the request, and map `H3Error` onto the
shared `UpstreamError` so the proxy, breaker, and health layers stay
transport-agnostic. The per-attempt `read_timeout` bounds the whole
exchange (resolve + dial + write + headers + body), mirroring the
TCP/TLS path's per-attempt deadline. A QUIC `ConnectionError::TimedOut`
maps to `ConnectTimeout`; all other H3 errors map to
`UpstreamError::Io` (retryable transport errors).

## Response buffering (documented v1 limitation)

Unlike the TCP/TLS path (which streams the upstream body through
`UpstreamBody`), the H3 path buffers the full response body before
returning. h3's `recv_data` is an async method on the stream handle,
not a hyper `Body`, and bridging it into the streaming `UpstreamBody`
wrapper without a per-stream driver task is a follow-up. The request
body is likewise buffered (sent as one `DATA` frame). Streaming H3
bodies are a future improvement, not a regression: an H3 upstream is a
new transport.

## Configuration

```yaml
upstreams:
  - name: api-h3
    protocol: h3              # HTTP/3 over QUIC; requires the h3 feature
    endpoints:
      - address: api.example.com
        port: 8443
    timeouts:
      connect_ms: 5000
      read_ms: 30000
    connection_cap: 8         # QUIC connections per endpoint (default 8)
    trusted_ca_file: /etc/dwara/ca.pem   # optional; default webpki
```

`UpstreamProtocol::H3` is the config variant (snake_case `h3`). QUIC
mandates TLS 1.3, so an `h3` upstream always negotiates TLS with ALPN
`h3`; the `trusted_ca_file` field selects the trust roots. Requires
the `h3` cargo feature on dwara-bin to actually proxy: when the
feature is off the protocol is accepted at validation but the upstream
is inert (every dispatch fails closed with a clear error rather than
silently falling back to a wrong transport).

The [dataplane and proxy](./dataplane-proxy.md) page covers the
shared LB/breaker/retry/health layers the H3 path maps onto; the
[TLS](./tls.md) page covers the shared rustls client config.
