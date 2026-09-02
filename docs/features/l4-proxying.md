# L4 TCP/UDP proxying with SNI routing reuse (DW-103)

> Implements issue DW-103 (M2, `edition/oss`, effort M). Sources:
> `crates/dwara-core/src/dataplane/l4.rs` (the `L4Dispatcher`, the
> `L4ProxyConfig`, the `L4DispatchAction` outcome, the
> `splice_with_idle` tunnel, the stubbed `UdpDispatcher`, the
> `pick_endpoint` fallback), the listener wiring in
> `crates/dwara-bin/src/listeners.rs` (the `ListenerMode::L4` variant,
> the `bind_listener` arm for `protocol: tcp`, the accept-loop spawn
> that drives the dispatcher per connection), the config schema in
> `crates/dwara-core/src/config/mod.rs` (`ListenerProtocol::Tcp` /
> `Udp`, `L4Config` with `upstream`, `sni_routing`, `idle_timeout_s`),
> and validation in `src/snapshot/mod.rs`. Tests: the snapshot-pipeline
> validation matrix in `crates/dwara-core/tests/snapshot_pipeline.rs`
> (the `l4` inert-feature warning, the `tcp` listener without the `l4`
> feature rejection) and the panic-supervisor respawn coverage in
> `crates/dwara-bin/src/listeners.rs` (the shared accept-loop plumbing
> the L4 arm rides). Operator docs: [docs-site routing
> guide](../../docs-site/guide/routing.md).

L4 proxying is a LISTENER TYPE, not a route action. A `protocol: tcp`
(or `protocol: udp`) listener accepts raw L4 connections and splices
them byte-for-byte to an upstream endpoint, never running the HTTP
pipeline. This is the same byte-splice model the DW-008 TLS passthrough
path uses -- and when `sni_routing` is true, the TCP dispatcher reuses
the EXACT SNI extraction from passthrough
(`security::tls::sni_from_client_hello` + the peek loop) to select the
upstream from the listener's `tls.sni_routes`. The gateway thus serves
both as a TLS-terminating HTTP gateway and as an L4 TCP load balancer
that routes by SNI without terminating TLS, on separate listeners.

## The TCP dispatcher

`L4Dispatcher` (built from `L4ProxyConfig`) accepts one TCP connection
and:

1. If `sni_routing` is true, peeks the TLS ClientHello SNI (reusing
   `peek_client_hello_sni` -- the peek-only half of
   `tls::handle_passthrough`, the same bounded reassembly, the same
   64 KiB budget, the same 10s peek timeout). The SNI is matched
   against the listener's `tls.sni_routes` to select the upstream; the
   configured `upstream` is the fallback for no-SNI / unmatched names
   (absent = close).
2. If `sni_routing` is false, the configured `upstream` receives every
   connection.
3. The selected upstream's endpoint is picked through the CURRENT
   generation's balancers (no hash key -- a byte splice has no
   client-IP semantics), so L4 picks follow config reloads.
4. The client and upstream connections are spliced with
   `tokio::io::copy_bidirectional` until either side closes (the same
   tunnel the passthrough path and the 101 upgrade path use). An
   optional idle timeout closes the splice when neither side sends data
   for the configured duration.

Peeking (never reading) keeps the ClientHello bytes available for the
upstream once splicing starts: the entire hello is still in the socket
buffer and is replayed to the upstream by the splice. The dispatcher is
stateless beyond the config -- each `dispatch` call handles one
connection. `L4DispatchAction::Forward { host, port }` records the
splice target for metrics/logging; `L4DispatchAction::Close` records a
connection closed with no upstream, no endpoint, no SNI match, or a
connect/splice error.

`splice_with_idle` wraps `copy_bidirectional` in a `tokio::time::timeout`
when an idle timeout is configured; without one the splice runs until
either side closes. A splice error (one side reset mid-stream) is
expected at L4 -- it is logged at debug and the connection closed, not
propagated as a hard error to the caller (the connection is gone either
way).

## SNI routing reuse

The deliberate design choice is to reuse the passthrough SNI machinery
rather than fork it. `peek_client_hello_sni` is the peek-only half of
`handle_passthrough`, extracted for this path; the L4 dispatcher owns
the splice (idle timeout, metrics) rather than letting
`handle_passthrough` splice for us. `resolve_passthrough` resolves the
SNI against `tls.sni_routes` with an `EndpointPicker` closure that
picks through the current generation's balancers -- the same resolver
passthrough uses, so the routing table and the load-balancing semantics
are identical between the two paths. A non-TLS client, a missing SNI,
or an unmatched name falls through to the configured `upstream`
fallback, or is closed when no fallback is configured.

## UDP dispatcher (stubbed)

`UdpDispatcher` is STUBBED. UDP session semantics (per-client session
tracking, NAT timeout management, datagram boundaries) are harder to
get right than a byte splice and are a follow-up. The stub accepts the
config shape and returns `L4Error::Unimplemented` from `dispatch` so the
listener wiring can close the socket cleanly. The config schema is
present so configs round-trip; a `protocol: udp` listener binds a UDP
socket in `main.rs` (the same skip pattern as H3) and the stub answers
every datagram batch with `Unimplemented`.

## Listener wiring

`bind_listener` constructs `ListenerMode::L4 { config, sni_routes }`
for a `protocol: tcp` listener when the `l4` cargo feature is on; the
compiled `L4ProxyConfig` and the listener's `tls.sni_routes` are
captured at bind time. Without the feature, `bind_listener` returns an
error (the binary was not built with L4 support) -- mirroring the h3
pattern. The accept loop spawns one task per accepted connection: it
consults the CURRENT snapshot for the gateway (SNI route resolution +
endpoint fallback), constructs an `L4Dispatcher`, and drives
`dispatch`. L4 splices are not part of hyper graceful shutdown (the
same limitation as passthrough: no drain signaling through a raw byte
pipe).

## Configuration

```yaml
listeners:
  - name: tls-lb
    address: 0.0.0.0
    port: 8443
    protocol: tcp
    l4:
      sni_routing: true
      upstream: backend-fallback
      idle_timeout_s: 300
    tls:
      sni_routes:
        - sni: app.example.com
          upstream: app-svc
        - sni: api.example.com
          upstream: api-svc
```

The `l4` block is valid only on `protocol: tcp` and `protocol: udp`
listeners; validation rejects it on other protocols. `upstream` is
required when `sni_routing` is false; when `sni_routing` is true it is
the fallback for no-SNI / unmatched names (absent = close).
`idle_timeout_s` bounds an established splice (at most 1 hour; absent or
0 means no idle timeout). The entire module is behind `#[cfg(feature =
"l4")]`; the config schema is always present so configs round-trip
without the feature, and validation warns that the listener is inert
when the feature is off.

The [TLS](./tls.md) page covers the SNI passthrough path whose
extraction this feature reuses; the [dataplane and
proxy](./dataplane-proxy.md) page covers the HTTP pipeline this
listener type bypasses.
