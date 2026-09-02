# HTTP/3 upstream transport

Dwara can connect to an upstream over [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3)
(h3 over [QUIC](https://en.wikipedia.org/wiki/QUIC)) -- the same protocol
it can serve on the ingress side, but used here for the gateway-to-upstream
hop. An h3 upstream uses QUIC's multiplexed streams without head-of-line
blocking and benefits from QUIC's faster connection establishment and
connection migration, while the gateway's listener side can still serve
clients over HTTP/1.1, HTTP/2, or HTTP/3 independently.

## When to use this

Use an h3 upstream when the upstream itself speaks HTTP/3 and you want
the gateway-to-upstream hop to gain QUIC's properties:

- Multiplexed concurrent requests without head-of-line blocking, so a
  slow response on one stream does not stall the others sharing the
  connection.
- Lower connection-establishment latency (1-RTT, or 0-RTT on resumption),
  useful when the gateway opens short-lived connections to the upstream.
- Connection migration -- the QUIC connection survives a NAT rebinding or
  a gateway failover that changes the source IP, avoiding a reconnect.

If the upstream only speaks HTTP/1.1 or HTTP/2, use `protocol: http1` or
`protocol: http2` instead. h3 is not a faster choice for a single
request/response; it pays off when the gateway reuses one QUIC connection
for many concurrent streams to the same upstream.

## Enabling

The h3 upstream transport shares the `h3` cargo feature with HTTP/3
ingress (default OFF), because both pull in the `quinn` (QUIC) and `h3`
crates:

```sh
cargo build -p dwara-bin --features h3
```

In a default build the feature is absent and `upstream.protocol: h3` is
accepted but inert -- the upstream connects over HTTP/1.1 instead.

## Configuration

Set the upstream's `protocol` to `h3`:

```yaml
upstreams:
  - name: h3-backend
    endpoints:
      - address: 10.0.0.7
        port: 8443
    protocol: h3
    tls:
      cert_file: /etc/dwara/upstream-ca.pem
```

QUIC mandates TLS 1.3, so the upstream connection is always encrypted --
there is no cleartext h3 equivalent of h2c. The `tls` block supplies the
CA used to validate the upstream's certificate. The same certificate
trust model as an `https`/`http2` upstream applies; only the transport
differs.

## How it differs from HTTP/3 ingress

HTTP/3 ingress (a listener with `protocol: h3`) and an h3 upstream are
independent:

- **Ingress h3** is about how clients connect to the gateway. Clients
  negotiate it via `Alt-Svc` advertised by an h1/h2 listener or connect
  directly to the h3 port. See [HTTP/3 ingress](./http3).
- **Upstream h3** is about how the gateway connects to backends. The
  gateway can serve HTTP/1.1 clients on the front and proxy to an h3
  backend on the rear, or serve h3 on the front and proxy to an h2
  backend on the rear -- the two sides are decoupled.

A request flows: client -> (ingress protocol) -> gateway -> (upstream
protocol) -> backend. The ingress and upstream protocols are chosen
separately per listener and per upstream.

## Notes

- The `h3` feature pulls in the `quinn` and `h3` crates, increasing the
  binary size. That is why the feature is default OFF -- enable it only
  in builds that serve or proxy h3 traffic.
- An h3 upstream cannot fall back to cleartext; QUIC is always
  encrypted, so the `tls` block is required.
- Connection pooling for h3 upstreams reuses a single QUIC connection
  across many concurrent request streams. The pool settings
  (`max_connections_per_host`, idle timeout) apply to QUIC connections
  the same way they apply to TCP connections for h1/h2 upstreams.
