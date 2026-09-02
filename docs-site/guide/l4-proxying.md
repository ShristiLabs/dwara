# L4 TCP/UDP proxying

Dwara can proxy raw TCP and UDP at layer 4, below HTTP, on the same binary
that serves its HTTP listeners. An L4 listener terminates TLS (or passes it
through untouched) and forwards bytes to an upstream without inspecting the
application protocol -- useful for protocols the gateway does not speak as
HTTP, for TLS passthrough where the gateway must not see the certificate, and
for SNI-based routing of TLS without termination.

## When to use this

Use an L4 listener when the traffic is not HTTP -- a database connection, an
SMTP relay, a custom binary protocol -- or when you want to route TLS by SNI
without terminating it (the gateway reads the ClientHello SNI, picks an
upstream, and splices the bytes through, never seeing the private key). For
HTTP traffic, prefer an HTTP listener: it gets routing, transforms, authn,
rate limits, and analytics that an L4 listener cannot apply because it does
not parse the application layer.

## Configuration

Add a listener with `protocol: tcp` or `protocol: udp`. An L4 listener takes
a `l4` block with the routing mode and upstream(s).

```yaml
listeners:
  - name: db-tcp
    bind: 0.0.0.0:5432
    protocol: tcp
    l4:
      mode: passthrough
      upstreams:
        - address: db-1.internal:5432
          weight: 1
        - address: db-2.internal:5432
          weight: 1
```

## SNI routing

For TLS traffic, `mode: sni` reads the ClientHello SNI (the server name the
client asks for in the TLS handshake) without terminating TLS, then routes
the connection to an upstream chosen by the SNI value. The gateway never
holds the private key -- it splices the TCP stream after reading the SNI.

```yaml
listeners:
  - name: tls-sni
    bind: 0.0.0.0:443
    protocol: tcp
    l4:
      mode: sni
      sni_routes:
        - sni: api.example.com
          upstream: api-svc.internal:443
        - sni: legacy.example.com
          upstream: legacy-svc.internal:443
      default_upstream: catchall-svc.internal:443
```

A ClientHello with no SNI, or an SNI not in `sni_routes`, goes to
`default_upstream`. Omit `default_upstream` to reject unmatched SNI with a
TCP close. SNI routing preserves the client's TLS session end-to-end -- the
upstream terminates TLS, not the gateway.

## TCP passthrough and termination

`mode: passthrough` forwards bytes to the configured upstreams with
load balancing across the pool (round-robin by default; the same balancer
modes as HTTP upstreams apply). `mode: terminate` terminates TLS at the
gateway using a `tls` block on the listener, then forwards cleartext to the
upstream -- useful when the upstream cannot speak TLS but the client must.

```yaml
listeners:
  - name: tls-terminate
    bind: 0.0.0.0:9443
    protocol: tcp
    tls:
      cert_file: /etc/dwara/tls.crt.pem
      key_file: /etc/dwara/tls.key.pem
    l4:
      mode: terminate
      upstreams:
        - address: backend.internal:8080
```

## UDP

A `protocol: udp` listener forwards datagrams. UDP has no connection state,
so load balancing is per-datagram (hash by source address to keep a given
client sticky to one upstream). There is no health check round-trip for UDP
-- an upstream is marked down only by an explicit admin mark or by a
configured send/expect probe if the upstream speaks a probeable protocol.

## L4 vs HTTP proxying

| Concern | L4 listener | HTTP listener |
| --- | --- | --- |
| Protocols | any TCP/UDP, TLS passthrough | HTTP/1.1, h2, h3, gRPC, WebSocket |
| Routing | by SNI (TLS) or upstream pool only | by path, header, query, method, weight |
| Policies | none at the application layer | authn, authz, rate limit, transforms, quotas |
| TLS | terminate or passthrough | terminate (multi-SNI) |
| Analytics | bytes, connections, upstream | full request-level analytics |

Pick the HTTP listener when you need the policy chain; pick L4 when the
traffic is not HTTP or when SNI passthrough is a hard requirement.

## Observability

L4 listeners surface in [`/metrics`](./observability) as
`dwara_l4_connections_total{listener,mode,outcome}` and
`dwara_l4_bytes_total{listener,direction}`. There is no per-request access
log -- L4 has no requests, only connections and bytes -- but connection
teardowns record the upstream, the byte count, and the close reason (clean,
upstream reset, idle timeout).
