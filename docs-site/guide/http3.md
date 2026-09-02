# HTTP/3 ingress

Dwara supports HTTP/3 (h3 over [QUIC](https://en.wikipedia.org/wiki/QUIC))
as a first-class listener protocol alongside HTTP/1.1 and HTTP/2. An h3
listener uses the same routing, config, and policy chain as the other
listener protocols -- routes, transforms, rate limits, authn/authz,
analytics, and the AI gateway all work unchanged over h3.

## When to use this

Use an h3 listener when clients benefit from QUIC's multiplexing without
head-of-line blocking and faster connection establishment (0-RTT). Browsers
and modern HTTP clients negotiate h3 automatically via the `Alt-Svc` header
advertised by an h1/h2 listener, so you can add h3 alongside existing
listeners without forcing clients to switch.

## Enabling

HTTP/3 is feature-gated behind the `h3` cargo feature because it brings
in the `quinn` (QUIC) and `h3` crates, which add to the binary size. The
feature is default OFF.

```sh
cargo build -p dwara-bin --features h3
```

In a default build the `h3` feature is absent and an h3 listener config
block is accepted but inert -- the listener does not bind.

## Configuration

Add a listener with `protocol: h3`. The h3 listener runs alongside your
h1/h2 listeners; clients negotiate via `Alt-Svc` (advertised by an h1/h2
listener) or connect directly to the h3 port.

```yaml
listeners:
  - name: h1-listener
    bind: 0.0.0.0:8443
    protocol: h2
    tls:
      cert_file: /etc/dwara/tls.crt.pem
      key_file: /etc/dwara/tls.key.pem
    alt_svc:
      - protocol: h3
        port: 8444

  - name: h3-listener
    bind: 0.0.0.0:8444
    protocol: h3
    tls:
      cert_file: /etc/dwara/tls.crt.pem
      key_file: /etc/dwara/tls.key.pem
```

The h3 listener requires TLS (QUIC mandates encryption); the same
certificate and key files used for h1/h2 termination work here. Routing,
policy, and analytics are shared across all listeners -- a route matched
on an h1 listener matches the same request on an h3 listener.

## Notes

- The `h3` feature pulls in the `quinn` and `h3` crates, which increase
  the binary size. That is why the feature is default OFF -- enable it
  only in builds that serve h3 traffic.
- An h3 listener cannot fall back to cleartext; QUIC is always
  encrypted, so the `tls` block is required.
