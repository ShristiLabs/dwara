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

HTTP/3 is compiled into every build — there is no `h3` cargo feature to
enable. The `quinn` (QUIC) and `h3` crates are unconditional
dependencies (they add to the binary size, which is the trade the
default build makes):

```sh
cargo build -p dwara-bin
```

An h3 listener binds and serves as soon as it appears in the config.

## Configuration

Add a listener with `protocol: h3`. The h3 listener runs alongside your
h1/h2 listeners; clients negotiate via `Alt-Svc` (a string on the h1/h2
listener, e.g. `h3=":8444"; ma=86400`) or connect directly to the h3
port.

```yaml
listeners:
  - name: h1-listener
    address: 0.0.0.0
    port: 8443
    protocol: https
    tls:
      cert_file: /etc/dwara/tls.crt.pem
      key_file: /etc/dwara/tls.key.pem
    alt_svc: h3=":8444"; ma=86400

  - name: h3-listener
    address: 0.0.0.0
    port: 8444
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

- The `quinn` and `h3` crates increase the binary size; they are
  compiled in unconditionally.
- An h3 listener cannot fall back to cleartext; QUIC is always
  encrypted, so the `tls` block is required.

## Runnable demo

Run this feature against a live gateway: [`demos/10-tls-transport/`](https://github.com/shristilabs/dwara/tree/main/demos/10-tls-transport) (test
script: `test-07-http3.sh`) in the repository.
The category README covers prerequisites and teardown.
