# Post-quantum TLS

Dwara can negotiate a [hybrid post-quantum key exchange](https://en.wikipedia.org/wiki/Post-quantum_cryptography)
on its TLS connections, combining the classical [X25519](https://en.wikipedia.org/wiki/Curve25519)
ECDH curve with [ML-KEM](https://en.wikipedia.org/wiki/Module-Lattice-based_Key_Encapsulation_Mechanism)
(formerly Kyber, the NIST FIPS 203 lattice-based key-encapsulation mechanism).
The hybrid shares are combined so that the connection is secure as long as
EITHER the classical assumption OR the lattice assumption holds -- a future
quantum adversary that breaks ECDH still cannot recover the session key
unless ML-KEM is also broken, and a flaw in the new lattice scheme does not
weaken today's classical security.

## When to use this

Enable post-quantum TLS when you need to protect long-lived traffic against
harvest-now-decrypt-later attacks -- an adversary recording ciphertext today
to decrypt it once a cryptographically relevant quantum computer exists.
This matters for data with a confidentiality horizon of a decade or more
(government, healthcare, long-lived secrets in transit). For short-lived
or low-sensitivity traffic the classical handshake is sufficient and the
hybrid adds handshake bytes and CPU cost for no practical benefit.

## Enabling

Post-quantum key exchange is gated behind the experimental `pq` cargo
feature (default OFF). The feature pulls in the ML-KEM implementation and
adds the hybrid group to the TLS handshake:

```sh
cargo build -p dwara-bin --features pq
```

In a default build the feature is absent and `upstream.pq: true` is
accepted but inert -- the upstream connects with the standard classical
key exchange only.

## Configuration

Enable the hybrid exchange per upstream:

```yaml
upstreams:
  - name: sensitive-api
    endpoints:
      - address: 10.0.0.5
        port: 8443
    protocol: https
    pq: true
    trusted_ca_file: /etc/dwara/upstream-ca.pem
```

When `pq: true`, the gateway advertises the X25519+ML-KEM hybrid group in
the TLS ClientHello. If the upstream supports the hybrid group, the
handshake completes with a combined shared secret. If the upstream does
not support it, the gateway falls back to X25519 alone -- the connection
still succeeds, just without the post-quantum component. This makes the
flag safe to enable ahead of upstream support.

## Security considerations

- The hybrid is NOT a substitute for classical TLS hygiene. Certificate
  validation, SNI, and the trust store behave exactly as in a classical
  handshake; `pq` only changes the key-exchange group.
- ML-KEM is a key-encapsulation mechanism, not a signature scheme. The
  certificate signature remains classical (RSA/ECDSA/Ed25519) until
  post-quantum signatures are standardized and deployed widely. A quantum
  adversary could still forge certificates in a recorded handshake -- the
  hybrid protects the session key, not the authentication.
- The hybrid group adds roughly 1 KB to the ClientHello and a comparable
  amount to the ServerHello. This is negligible on modern links but
  visible on constrained or high-latency paths.
- The `pq` flag is per-upstream, not per-listener. Inbound (listener-side)
  post-quantum termination is not yet exposed; the feature today protects
  the gateway-to-upstream hop.

## Experimental status

::: warning Experimental
The `pq` feature is experimental. The ML-KEM implementation tracks the
finalized FIPS 203 standard, but the hybrid group identifier and
negotiation behavior are subject to change as the IETF
`tls-hybrid-design` draft matures. Do not rely on this for a compliance
attestation yet. The feature may be revised or removed in a future
release without a deprecation cycle. Enable it for evaluation and
harvest-now-decrypt-later hardening, not as a substitute for a validated
post-quantum TLS product.
:::
