# TLS

Source: `crates/dwara-core/src/security/tls.rs` (DW-007). Tests:
`tls_validation`, `trusted_ca` (dwara-core), `tls_listener`, `tls_edges`
(dwara-bin).

## Responsibilities

One module owns everything TLS-shaped in the gateway:

- installing the process-global crypto provider (aws-lc-rs) before the
  first `rustls` object is constructed,
- building a hot-reloadable `rustls::ServerConfig` for a terminate
  listener, with SNI-based certificate selection,
- outbound trust for HTTPS dials (upstreams, JWKS fetches, active
  health probes) — the default webpki public root set, or a per-entity
  PEM-bundle root store,
- the minimal ClientHello SNI parser and byte-splice that back TLS
  passthrough.

## Terminate: multi-SNI

A terminate listener carries a fallback `cert_file`/`key_file` pair
plus an optional `certificates` list, each entry matched by SNI:

```yaml
listeners:
  - name: https
    port: 8443
    tls:
      mode: terminate
      cert_file: /etc/dwara/certs/default.crt.pem
      key_file: /etc/dwara/certs/default.key.pem
      certificates:
        - server_name: api.example.com
          cert_file: /etc/dwara/certs/api.crt.pem
          key_file: /etc/dwara/certs/api.key.pem
```

**Why SNI dispatch instead of one cert per listener:** a single bind
address is a scarce resource (ports, and often a single public IP);
hosting multiple TLS-terminated domains behind it without SNI would
mean one listener (and one config block) per certificate. TLS 1.2 and
1.3 are both enabled at rustls's default (modern) cipher-suite policy —
v1 does not expose cipher/version override knobs.

## Passthrough

A passthrough listener never decrypts the connection. It:

1. Peeks (never consumes) bytes from the socket, reassembling a
   ClientHello that may be fragmented across multiple TLS records, up
   to `MAX_HELLO_BYTES` (64 KiB) — a bound chosen so a hostile client
   can't pin unbounded memory building a fake, endlessly-fragmented
   hello.
2. Extracts the SNI value to pick an upstream via the normal load
   balancer.
3. Splices the connection's bytes to the chosen upstream verbatim; the
   upstream performs its own TLS handshake against the original
   client.

```mermaid
sequenceDiagram
    participant C as Client
    participant L as dwara listener
    participant U as Upstream

    C->>L: TCP connect
    C->>L: ClientHello (may span several TLS records)
    L->>L: peek + reassemble, extract SNI (bytes not consumed)
    L->>L: pick upstream via SNI + load balancer
    L->>U: TCP connect
    L->>C: splice bytes verbatim (both directions)
    Note over C,U: dwara never sees plaintext;\nupstream terminates TLS itself
```

**Why passthrough exists at all** (rather than "always terminate and
re-encrypt"): some deployments need the upstream to see the original,
unmodified TLS session — its own certificate presented to the client,
client-cert mTLS negotiated directly with the origin, or compliance
requirements that the gateway never hold key material for that domain.
Passthrough listeners never serve `/healthz`/`/readyz`/`/metrics` (they
don't speak HTTP at all — see [Operations](../../docs-site/guide/operations.md)).

## Hot reload

`TlsTermination` keeps the current `Arc<rustls::ServerConfig>` behind
an `ArcSwap`. Each accepted connection clones the *current* `Arc` into
a fresh `TlsAcceptor`, so a swap only affects handshakes that start
after it — in-flight TLS sessions keep their negotiated configuration,
and no existing connection is ever dropped by a certificate rotation.
This is the same swap-not-mutate pattern the config `Snapshot` uses
(see [Architecture](../architecture.md#hot-reload)), applied one level
down to just the TLS material.

## Outbound trust (per-entity, #121)

By default, outbound HTTPS dials (to upstreams, JWKS providers, and
their active health probes) trust the Mozilla webpki public root set
compiled into the binary — no CA bundle ships with the image. When an
upstream or JWT provider configures `trusted_ca_file`, that PEM bundle
**replaces** the public roots for that entity only; it does not add to
them. Rationale: additive trust would mean any deployment that adds one
private CA also implicitly trusts every public CA for that entity,
which is a broader trust grant than most private-CA deployments intend
(they typically want to say "only my CA," not "my CA plus the whole
public web").

- Validation-time: `check_trusted_ca_file` (in `snapshot/mod.rs`)
  parses the bundle at config-validate time and rejects a missing,
  unreadable, or certificate-free file, naming the offending field —
  so a broken trust bundle fails a `dwara-cli validate` or a `PATCH
  /config` dry run, not a live request.
- Runtime fail-closed: the empty-root-store-plus-ERROR-log path (for an
  upstream) or provider-disabled path (for a JWT provider) exists only
  as a backstop for the microsecond validate-vs-build race — it is
  never a silent fallback to the public roots.
- Active HTTPS health probes inherit their upstream's trust roots (kept
  on the upstream handle), so a probe against a private-CA upstream
  doesn't independently need its own trust configuration.
- Bundle files are **not** file-watched (only the main config file and
  listener terminate cert/key files are) — rotating a trust bundle
  needs a `SIGHUP` or a config change to take effect.

## Testing notes

TLS behavior is covered process-level: `tls_listener`/`tls_edges` spawn
the real `dwara` binary and drive real TLS handshakes (multi-SNI
selection, passthrough splicing, hot-reload-without-drop);
`tls_validation`/`trusted_ca` exercise the validate-time PEM checks
directly against `dwara-core`.
