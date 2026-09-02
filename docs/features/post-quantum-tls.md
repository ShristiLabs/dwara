# Post-quantum TLS: X25519+ML-KEM hybrid key exchange (DW-105)

> Implements issue DW-105 (M2, `edition/oss`, effort M, experimental).
> Sources: `crates/dwara-core/src/security/pq.rs` (the `PqMode`
> compile-time enum, the `PqHandshakeResult` outcome, the
> `pq_handshake_metric` label, the `install_pq_kx_group` wiring point,
> the `pq_api_available` probe, the `PQ_KX_GROUP_NAME` constant), the
> config schema in `crates/dwara-core/src/config/mod.rs` (the additive
> `pq: bool` field on `ListenerTls` and on the upstream TLS client
> config), validation in `src/snapshot/mod.rs` (the FIPS-incompatibility
> rejection, the passthrough-listener rejection, the inert-feature
> warning), and the rustls provider integration in
> `crates/dwara-core/src/security/tls.rs`. Tests:
> `crates/dwara-core/tests/pq.rs` (the mode enum, the install no-op
> contract, the metric label) behind `#![cfg(feature = "pq")]`, and the
> snapshot-pipeline validation matrix in
> `crates/dwara-core/tests/snapshot_pipeline.rs` (the `pq` field on
> every `ListenerTls` builder). Operator docs: [docs-site security
> guide](../../docs-site/guide/security.md).

Post-quantum TLS prepends the X25519+ML-KEM hybrid key-exchange group
into rustls, behind the experimental `pq` cargo feature. The hybrid
group combines a classical ECDH secret (X25519) with a post-quantum KEM
secret (ML-KEM, formerly Kyber) so that the negotiated session key
remains confidential even if a future quantum adversary can break ECDH.
The classical X25519 share is kept as a fallback, so a client that does
not support the hybrid group still completes a classical handshake --
rustls's kx group list is a preference order, so prepending the hybrid
group PREFERS it without removing the classical fallback.

## Experimental

The rustls API for post-quantum key exchange is EXPERIMENTAL and not
yet stable: the specific kx group type, its registration path, and the
provider integration may change between rustls releases. DW-105 is
therefore structured so the feature gate and config schema EXIST and
COMPILE regardless of whether the experimental PQ API is available in
the pinned rustls version. When the `pq` feature is ON but the
experimental API is not reachable, `install_pq_kx_group` is a
documented no-op: it logs a warning (`pq_kx_group_experimental`) and
returns `PqMode::Disabled`, so the caller treats the config as inert
and the handshake proceeds with the classical kx group list (no
regression -- the default rustls behavior). When the API stabilizes,
the real kx group construction lands in `install_pq_kx_group` without
touching config, validation, or metrics. `pq_api_available` distinguishes
"feature on but API inert" (warn) from "feature off" (warn) for
validation messaging -- today it always returns `false`.

## The kx group installation

`install_pq_kx_group` is the wiring point. When the `pq` cargo feature
is ON and the experimental API is reachable, it will construct the
hybrid group, prepend it to the provider's kx_groups vector, and return
`PqMode::Enabled`. The canonical group name is `X25519MLKEM768`
(`PQ_KX_GROUP_NAME`), used as the `kx_group` label on
`PqHandshakeResult` and in logs. The install is a compile-time switch,
not a runtime toggle (the same shape as `FipsMode`): `PqMode::current()`
returns `Enabled` under `#[cfg(feature = "pq")]` and `Disabled`
otherwise.

## The handshake outcome and metric

`PqHandshakeResult` captures the outcome of a PQ hybrid handshake
attempt for the `dwara_tls_pq_handshakes_total{result}` metric.
`succeeded: true` with `kx_group: "X25519MLKEM768"` records a hybrid
handshake; `succeeded: false` with `kx_group: "X25519"` records a
fallback (the client did not support the hybrid group and a classical
group was negotiated); an empty `kx_group` records the inert case when
PQ is disabled. `pq_handshake_metric` maps a result to the closed
three-value label set `success` / `fallback` / `disabled`.

## Opt-in and the config schema

PQ hybrid key exchange is opt-in per listener and per upstream via the
additive `pq: true` config field. On a listener (`tls.pq`), it is
meaningful only in terminate mode (passthrough does not terminate TLS,
so the kx group list is irrelevant); validation rejects `pq: true` on a
passthrough listener. On an upstream (`tls.pq`), it is meaningful only
for the TLS protocols (`https`, `http2`); validation rejects `pq: true`
on an `http1` upstream (no TLS is negotiated). When the `pq` cargo
feature is OFF, `pq: true` is accepted by the parser (additive-only,
strict serde preserved) but is INERT: no kx group is prepended, and
validation emits a warning issue so the operator knows the build does
not include the PQ feature.

```yaml
listeners:
  - name: https-pq
    address: 0.0.0.0
    port: 443
    protocol: https
    tls:
      mode: terminate
      cert_file: /etc/certs/cert.pem
      key_file: /etc/certs/key.pem
      pq: true
```

## Security considerations

- **Hybrid, not PQ-only.** The classical X25519 share is always
  present. A break of ML-KEM still leaves the X25519 secret protecting
  the session; a break of ECDH by a future quantum adversary still
  leaves the ML-KEM secret protecting it. The hybrid is defense in
  depth, not a bet on one algorithm.
- **FIPS incompatibility.** ML-KEM is NOT on the FIPS-validated list
  for aws-lc-rs. Combining PQ hybrid key exchange with FIPS mode (`fips`
  cargo feature) is REJECTED at config validation: a listener or
  upstream with `pq: true` while FIPS mode is active fails validation
  naming the field. The two features must not combine unless both
  algorithms are on a validated list (a future NIST FIPS 203 module
  path would lift this).
- **No protocol change.** The hybrid group is a TLS 1.3 key-exchange
  group; the rest of the handshake (certificate chain, cipher suite,
  transcript) is unchanged. A client that does not advertise the hybrid
  group negotiates the classical X25519 group with no penalty.
- **Inert until the API stabilizes.** Building with `--features pq` and
  setting `pq: true` today does not activate hybrid key exchange -- it
  logs the experimental warning and uses the classical kx group list.
  The metric records `disabled`. Operators who want the hybrid
  handshake today must verify the rustls version exposes the stable
  API; the feature gate and schema are forward-compatible so no config
  change is needed when the API lands.

The [TLS](./tls.md) page covers the termination and passthrough paths
whose kx group list this feature prepends to; the security guide covers
the FIPS mode whose incompatibility this feature enforces.
