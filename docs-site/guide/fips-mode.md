# FIPS mode

Dwara can be built in [FIPS 140-3](https://en.wikipedia.org/wiki/FIPS_140)
mode, restricting the gateway's cryptographic primitives to the set
approved by the NIST Cryptographic Module Validation Program (CMVP) and
running a startup self-test that attests the module is operating in its
approved configuration. FIPS mode is intended for environments that
require a validated crypto boundary -- US federal workloads, regulated
finance, and any deployment whose compliance posture mandates a
FIPS-validated module.

## When to use this

Enable FIPS mode when your compliance regime requires a FIPS-validated
cryptographic module. In FIPS mode the gateway refuses to use
non-approved algorithms (non-approved cipher suites, Ed25519 signatures
outside the approved boundary, ChaCha20-Poly1305, and the DRBG entropy
sources that are not on the approved list). If your traffic does not
require a FIPS attestation, leave FIPS off -- the default build uses a
broader, modern cipher set that is faster and more widely interoperable.

## Enabling

FIPS mode is gated behind the `fips` cargo feature (default OFF). The
feature swaps the crypto provider for a FIPS-validated backend and
enables the startup self-test:

```sh
cargo build -p dwara-bin --features fips
```

In a default build the feature is absent and the gateway uses the
standard crypto provider with no self-test. The `fips` feature is
mutually exclusive with the `pq` feature -- post-quantum key exchange is
not yet part of the FIPS-approved boundary.

## Configuration

FIPS mode is a build-time property, not a runtime toggle. Once the
binary is built with `--features fips`, the approved-only cipher
restrictions and self-test apply to every listener and upstream
unconditionally. There is no per-route or per-upstream FIPS setting.

The startup self-test runs before the gateway binds any listener. On
success it logs a single attestation line and proceeds; on failure the
gateway refuses to start and exits non-zero. The self-test covers the
approved cipher suite list, the DRBG health check, and the integrity
check of the module boundary.

## Approved cipher restrictions

In FIPS mode the TLS cipher suite list is restricted to the FIPS-approved
set, including:

- TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`.
- TLS 1.2: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
  `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`,
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.

Non-approved suites (ChaCha20-Poly1305, CBC-mode suites, NULL cipher
suites) are not offered. The minimum TLS version is 1.2; TLS 1.0 and 1.1
are disabled. RSA key transport (non-forward-secret) suites are disabled.
Ed25519 is not used for certificate signatures within the validated
boundary.

## Compliance posture

::: info Status
The `fips` feature wires the gateway to a FIPS-validated crypto provider
and enforces the approved-only cipher list and startup self-test. The
FIPS 140-3 validation certificate itself is a property of the underlying
crypto module, not the gateway binary -- a deployment that needs a
formal FIPS attestation must run the gateway on a platform whose crypto
module has a current CMVP certificate and must operate within the
module's approved operating environment. The gateway's self-test
confirms the module is in its approved mode; it does not itself
constitute the validation. Consult your security team and the crypto
module's security policy before claiming a FIPS compliance posture.
:::
