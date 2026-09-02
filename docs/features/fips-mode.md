# FIPS 140-3 mode (DW-111)

> Implements issue DW-111 (Enterprise, flag-only behind the `fips`
> cargo feature). Sources: `crates/dwara-core/src/security/fips.rs`
> (`FipsMode`, `FipsAttestation`, `fips_self_test`,
> `is_primitive_allowed`, `is_cipher_suite_disallowed`,
> `is_signature_disallowed`, `is_credential_hash_disallowed`,
> `install_fips_provider`, `health_attestation`,
> `FIPS_ALLOWED_CIPHERS`, `FIPS_ALLOWED_SIGNATURES`,
> `FIPS_ALLOWED_CREDENTIAL_HASHES`), validation rules in
> `snapshot/mod.rs`. Tests: `crates/dwara-core/tests/fips.rs` (the
> self-test passes with the feature on, the attestation is
> JSON-serializable, the cipher allowlist excludes ChaCha20-Poly1305,
> the signature denylist excludes Ed25519, the credential-hash
> denylist excludes Argon2, the health attestation returns `Some` when
> enabled). Operator docs:
> [enterprise guide](../../docs-site/guide/enterprise.md) and
> [security guide](../../docs-site/guide/security.md).

When the `fips` cargo feature is compiled in, the gateway operates in
FIPS 140-3 mode: the rustls process-default crypto provider is the
FIPS-validated aws-lc-rs provider, TLS cipher suites are restricted to
the FIPS-approved allowlist, non-approved primitives (Ed25519
certificates, Argon2 credential hashing) are rejected at config
validation, and a startup self-test verifies the provider before the
gateway accepts traffic.

aws-lc-rs is already the default rustls crypto provider in every build
(see `security::tls::install_aws_lc_rs_provider`), so the FIPS-
validated code path is present regardless of this feature. The `fips`
feature is a FLAG: it turns ON the enforcement layer (provider
self-test, cipher-suite restriction, primitive allowlist, license
assertion) without adding any new dependency.

## The fips cargo feature

The feature compiles in OSS builds, but it is only MEANINGFUL with the
`ent` cargo feature: license-gated enforcement needs the licensing
gate, which is an ent-only subsystem. An OSS build with `fips` alone
still installs the FIPS provider and runs the self-test, but the
license assertion is inert.

When the `fips` feature is OFF, every function in the module is inert:
`FipsMode` is `Disabled`, the self-test returns a `Disabled`
attestation, and `is_primitive_allowed` always returns `true`. The
config schema is always present so configs round-trip without the
feature.

`FipsMode::current()` is a compile-time constant: the feature is a
build-time switch, not a runtime toggle. `install_fips_provider`
installs the aws-lc-rs default provider as the process-default crypto
provider (idempotent -- the same call as
`install_aws_lc_rs_provider`).

## The startup self-test

`fips_self_test` verifies that the process-default rustls crypto
provider is installed and returns a `FipsAttestation` capturing the
provider name, version, self-test result, and timestamp. The self-test
SUCCEEDS when a process-default crypto provider is installed (the
caller, dwara-bin, installs the provider BEFORE calling this). The
function is idempotent and safe to call from tests.

The binary runs this at startup and refuses to boot (exit 1) if the
self-test fails. The attestation is surfaced on the `/healthz`
endpoint (`health_attestation`) so orchestrators can confirm FIPS mode
is active. When the `fips` feature is OFF, `health_attestation`
returns `None` (the `fips` field is omitted from the health response).

`FipsAttestation` serializes to JSON via serde: `{ enabled, provider,
provider_version, self_test_passed, timestamp }`. The `Disabled`
variant carries an inert attestation (`enabled: false`,
`self_test_passed: false`, `timestamp: 0`).

## The primitive allowlist

Three allowlists govern which primitives are approved under FIPS mode:

- **`FIPS_ALLOWED_CIPHERS`** -- the FIPS-approved TLS cipher suites
  (IANA names, lowercase). TLS 1.3 AEAD suites
  (`tls13_aes_256_gcm_sha384`, `tls13_aes_128_gcm_sha256`) and TLS 1.2
  ECDHE AES-GCM suites (ECDSA and RSA key exchange). ChaCha20-Poly1305
  is NOT FIPS-approved and is excluded.
- **`FIPS_ALLOWED_SIGNATURES`** -- the FIPS-approved TLS signature
  schemes. RSA-PSS (SHA-256/384/512), RSA-PKCS1 (SHA-256/384, TLS 1.2
  fallback), ECDSA P-256 and P-384. Ed25519 is NOT on the
  FIPS-validated list for aws-lc-rs and is excluded.
- **`FIPS_ALLOWED_CREDENTIAL_HASHES`** -- the FIPS-approved credential
  hash formats: `sha256` and `hmac-sha256` (the fast-path formats).
  Argon2 is NOT FIPS-approved and is excluded.

`is_primitive_allowed` checks a primitive name against all three
allowlists (case-insensitive). A primitive that matches any allowlist
is allowed. A primitive that does not match any allowlist is allowed
UNLESS it is a known-non-approved primitive (the explicit denylist:
`ed25519`, `tls_chacha20_poly1305_sha256`, `chacha20-poly1305`,
`argon2`, `argon2id`). Unknown primitives are allowed -- the FIPS
restriction targets specific known-non-approved primitives, not a
blanket deny-by-default.

## Validation rules

Snapshot validation calls the disallowed-primitive checks to reject
non-approved configs at publish time:

- **`is_cipher_suite_disallowed`** -- true when FIPS mode is active and
  the cipher suite is NOT on the allowlist (e.g. ChaCha20-Poly1305).
- **`is_signature_disallowed`** -- true when FIPS mode is active and
  the signature scheme is NOT on the allowlist (e.g. Ed25519).
- **`is_credential_hash_disallowed`** -- true when FIPS mode is active
  and the credential hash format prefix (the part before the
  colon, e.g. `sha256`, `hmac-sha256`, `argon2id`) is NOT on the
  allowlist. Used to reject Argon2 credential hashing.

When the `fips` feature is OFF, all three functions always return
`false` (no rejection) -- the validation rules are inert.

## Configuration

FIPS mode is a compile-time switch (the `fips` cargo feature), not a
runtime config field. There is no `fips` block in the gateway config:
the mode is determined by the build. Enforcement is automatic when the
feature is on -- validation rejects non-approved primitives for the
operator.

The `/healthz` endpoint surfaces the attestation when FIPS mode is
enabled, so orchestrators can verify the gateway booted in FIPS mode:

```json
{
  "fips": {
    "enabled": true,
    "provider": "aws-lc-rs",
    "provider_version": "",
    "self_test_passed": true,
    "timestamp": 1700000000
  }
}
```

Build with FIPS mode (Enterprise):

```sh
cargo build --features fips,ent
```

The [TLS](./tls.md) page covers the rustls provider installation and
the shared client/server config; the [authn-authz](./authn-authz.md)
page covers the credential hash formats the allowlist governs.
