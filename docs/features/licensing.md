# Enterprise licensing gate (DW-032)

The edition boundary as a runtime value: a `LicenseGate` holds an
optional verified license and answers the two questions every
enterprise feature asks before it engages — "are we in enterprise
mode?" and "does this license grant feature X?". OSS builds (the
default, no `ent` cargo feature) compile a stub gate that is always
`none()`: every enterprise feature is inert by construction, and no
`licensing-core` dependency is pulled in.

## Why a gate, not a compile-time flag alone

A cargo feature (`ent`) controls whether the licensing primitives are
linked at all — OSS builds stay clean of the BSL-1.1 `licensing-core`
dependency. But the feature flag alone cannot answer "is THIS
deployment licensed?" — a binary compiled with `ent` still needs to
verify a license file at runtime. The `LicenseGate` is the runtime
half: it holds the verified license (or none) and provides the check
methods every enterprise feature calls.

## The `ent` cargo feature

Declared in `crates/dwara-core/Cargo.toml`:

```toml
[features]
ent = ["dep:licensing-core"]
```

`licensing-core` is an optional dependency (BSL-1.1, allow-listed in
`deny.toml`). The canonical source is the private
`https://github.com/ShristiLabs/licensing.git` repo; a path dependency
is used in local development. The feature is OFF by default — OSS
builds never pull in `licensing-core`.

`dwara-bin` forwards the feature: `ent = ["dwara-core/ent"]`, so the
binary's startup license-verification path compiles in when the feature
is on.

## Verification model

When `ent` is compiled in, `LicenseGate::from_file` reads a license
file, verifies its Ed25519 signature against the product's public key,
and checks expiry. The public key is NEVER user-configurable in the
YAML — it comes from the `DWARA_LICENSE_PUBLIC_KEY` environment variable
(or the compiled-in development key when unset), so an operator cannot
substitute their own key to forge a license. The product ID is pinned
to `"dwara"` so a license issued for another ShristiLabs product cannot
be replayed here.

The license file format is the `licensing-core` claims v2 format: a
flat JSON object with claims (`license_id`, `product_id`, `customer`,
`plan`, `seats`, `instance_id`, `issued_at`, `expires_at`, `features`)
and a `signature` field (base64 Ed25519 signature over the canonical
JSON of the claims).

## Grace period

A license that has passed its `expires_at` timestamp is not immediately
fatal. For a configurable grace window (default 7 days, 0..=30) after
expiry, enterprise features keep working and a warning is logged — the
operator has a buffer to renew. After the grace window the gate
degrades to OSS: `is_enterprise()` returns false and every enterprise
feature falls back to its OSS behavior.

This is the done-when: "Invalid/expired license degrades to OSS feature
set gracefully."

## Startup behavior

The gate is built once at startup (`build_license_gate` in
`dwara-bin/src/main.rs`) from the config's `license` block:

| Condition | Behavior | Metric | Log |
|---|---|---|---|
| No `license` block | OSS mode | 0 | "running in OSS mode (no license configured)" |
| Valid license | Enterprise mode | 1 | "enterprise license verified: customer=..., plan=..., features=..." |
| Expired, within grace | Enterprise mode | 2 | "license expired but within grace period" (warn) |
| Expired, past grace | Degrades to OSS | 3 | "license expired past grace period, degrading to OSS" (warn) |
| Invalid signature | Refuse to start (exit 1) | — | "license signature invalid" (error) |
| File not found | Refuse to start (exit 1) | — | "license file not found" (error) |
| `ent` not compiled in, block present | OSS mode (inert) | 0 | "license block present but the ent cargo feature is not compiled in" |

## Config schema

```yaml
gateway:
  license:
    file: /path/to/license.json
    grace_period_days: 7  # default 7; 0..=30
```

The `license` block is optional. When absent, the gateway runs in OSS
mode. When present, the gateway verifies the license at startup (if
compiled with `ent`). The public key is NOT in the config — it is an
env var (`DWARA_LICENSE_PUBLIC_KEY`) or the compiled-in default, never
user-configurable.

When the `ent` feature is NOT compiled in, the block is accepted but
inert (the gate is always `none()`).

## Feature claim flags

The license's `features` vector carries claim strings. The gate checks
them by exact string match via `has_feature(feature)`. The current
enterprise features and their claim strings:

- `redis_rate_limiter` — DW-031 (not yet implemented; the gate provides
  the check, the feature will call it).
- `config_convergence` — DW-054 (not yet implemented; same).

Pattern for feature gating (in a future ent feature's config
validation):

```rust
if config.gateway.license.is_some() {
    #[cfg(feature = "ent")]
    {
        if !dp.license_gate().is_enterprise() {
            return Err("Redis rate limiter requires an enterprise license");
        }
    }
}
```

## Metrics

- `dwara_license_status` — gauge: 0 = no license (OSS), 1 = valid,
  2 = expired within grace, 3 = expired past grace (degraded to OSS).
  No labels (closed four-value set, one series).

## Key files

- `crates/dwara-core/src/extensions/licensing.rs` — the `LicenseGate`
  struct, `LicenseStatus` enum, `LicenseLoadError`, and the
  `from_file`/`from_file_claims` verification constructors.
- `crates/dwara-core/src/config/mod.rs` — the `LicenseConfig` schema
  struct and the `license` field on `Gateway`.
- `crates/dwara-core/src/config/limits.rs` —
  `DEFAULT_LICENSE_GRACE_PERIOD_DAYS` and
  `MAX_LICENSE_GRACE_PERIOD_DAYS` (in the lowest domain so both
  `extensions::licensing` and `snapshot::validate` can read them
  without an upward import).
- `crates/dwara-core/src/snapshot/mod.rs` — `validate_license` (bounds
  check on `grace_period_days` and non-empty `file`).
- `crates/dwara-bin/src/main.rs` — `build_license_gate` (startup
  verification and logging).
- `crates/dwara-core/src/observability.rs` — the
  `dwara_license_status` gauge and its setter.
- `crates/dwara-core/tests/licensing.rs` — integration tests (OSS mode
  by default, ent-feature-gated tests with `cargo test --features ent`).
