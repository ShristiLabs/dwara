# Vault/KMS SecretSource (DW-069, Enterprise)

## Overview

dwara Enterprise supports Vault KV v2 and KMS-backed secret sources.
This implements `SecretSource` (section 11.3) alongside DW-045's OSS
file/env implementation, behind the same trait.

Resolved values must never be logged or echoed back -- including via
the admin API -- per section 13.3's blanket secret-redaction
requirement; a resolved Vault/KMS value gets the same redaction
treatment as an inline config secret.

## Enabling

Build with the `ent` feature:

```sh
cargo build --features ent
```

## API

### VaultSecretSource

A `SecretSource` that reads from Vault's KV v2 engine with a
configurable cache TTL for rotation without restart:

```rust
use dwara_core::extensions::vault_secrets::VaultSecretSource;
use std::time::Duration;

let source = VaultSecretSource::new(
    "https://vault.example.com:8200",
    "s.token",
    Duration::from_secs(300),
);
```

The `name` passed to `resolve` is interpreted as `<mount>/<path>`
(e.g. `secret/data/my-app/db`).

### KmsSecretSource

A `SecretSource` that decrypts ciphertext via a pluggable `KmsProvider`
trait:

```rust
use dwara_core::extensions::vault_secrets::{KmsSecretSource, MockKmsProvider};

let provider = MockKmsProvider::passthrough();
let source = KmsSecretSource::new(Box::new(provider));
```

The `name` passed to `resolve` is interpreted as
`<key_id>:<ciphertext>`.

### KmsProvider trait

For AWS KMS, GCP KMS, Azure Key Vault, etc. implementations:

```rust
use dwara_core::extensions::vault_secrets::KmsProvider;
use dwara_core::extensions::ExtensionsError;

#[async_trait]
impl KmsProvider for MyAwsKmsProvider {
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8])
        -> Result<String, ExtensionsError>
    {
        // Call AWS KMS Decrypt API...
    }
}
```

### LeaseManager

Tracks active leases for dynamic secrets and renews them:

```rust
use dwara_core::extensions::vault_secrets::{LeaseManager, Lease};

let mgr = LeaseManager::new();
mgr.register("db-creds", Lease {
    lease_id: "lease-123".to_string(),
    lease_duration: 3600,
    renewable: true,
});

// Get leases needing renewal.
let needing = mgr.leases_needing_renewal(200);

// Renew a lease.
mgr.renew("db-creds").await?;
```

## Secret redaction

Resolved values are wrapped in `Secret` (redacted Debug, no Display).
The source itself never logs resolved values. The `Secret` type's
`Debug` implementation shows only the byte count, never the value:

```
Secret([16 bytes redacted])
```

## Rotation without restart

The `VaultSecretSource` caches resolved secrets with a configurable
TTL. When the TTL expires, the next `resolve` call re-reads from
Vault, allowing rotation without restart:

```rust
let source = VaultSecretSource::new(
    "https://vault.example.com:8200",
    "s.token",
    Duration::from_secs(300), // 5-minute cache TTL
);
```

## Lease renewal

Dynamic secrets (e.g. database credentials, AWS STS tokens) have
leases that must be renewed periodically. The `LeaseManager` tracks
active leases and provides a `renew` method (placeholder: in a real
implementation, this would call Vault's lease-renew API).

## Feature gate

The `ent` cargo feature must be enabled. Without it, the module is
not compiled and the gateway uses the OSS file/env secret sources.
