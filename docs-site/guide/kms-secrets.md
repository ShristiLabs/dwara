# KMS secrets

The KMS secret source uses envelope encryption: secrets are stored
encrypted in the config (or a file), and the KMS provider decrypts
them at request time. This keeps secrets encrypted at rest while
avoiding a live dependency on a secret server.

KMS is one of two external secret sources -- the other,
[Vault secrets](./vault-secrets), reads secrets from HashiCorp
Vault's key-value store. Both providers plug into the same
reference-resolution model as the built-in file source; see
[Secrets](./secrets) for how secret references are written and
resolved.

## When to use this

Use external secret sources when:

- Secrets must not be stored in the config file (even hashed).
- Secrets are rotated frequently and you don't want to reload config
  on each rotation.
- You have a central secret management system (Vault, AWS KMS, GCP
  KMS, etc.) that is the source of truth.

This is an enterprise feature (see [Enterprise](./enterprise)) --
build with the `ent` feature:

```sh
cargo build --features ent
```

## Configuration

```yaml
secret_sources:
  - type: kms
    provider: aws-kms
    key_id: alias/dwara-secrets
```

| Field | Default | Description |
|---|---|---|
| `provider` | (required) | KMS provider (`aws-kms`, `gcp-kms`, `azure-kv`, or `mock` for testing). |
| `key_id` | (required) | The KMS key ID or alias. |

## How it works

KMS secrets are referenced as `key_id:ciphertext`:

```yaml
listeners:
  - bind: 0.0.0.0:8443
    tls:
      cert_file: /etc/dwara/cert.pem
      key_file: kms:alias/dwara-secrets:base64-encoded-ciphertext
```

The gateway decrypts the ciphertext using the named KMS key and uses
the plaintext as the secret value. See [Secrets](./secrets) for the
general reference-resolution model, and [Vault secrets](./vault-secrets)
for the live secret-server alternative.

### Mock provider

For testing, use the `mock` provider with a configurable decrypt
function:

```yaml
secret_sources:
  - type: kms
    provider: mock
```

The mock provider returns the ciphertext as-is (no actual
decryption). This is useful for integration tests.

## Fail-closed behavior

Vault and KMS secret sources fail closed: if a secret cannot be
resolved (Vault is down, KMS is unreachable, decryption fails), the
gateway does not start (or does not reload, for a live config
change). A misconfigured secret never silently falls back to an
empty or default value.

## Interaction with the file secret source

The built-in file secret source (reading secrets from files on disk,
e.g. for Docker/Kubernetes secrets) is always available. External
secret sources complement it -- you can mix file and Vault/KMS
secrets in the same config.
