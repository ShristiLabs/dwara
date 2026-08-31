# Vault and KMS secret sources

Dwara can resolve secrets from external secret management systems
at request time, instead of embedding secrets in the config file.
Two providers are supported: HashiCorp Vault and a generic KMS
(key management service) provider for envelope encryption.

## When to use this

Use external secret sources when:

- Secrets must not be stored in the config file (even hashed).
- Secrets are rotated frequently and you don't want to reload config
  on each rotation.
- You have a central secret management system (Vault, AWS KMS, GCP
  KMS, etc.) that is the source of truth.

This is an enterprise feature -- build with the `ent` feature:

```sh
cargo build --features ent
```

## Vault

Configure a Vault secret source to resolve secrets from Vault's
key-value store:

```yaml
secret_sources:
  - type: vault
    url: http://vault:8200
    token: ${VAULT_TOKEN}
    mount: secret
    path_prefix: dwara
```

| Field | Default | Description |
|---|---|---|
| `url` | (required) | Vault server URL. |
| `token` | (required) | Vault auth token (typically from an env var). |
| `mount` | `secret` | The KV mount to read from. |
| `path_prefix` | (none) | Prefix prepended to all secret paths. |

### Referencing Vault secrets

In config fields that accept secret references, use the `vault:`
scheme:

```yaml
listeners:
  - bind: 0.0.0.0:8443
    tls:
      cert_file: /etc/dwara/cert.pem
      key_file: vault:tls/private-key
```

The gateway resolves `vault:tls/private-key` by reading
`secret/data/dwara/tls/private-key` from Vault at startup (and on
reload).

### Lease renewal

Vault secrets are read with a lease. The gateway renews leases
automatically before they expire. If a lease cannot be renewed (e.g.
Vault is down), the gateway continues using the cached secret value
until the lease expires, then fails closed.

## KMS

The KMS provider uses envelope encryption: secrets are stored
encrypted in the config (or a file), and the KMS provider decrypts
them at request time. This keeps secrets encrypted at rest while
avoiding a live dependency on a secret server.

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

### Referencing KMS secrets

KMS secrets are referenced as `key_id:ciphertext`:

```yaml
listeners:
  - bind: 0.0.0.0:8443
    tls:
      cert_file: /etc/dwara/cert.pem
      key_file: kms:alias/dwara-secrets:base64-encoded-ciphertext
```

The gateway decrypts the ciphertext using the named KMS key and uses
the plaintext as the secret value.

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

Both Vault and KMS secret sources fail closed: if a secret cannot be
resolved (Vault is down, KMS is unreachable, decryption fails), the
gateway does not start (or does not reload, for a live config
change). A misconfigured secret never silently falls back to an
empty or default value.

## Interaction with the file secret source

The built-in file secret source (reading secrets from files on disk,
e.g. for Docker/Kubernetes secrets) is always available. External
secret sources complement it -- you can mix file and Vault/KMS
secrets in the same config.
