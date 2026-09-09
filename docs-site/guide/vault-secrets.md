# Vault secrets

Dwara can resolve secrets from external secret management systems at
request time, instead of embedding secrets in the config file. The
Vault provider reads secrets from HashiCorp Vault's key-value store.

Vault is one of two external secret sources -- the other,
[KMS secrets](./kms-secrets), decrypts envelope-encrypted values via
a cloud KMS. Both providers plug into the same reference-resolution
model as the built-in file source; see [Secrets](./secrets) for how
secret references are written and resolved.

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

## How it works

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
reload). See [Secrets](./secrets) for the general
reference-resolution model, and [KMS secrets](./kms-secrets) for the
envelope-encryption alternative.

### Lease renewal

Vault secrets are read with a lease. The gateway renews leases
automatically before they expire. If a lease cannot be renewed (e.g.
Vault is down), the gateway continues using the cached secret value
until the lease expires, then fails closed.

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
