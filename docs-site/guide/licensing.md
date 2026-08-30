# Enterprise licensing

Dwara is open-core: the default build is the OSS edition (Apache-2.0),
and enterprise features are gated behind a license. This page covers
how to configure and operate the license gate.

## OSS vs enterprise

The default build (no `ent` cargo feature) is the OSS edition. It
compiles without the `licensing-core` dependency and every enterprise
feature is inert. A `license` block in the config is accepted but
ignored — the gateway runs in OSS mode regardless.

An enterprise build (`cargo build --features ent`) links
`licensing-core` and verifies a license file at startup. Enterprise
features are active only when the license is valid (or within the grace
period after expiry).

## Configuring a license

Add a `license` block to your gateway config:

```yaml
gateway:
  license:
    file: /etc/dwara/license.json
    grace_period_days: 7  # optional, default 7, range 0..=30
```

- `file` — path to the license file (JSON: claims + Ed25519 signature).
- `grace_period_days` — days after expiry before the gate degrades to
  OSS. Default 7. During the grace window enterprise features still
  work and a warning is logged. 0 means no grace (immediate
  degradation on expiry).

The public key is NOT in the config. It comes from the
`DWARA_LICENSE_PUBLIC_KEY` environment variable (base64-encoded 32-byte
Ed25519 public key), or the compiled-in development key when unset.
**Production deployments MUST set `DWARA_LICENSE_PUBLIC_KEY`** to the
real public key published by ShristiLabs. The key is never
user-configurable in the YAML so an operator cannot substitute their
own key to forge a license.

## Startup behavior

| Condition | Behavior |
|---|---|
| No `license` block | OSS mode. All features are OSS-only. |
| Valid license | Enterprise mode. Logs customer, plan, and features. |
| Expired, within grace | Enterprise mode with a warning. Renew before the grace window ends. |
| Expired, past grace | Degrades to OSS. Enterprise features fall back to OSS behavior. |
| Invalid signature | **Refuses to start** (exit 1). Check the license file and public key. |
| File not found | **Refuses to start** (exit 1). Check the `file` path. |

## Grace period

When a license expires, the gateway does not immediately drop
enterprise features. For `grace_period_days` after the expiry
timestamp, enterprise features keep working. This gives the operator a
buffer to renew the license without downtime.

After the grace window, the gate degrades to OSS: enterprise features
fall back to their OSS behavior. This is logged as a warning.

## Monitoring

The `dwara_license_status` metric on `/metrics` reports the current
license status:

| Value | Meaning |
|---|---|
| 0 | No license configured (OSS mode) |
| 1 | Valid license |
| 2 | Expired, within grace period |
| 3 | Expired, past grace period (degraded to OSS) |

Alert on value 2 (renew soon) and 3 (enterprise features degraded).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DWARA_LICENSE_PUBLIC_KEY` | compiled-in dev key | Base64-encoded Ed25519 public key for license verification. **Set in production.** |

## Building an enterprise binary

```sh
# OSS build (default)
cargo build --release

# Enterprise build
cargo build --release --features ent
```

The `ent` feature pulls in `licensing-core` (BSL-1.1). OSS builds never
link it.
