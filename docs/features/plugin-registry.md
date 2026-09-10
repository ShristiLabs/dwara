# Remote/Signed Plugin Registry (#192, CFG-06)

## Overview

The plugin system previously loaded `.wasm` modules only from local
filesystem paths. This feature adds remote/signed plugin registry
support: plugin artifacts can be downloaded from an HTTP/OCI
registry, verified by SHA-256 digest and optional Ed25519 signature,
and cached locally. The CLI gains `dwara plugin search` and
`dwara plugin install` commands.

## Motivation

- **Fleet consistency:** All gateways in a fleet reference the same
  registry and get the same signed artifacts, ensuring plugin
  versions are pinned and consistent across the fleet.
- **Supply-chain security:** SHA-256 digest verification and optional
  Ed25519 signature verification ensure plugin artifacts are not
  tampered with in transit or at rest.
- **Operational simplicity:** Operators can search and install
  plugins from a central registry instead of manually distributing
  `.wasm` files to each gateway.

## Configuration

### `PluginSourceConfig`

Added to `PluginConfig` as the `source` field. When set, the gateway
downloads the `.wasm` artifact from the registry at startup (and on
reload), verifies its digest, and caches it locally before loading.

```rust
pub struct PluginSourceConfig {
    pub url: String,              // https:// or oci://
    pub digest: String,           // SHA-256 hex, required
    pub signature: Option<String>,// Ed25519 hex, optional
    pub public_key: Option<String>,// Ed25519 key hex, required with signature
    pub cache_path: Option<String>,// local cache path, optional
}
```

### `PluginRegistryConfig`

Added to `Gateway` as the `plugin_registry` field. Enables
fleet-consistent pinning.

```rust
pub struct PluginRegistryConfig {
    pub base_url: Option<String>,    // registry base URL
    pub public_keys: Vec<String>,     // pinned Ed25519 public keys
    pub cache_dir: Option<String>,   // local cache directory
}
```

### Example config

```yaml
plugin_registry:
  base_url: https://registry.example.com/plugins
  public_keys:
    - 9f2a7c3b1e8d4f6a5c2b7e9d1a3f4c6b8e7d2a1f3c5b9e4d6a8c2f1b7e3d5a9
  cache_dir: /var/lib/dwara/plugins

plugins:
  - name: rate-limiter
    source:
      url: https://registry.example.com/plugins/rate-limiter-1.2.0.wasm
      digest: a1b2c3d4e5f6...
      signature: 9f2a7c3b...
      public_key: 9f2a7c3b1e8d4f6a5c2b7e9d1a3f4c6b8e7d2a1f3c5b9e4d6a8c2f1b7e3d5a9
    phases:
      - request_headers
      - response_headers
```

## Validation

`validate_plugins` in `crates/dwara-core/src/snapshot/mod.rs` checks:

- `source` is mutually exclusive with `wasm` and `native`.
- `source.digest` must be non-empty.
- `source.url` must use `https://` or `oci://` scheme.
- `source.signature` requires `source.public_key`.
- Each pinned `public_key` in `plugin_registry` must be 64 hex chars
  (32 bytes).

## CLI commands

### `dwara plugin search`

```sh
dwara plugin search [--registry URL] [query]
```

Fetches the registry's manifest JSON, filters by the optional query
(substring match on plugin names), and prints plugin names,
versions, and digests.

### `dwara plugin install`

```sh
dwara plugin install <name> [--registry URL] [--digest HASH] [-o DIR]
```

Fetches the plugin's manifest entry, downloads the `.wasm` artifact,
verifies the SHA-256 digest, and writes it to the output directory.

Registry URL resolution: CLI arg > `DWARA_PLUGIN_REGISTRY` env var >
default (`https://registry.dwara.dev/plugins`).

## Design decisions

- **Lean dependencies:** Uses `curl` as an external tool for HTTP(S)
  fetches instead of adding TLS dependencies to the CLI. This is
  consistent with the project's approach in #187 (Kafka REST Proxy)
  and #190 (external Parquet conversion). The `sha2` crate is already
  in the workspace dependency tree.
- **Digest-first verification:** SHA-256 digest is required for all
  remote plugins. Ed25519 signature is optional (suitable for trusted
  registries where digest verification is sufficient).
- **OCI support:** The `source.url` field accepts `oci://` references
  for OCI artifact registries. The actual OCI client implementation
  is a follow-up; the config and validation infrastructure is in
  place.
- **Cache reuse:** The cached artifact is reused if its digest
  matches the expected digest; otherwise it is re-downloaded.

## Source files

- `crates/dwara-core/src/config/mod.rs` -- `PluginSourceConfig`,
  `PluginRegistryConfig`, `PluginConfig.source`,
  `Gateway.plugin_registry`.
- `crates/dwara-core/src/snapshot/mod.rs` -- validation logic.
- `crates/dwara-cli/src/plugin_registry.rs` -- CLI `search` and
  `install` commands.
- `crates/dwara-cli/src/main.rs` -- `PluginKind::Search` and
  `PluginKind::Install` subcommands.
