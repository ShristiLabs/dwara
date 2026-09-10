# Plugin registry

Plugins can be loaded from a remote registry with SHA-256 digest
verification and optional Ed25519 signature verification. This
enables fleet-consistent plugin pinning: all gateways in a fleet
reference the same registry and get the same signed artifacts.

## Configuring a remote plugin source

Set the `source` block on a plugin entry instead of a local `wasm`
path:

```yaml
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

The gateway downloads the `.wasm` artifact at startup (and on
reload), verifies its SHA-256 digest, optionally verifies the
Ed25519 signature, and caches it locally before loading.

### Fields

| Field | Required | Description |
|---|---|---|
| `url` | yes | Registry URL (`https://` or `oci://`). |
| `digest` | yes | Expected SHA-256 hex digest. |
| `signature` | no | Ed25519 signature (hex). Requires `public_key`. |
| `public_key` | no | Ed25519 public key (hex, 32 bytes). Required with `signature`. |
| `cache_path` | no | Local cache path. Defaults to `<data_dir>/plugins/<name>.wasm`. |

## Fleet-consistent pinning

Configure the `plugin_registry` block at the gateway level to pin a
set of public keys and a base URL:

```yaml
plugin_registry:
  base_url: https://registry.example.com/plugins
  public_keys:
    - 9f2a7c3b1e8d4f6a5c2b7e9d1a3f4c6b8e7d2a1f3c5b9e4d6a8c2f1b7e3d5a9
  cache_dir: /var/lib/dwara/plugins
```

When the registry has pinned public keys, plugin signatures are
verified against these keys in addition to any per-plugin
`public_key`. A plugin with no signature is rejected when the
registry has pinned keys.

## CLI: searching and installing plugins

### `dwara plugin search`

```sh
dwara plugin search [--registry URL] [query]
```

Fetches the registry's manifest and prints available plugins. The
optional `query` filters by substring match on plugin names.

```sh
dwara plugin search rate
```

```
rate-limiter    1.2.0    a1b2c3d4e5f6...
rate-limiter    1.1.0    b2c3d4e5f6a1...
```

### `dwara plugin install`

```sh
dwara plugin install <name> [--registry URL] [--digest HASH] [-o DIR]
```

Downloads the plugin artifact, verifies its SHA-256 digest, and
writes it to the output directory (default: current directory).

```sh
dwara plugin install rate-limiter -o /var/lib/dwara/plugins
```

```
installed plugin 'rate-limiter' -> /var/lib/dwara/plugins/rate-limiter.wasm (digest: a1b2c3d4...)
```

The registry URL can be set via the `DWARA_PLUGIN_REGISTRY`
environment variable or the `--registry` flag. The default is
`https://registry.dwara.dev/plugins`.

## Requirements

- `curl` must be installed (used for HTTP(S) fetches).
- The `sha2` crate (already a workspace dependency) is used for
  digest verification.
