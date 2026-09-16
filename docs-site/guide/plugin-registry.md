# Plugin registry

Plugins can be loaded from a remote registry with SHA-256 digest
verification and optional Ed25519 signature verification. This
enables fleet-consistent plugin pinning: all gateways in a fleet
reference the same registry and get the same signed artifacts.

::: info Status
Live end to end: the gateway resolves `source:`-referenced plugins at
every publish (startup and reload), verifies digest and signatures
before loading, caches artifacts locally, and runs them on the request
path like local plugins. Registry tooling (`dwara plugin search` /
`plugin install`) works against the same layout. See
[Proxy-Wasm plugins](./proxy-wasm-plugins) for the runtime contract.
:::

## When to use this

- A fleet of gateways must run byte-identical plugin builds, pinned
  by digest rather than by mutable local copies.
- Plugins come from outside your build (a vendor or another team) and
  must be verified -- SHA-256 digests, optionally Ed25519 signatures
  -- before the gateway loads them.
- Gateways deploy into restricted or offline environments: artifacts
  are cached content-addressed, and a cached artifact satisfies
  resolution with no network access at all.

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

### Fields

| Field | Required | Description |
|---|---|---|
| `url` | yes | Artifact URL (`https://`). Fetched with one HTTP/1.1 GET; redirects are not followed. `oci://` is not supported yet. |
| `digest` | yes | Expected SHA-256 hex digest (64 chars). Verified against cached AND downloaded bytes. |
| `signature` | no | Ed25519 signature over the artifact bytes (hex, 128 chars). |
| `public_key` | no | Ed25519 public key (hex, 64 chars). Required with `signature` unless the registry pins keys. A key set **without** a signature is rejected (a key that verifies nothing is a config mistake). |
| `cache_path` | no | Cache file path **relative to the cache dir**, with no `..` segments (the artifact must stay inside the cache). Defaults to content-addressed `<digest>.wasm`. |

## Fleet-consistent pinning

Configure the `plugin_registry` block at the gateway level to pin a
set of public keys and a shared cache directory:

```yaml
plugin_registry:
  base_url: https://registry.example.com/plugins
  public_keys:
    - 9f2a7c3b1e8d4f6a5c2b7e9d1a3f4c6b8e7d2a1f3c5b9e4d6a8c2f1b7e3d5a9
  cache_dir: /var/lib/dwara/plugins
```

Signature rules when the registry pins `public_keys`:

- A plugin with **no signature is rejected** -- unsigned artifacts
  cannot ride a pinned-key registry.
- A plugin's signature must verify against **at least one pinned
  key**, in addition to its own `public_key` when one is configured.
- A `public_key` set **without** a `signature` is rejected everywhere
  (pinned registry or not): a key that verifies nothing is a config
  mistake -- sign the artifact or remove the key.

Without pinned keys and without a per-plugin signature, the artifact
is verified digest-only (suitable for trusted registries).

## How the gateway resolves a source

At every publish (startup and reload), each `source:` plugin runs
through the same pipeline before the WASM load step:

```text
scheme check -> digest format check -> cache lookup
    hit  -> verify cached digest -> verify signature -> load
    miss -> HTTPS GET -> verify downloaded digest -> verify signature
            -> cache atomically -> load
```

Properties operators can rely on:

- **Fail-closed, per plugin.** A source that cannot be resolved or
  fails verification never loads. The plugin reads `crashed` on the
  plugin status surface with an error naming the exact step (cache
  lookup, download, digest verification, signature verification),
  and every route referencing it answers `500` `plugin_unavailable`
  from the first request of the new generation. Other plugins and
  routes are unaffected.
- **Tampered cache fails closed.** The cache is content-addressed:
  the file named for a digest must hash to that digest. A mismatch
  (disk corruption or tampering) is reported as a digest error and
  is never silently re-downloaded -- the operator decides.
- **Digests are re-verified on every publish**, including cache hits
  and signed artifacts. Nothing is trusted because it is on disk.
- **Offline-safe.** A cached artifact satisfies resolution with the
  registry unreachable; the cache is the source of truth once the
  bytes are verified.
- **One fetch per miss, under a time budget.** The gateway performs a
  single GET with a 10s connect timeout and a 30s per-read timeout,
  does not follow redirects, and caps artifacts at 64 MiB. On top of
  the per-read timeouts, ALL source downloads of one publish share a
  60-second budget: a slow or drip-feeding registry cannot stall
  reloads indefinitely. When the budget runs out, the plugins that
  still needed the network fail closed with a budget-named error
  (cached plugins keep resolving -- they need no network), and the
  next publish retries. Resolution also runs off the gateway's
  request-handling threads, so a hung registry delays the reload, not
  traffic.

### Cache layout

```text
/var/lib/dwara/plugins/            # plugin_registry.cache_dir
  <sha256-digest>.wasm             # one immutable artifact per digest
  .<sha256-digest>.wasm.tmp<pid>   # transient write target (never read)
```

- Artifacts are named by digest, so two plugins pinning the same
  bytes share one file, and a fleet can pre-seed the cache with any
  file copy tooling.
- Cache writes are atomic (write to a same-directory temp file, sync,
  rename). A crash mid-download can never leave a partial artifact
  under the digest name; the next resolve either sees the complete
  file or downloads again.
- The default cache directory (when `cache_dir` is absent) is
  `./plugin-cache`, relative to the gateway working directory.

### `oci://` sources

OCI artifact references are not supported in this version: config
that uses `oci://` fails validation with an explicit error. Publish
the artifact over plain HTTPS (any static host -- see the spec
below), or pull it with your OCI tooling and reference the local
file with `wasm:`.

## Pre-fetching for offline gateways

Use the CLI to populate the cache ahead of a restricted deployment:

```sh
dwara plugin install rate-limiter --digest a1b2c3d4e5f6... -o /var/lib/dwara/plugins
```

Rename (or install directly) the artifact to
`<digest>.wasm` under the gateway's `cache_dir`, and the gateway
resolves it without ever dialing the registry.

## Registry spec

The contract that `dwara plugin search` / `plugin install` implement
and that self-hosted registries must serve. A registry is **any
static HTTPS host**: no server-side logic is required, only three
content types at stable paths.

### Layout

Given a registry base URL (e.g. `https://registry.example.com/plugins`):

| Path | Content type | Purpose |
|---|---|---|
| `/manifest.json` | `application/json` | The catalog: every plugin, version, digest. |
| `/<name>-<version>.wasm` (or the manifest's `url`) | `application/wasm` or `application/octet-stream` | The artifact bytes. |
| Optional: `/<name>-<version>.sig` | `text/plain` | Detached signature material (see below). |

`base_url` in the gateway's `plugin_registry` block is informational
for fleet tooling; each plugin's `source.url` is always a full URL,
so gateways can mix registries or pin absolute CDN URLs.

### `manifest.json` schema

A JSON array at the registry root; one object per plugin version:

```json
[
  {
    "name": "rate-limiter",
    "version": "1.2.0",
    "digest": "a1b2c3d4e5f6...full 64-char sha256...",
    "url": "https://registry.example.com/plugins/rate-limiter-1.2.0.wasm",
    "signature": "9f2a7c3b...full 128-char hex signature...",
    "public_key": "9f2a7c3b1e8d4f6a5c2b7e9d1a3f4c6b8e7d2a1f3c5b9e4d6a8c2f1b7e3d5a9",
    "compat": ">=0.9 <1.0"
  }
]
```

| Field | Required | Type | Description |
|---|---|---|---|
| `name` | yes | string | Plugin name (the key CLI installs match on). |
| `version` | yes | string | Version label, informational for the gateway. |
| `digest` | yes | string | SHA-256 of the artifact bytes, hex. **Digests are mandatory everywhere** -- in the manifest and in every gateway `source:` pin. There are no digest-less remote plugins. |
| `url` | no | string | Absolute artifact URL. Defaults to `<base>/<name>.wasm` when absent. |
| `signature` | no | string | Ed25519 signature over the artifact bytes, hex (128 chars). Copy into the plugin's `source.signature` when pinning. |
| `public_key` | no | string | Ed25519 public key, hex (64 chars). Copy into `source.public_key`, or pin fleet-wide via `plugin_registry.public_keys`. |
| `compat` | no | string | Gateway version constraint. Advisory in this version: the CLI surfaces it; the gateway does not yet enforce it at load. |

The gateway itself never reads `manifest.json` -- operators (or CI)
copy `digest`/`signature`/`public_key` from the manifest into their
config, pinning exactly what runs. This keeps the gateway's fetch
surface to one GET per artifact.

### Signature envelope

One canonical rule, both sides: **the Ed25519 signature is over the
raw artifact bytes exactly as downloaded and exactly as loaded.**
Sign the `.wasm` file itself (RFC 8032 Ed25519, hex-encoded). Producer
side with openssl:

```sh
# signature (64 bytes, hex-encoded -> source.signature / manifest "signature"):
openssl pkeyutl -sign -inkey ed25519.key -rawin -in plugin.wasm \
  | xxd -p -c 256

# public key (raw 32 bytes from the SPKI DER trailer -> source.public_key):
openssl pkey -pubout -in ed25519.key -outform DER | tail -c 32 | xxd -p -c 64
```

Key distribution:

- **Per-plugin**: `source.public_key` next to `source.signature`.
- **Fleet-wide**: `plugin_registry.public_keys` pins the trusted
  signer set; every `source:` plugin must then carry a signature that
  verifies against one of them.

### Serving requirements

Any static HTTPS host works (S3 bucket + CloudFront, GitHub Releases,
nginx, a Git repository's raw view). Requirements:

1. `GET <url>` returns the artifact bytes with `200` (no redirects --
   serve the final URL; the gateway does not follow 3xx).
2. Correct `Content-Length` or chunked transfer encoding; bodies are
  capped at 64 MiB.
3. TLS with a publicly-trusted certificate (the gateway uses the
   standard web root store).
4. Immutability per URL: a published `<digest>` URL must serve the
   same bytes forever. Digest pinning makes replays harmless to
   security but confusing to operators -- publish new versions under
   new URLs.

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

- `curl` must be installed (used by the CLI for HTTP(S) fetches; the
  gateway itself fetches with its own built-in HTTPS client and needs
  nothing extra).
