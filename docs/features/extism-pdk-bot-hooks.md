# Extism PDK plugins, bot hooks, signed URLs, cert pinning (DW-109)

> Implements issue DW-109 (four security/plugin sub-features, each
> independently feature-gated). Sources:
> `crates/dwara-core/src/plugins/extism.rs` (`ExtismHost`,
> `ExtismPlugin`, `ExtismInstance`, `ExtismDispatch`,
> `ExtismChainAdapter`, `NoExtism`),
> `crates/dwara-core/src/security/bot_hooks.rs` (`BotHooksEngine`),
> `crates/dwara-core/src/security/signed_url.rs` (`SignedUrlConfig`,
> `SignedUrlVerifier`, `SignedUrlError`, `SignedUrlResult`),
> `crates/dwara-core/src/security/cert_pinning.rs` (`CertPin`,
> `CertPinVerifier`, `CertPinError`). Tests: the Extism scaffold
> contract (host load/duplicate/instance, no-op phase methods, dispatch
> adapter), the signed-URL verifier (valid/invalid/expired/missing-param
> round trips, sign/verify counterpart), the cert-pinning scaffold
> (empty pins accept, configured pins fail closed). Operator docs:
> [native plugins guide](../../docs-site/guide/native-plugins.md) and
> [security guide](../../docs-site/guide/security.md).

Four sub-features that extend the gateway's plugin surface and
security posture. The Extism PDK runtime is an alternative plugin host
(alongside proxy-wasm from DW-055 and the native filter trait from
DW-119). The bot hooks, signed URLs, and cert pinning are security
features that run in the request path. Each is independently
feature-gated so operators enable only what they need.

## Extism PDK plugin scaffold

Extism is an alternative plugin runtime that uses the Extism PDK
(Plugin Development Kit) ABI, allowing plugins written in any language
that compiles to WebAssembly (Rust, Go, C, Zig, ...) to run inside the
gateway. Like the proxy-wasm host (DW-055), an Extism plugin is a
`.wasm` module loaded at startup; unlike proxy-wasm, the Extism ABI is
simpler -- a single `call` entry point with input/output buffers, not
a multi-phase stream contract.

The scaffold is feature-gated behind the `extism` cargo feature
(default OFF). The actual `extism` crate is NOT a dependency yet. The
runtime calls in `ExtismHost` are scaffolded as documented no-ops:
`load` records the plugin definition but does not create a real Extism
plugin; `instance` returns an `ExtismInstance` whose phase methods
return `FilterOutcome::Continue` with the input unchanged. When
production-ready, the `extism` crate would be added and the stubs
replaced with real SDK invocations.

`ExtismPlugin` mirrors the config plugin definition: a `.wasm` module
path, a plugin name, an opaque config string, and the phases this
plugin hooks. `ExtismInstance` implements `NativeFilter` so the
unified plugin chain (DW-119) dispatches to it at each phase,
identically to a native filter or a WASM plugin. `ExtismDispatch` is
the dispatch trait (separate from `NativeFilter` because the host owns
per-request instances); `ExtismChainAdapter` is the per-request
adapter; `NoExtism` is the no-op adapter for routes without Extism
plugins. The scaffold does not import `wasm` -- the two runtimes are
independent.

## Bot detection hooks

`BotHooksEngine` is a placeholder module so the `pub mod bot_hooks`
declaration in `security/mod.rs` resolves. The full bot-detection
engine (regex-based pre-request and post-response checks, like
WAF-lite DW-051) is not yet implemented. The module compiles in every
build (no feature gate) but is inert: `BotHooksEngine::empty()` builds
an engine with no compiled hooks; every request passes unchecked. The
integration point is the request path, where the engine would run
pre-request checks (header signatures, user-agent patterns) and
post-response checks alongside the existing WAF-lite and rate-limiting
layers.

## Signed URL verification

Short-lived signed URL verification: a request to a route with
`signed_url` enabled must carry a cryptographic signature in its query
string, computed as an HMAC-SHA256 over the canonical request (method,
path, and an expiry timestamp). The signature proves the URL was
minted by a trusted party that holds the secret; the expiry bounds the
URL's validity window.

The canonical string signed by the HMAC is
`<METHOD>\n<path>\n<expires>` -- the uppercase HTTP method, the request
path (without query string), and the expiry as a Unix epoch seconds
string. The signature is the HMAC-SHA256 of this canonical string,
hex-encoded. The verifier extracts `sig` (configurable via
`query_param`, default `sig`) and `expires`, checks the expiry,
recomputes the HMAC, and compares using a constant-time comparison
(`subtle::ConstantTimeEq`).

The verifier is feature-gated behind the `signed_url` cargo feature
(default OFF). The config schema is always present; when off, the
block is accepted but inert (validation warns). Signed URL
verification runs as an authn method, before authz -- a route with
`signed_url.enabled: true` requires a valid signature; a missing or
invalid signature is rejected with 401 `signed_url_invalid` or 401
`signed_url_expired`. `SignedUrlVerifier::sign` is the counterpart to
`verify`: an external URL minter (or a test) uses it to produce a
valid signature.

```yaml
routes:
  - name: files
    match: { path: { type: prefix, value: /files } }
    signed_url:
      enabled: true
      secret: ${SIGNED_URL_SECRET}   # use a secret reference (DW-045)
      ttl_seconds: 300               # default 300; must be > 0
      query_param: sig               # default sig; must be non-empty
    action: { type: proxy }
```

## Upstream TLS certificate pinning

When enabled, the gateway pins upstream TLS certificates by their
SubjectPublicKeyInfo (SPKI) hash. During the TLS handshake, the
verifier extracts the upstream cert's SPKI, computes its SHA-256, and
compares it against the configured pins. A mismatch rejects the
connection (fail-closed: no fallback to CA-based verification). Pinning
the SPKI (rather than the full certificate) allows leaf rotation as
long as the key pair is unchanged.

This is a scaffold behind the `cert_pinning` cargo feature. `CertPin`
holds the SHA-256 hash of the SPKI (lowercase hex, 64 chars).
`CertPinVerifier` holds the allowed SPKI hashes; `from_upstream`
returns `None` when the upstream has no `cert_pinning` block (normal
CA-based verification). `verify` is a documented no-op: it accepts
everything when there are no pins and rejects everything when there
are pins (fail-closed). The SPKI extraction + SHA-256 + the rustls
custom verifier wiring would land here when production-ready.

```yaml
upstreams:
  - name: api
    cert_pinning:
      pins:
        - spki_sha256: "abcdef0123456789..."
```

The `cert_pinning` config block is always present in the schema; when
off the block is accepted but inert (validation warns).

## Feature gates

| Sub-feature | Cargo feature | Default | Config schema |
|---|---|---|---|
| Extism PDK plugins | `extism` | OFF | `plugins` (shared DW-119) |
| Bot detection hooks | (none, inert stub) | always compiled | (not yet wired) |
| Signed URL verification | `signed_url` | OFF | `routes[].signed_url` |
| Certificate pinning | `cert_pinning` | OFF | `upstreams[].cert_pinning` |

The [native plugins](./native-plugins.md) page covers the unified
dispatch chain (DW-119); the [proxy-wasm](./proxy-wasm.md) page covers
the alternative WASM host; the [authn-authz](./authn-authz.md) page
covers signed URL verification's request-path position.
