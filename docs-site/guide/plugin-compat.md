# Plugin compatibility

The compatibility contract between dwara gateways and proxy-wasm
plugins: which ABI level the host implements, which `proxy-wasm` crate
version the scaffold pins, which wasm targets load, and what counts as
a breaking change. Plugin authors should read this alongside the
[Plugin SDK](./plugin-sdk) hostcall matrix; the short version is at
the bottom.

## Proxy-wasm ABI level

The host implements the proxy-wasm **HTTP filter** ABI — the
header/body/log/local-response hostcall subset that HTTP filters use,
with the stream (TCP) context calls stubbed to Continue. Within that
subset:

- Imports are registered under their **spec names**
  (`proxy_send_local_response`, `proxy_get_current_time_nanoseconds`,
  ...), at their spec signatures, so modules built with the Rust
  proxy-wasm SDK (and other spec-conformant toolchains) link and run.
  Two legacy dwara spellings (`proxy_send_http_response`,
  `proxy_get_current_time`) remain registered with their original
  signatures; new plugins should use the spec names.
- Header maps use the spec map-type constants (request headers `0`,
  response headers `2`); the buffer hostcalls use the spec buffer-type
  constants (request body `0`, response body `1`, VM configuration
  `6`, plugin configuration `7`).
- Pair-serialized maps (`proxy_get_header_map_pairs`,
  `proxy_set_header_map_pairs`, and the header argument of
  `proxy_send_local_response`) use the SDK/spec wire layout:
  little-endian u32 entry count, little-endian u32 (key_len,
  value_len) length table, then NUL-terminated strings — the layout
  the Rust proxy-wasm SDK serializes and parses. Dwara's legacy
  `proxy_send_http_response` spelling keeps its original big-endian
  interleaved layout; modules written against that spelling (dwara's
  example plugins) are unaffected.
- The module lifecycle follows the spec sequence: `_start`,
  `proxy_on_context_create(root, 0)`, `proxy_on_vm_start`,
  `proxy_on_configure`, then per-request
  `proxy_on_context_create(ctx, root)` before the phase exports.
  Minimal ABI modules without the lifecycle exports also load (the
  host skips absent exports).

What is implemented, partial, or stubbed is enumerated per hostcall in
the [Plugin SDK support matrix](./plugin-sdk#hostcall-support-matrix).

## The proxy-wasm crate pin

`dwara-cli plugin new` scaffolds against:

```toml
[dependencies]
proxy-wasm = "0.2"
```

`0.2` is the pin the scaffold has shipped since the SDK workflow
landed; the host is audited against the 0.2.x series (0.2.5 at the
time of writing). A scaffolded plugin builds unmodified against every
0.2.x patch release. If the scaffold moves to a newer major (0.3+),
the [changelog](https://github.com/shristilabs/dwara/blob/main/CHANGELOG.md)
and this page move with it, and existing 0.2-built modules keep
loading — the ABI the host accepts is the spec ABI, not the crate.

## Wasm target matrix

| Target | Loads | Notes |
|---|---|---|
| `wasm32-wasip1` | Yes | The scaffold's target. The host stubs the small WASI p1 set Rust std emits (`environ_*`, `fd_write`, `proc_exit`, `random_get`, `clock_time_get`, `sched_yield`); anything beyond that set fails instantiation, fail-closed. |
| `wasm32-unknown-unknown` | Yes | Loads when the module imports no WASI (a `#![no_std]` plugin, or a toolchain that emits none). The proxy-wasm hostcalls are identical. |
| `wasm32-wasip2` | No | The component model is not implemented. Stance: p2 support would follow the proxy-wasm ecosystem (SDK and community filters) adopting it; until then the scaffold stays on p1. |
| Other targets | No | `wasm64-*` and friends are rejected at compile/instantiate. |

## Breaking-change policy for the hostcall surface

The hostcall surface is the contract. Within a dwara minor version:

- **Never breaking:** a hostcall that loads today keeps loading (name,
  module (`env`/`wasi_snapshot_preview1`), and signature), and a
  hostcall marked **Supported** keeps its semantics. The supported
  subset can only grow.
- **Not breaking:** a hostcall marked **Partial** or **Stub** gaining
  capability (a stub starting to work, per-instance state becoming
  shared). Plugins must not rely on a stub *failing*.
- **Breaking (avoided, changelog-required if ever needed):** removing
  or re-signing a registered import, changing Supported semantics, or
  narrowing the WASI subset. Pre-1.0, dwara reserves breaking changes
  for minor versions, always with a changelog entry and a compatibility
  note here.

The two legacy import spellings are covered by the same policy: they
stay registered as long as any released gateway accepts the modules
that use them.

## Plugin versioning guidance

- **Plugin versions are independent of gateway versions.** Plugins
  version against the ABI (above), not the gateway release. A plugin
  built for the current ABI keeps loading across gateway minors.
- **Semver your plugins**: breaking behavior changes (new required
  config keys, changed header effects) bump the plugin's major; pure
  fixes bump the patch. The plugin's `config` blob is part of its
  contract — treat additive-only as the rule, the same discipline the
  gateway config schema follows.
- **Pin artifacts by digest, not by tag.** When distributing plugins
  (see [Plugin registry](./plugin-registry)), pin the exact bytes with
  the `source.digest` field; a floating tag can change plugin behavior
  under a stable config. A plugin definition change (bytes or config)
  hot-swaps on reload and invalidates cached responses on every route
  referencing the plugin — version your artifacts so a rollback is a
  digest change, not a rebuild.

## The registry `compat` field

The plugin registry manifest (see
[Plugin registry](./plugin-registry)) carries an optional `compat`
string on each entry — a gateway version range the artifact is known
to work with, e.g. `">=0.9 <1.0"`. It is advisory today: `dwara
plugin search` / `plugin install` do not read it, and the gateway
does not reject an entry whose range excludes it. Authors should set
it to the gateway versions the artifact was tested against so it is
ready when enforcement lands; until then, the hostcall matrix above
is the actual compatibility contract.

## Summary

- Build with the scaffold (`proxy-wasm` 0.2, `wasm32-wasip1`); the
  result runs on every default build of the gateway.
- Stay inside the [supported hostcalls](./plugin-sdk#hostcall-support-matrix);
  do not depend on stubbed calls failing.
- Fuel is the effective execution bound; `timeout_ms` does not fire on
  its own.
- Version and digest-pin your artifacts; treat the plugin `config`
  blob as additive-only.
