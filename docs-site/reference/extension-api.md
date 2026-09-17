# Extension API

Signature-level reference for every extension surface, one page per
mechanism. Each page was extracted from the owning source and is
kept in sync with it:

| Surface | Reference page | Owning source |
|---|---|---|
| Proxy-wasm hostcalls: the full hostcall tables, statuses, selector values, status codes | [Hostcall API reference](../guide/proxy-wasm-hostcalls) | `crates/dwara-core/src/wasm/` |
| Native filter: `NativeFilter`, `FilterOutcome`, factory, `NativeRegistry`, `RegistryError` | [Native filter API](../guide/native-filter-api) | `crates/dwara-core/src/plugins/` |
| Nano-service ABI: exports, imports, the request wire format, sandbox limits | [Nano-service ABI](../guide/nano-service-abi) | `crates/dwara-core/src/dataplane/nano_service.rs` |
| Extension traits: the five traits' methods, `RateDecision`, `Event`, `Secret`, `ExtensionsError` | [Extension trait API](../guide/extension-trait-api) | `crates/dwara-core/src/extensions/` |

Each reference page sits inside its option's sidebar group next to
the option's landing page and its building guide, so the signatures,
the operations prose, and the how-to are one click apart.

The full generated Rust API documentation for the workspace crates
is published at
<https://shristilabs.github.io/dwara/api/dwara_core/>
(built by CI from `main`; public items only).

Upstream references for the proxy-wasm surface:

- Rust proxy-wasm SDK (the crate `dwara-cli plugin new` scaffolds
  against): <https://docs.rs/proxy-wasm/0.2.5/proxy_wasm/>
- proxy-wasm ABI specification (the source of truth for every import
  name, parameter, and wire layout):
  <https://proxy-wasm.spec.vec.io/>
