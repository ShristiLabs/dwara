# Native filter API

Signature-level reference for the native plugin filter surface:
the `NativeFilter` trait, its outcome and response types, the
factory, and the registry. Every entry below was extracted from
`crates/dwara-core/src/plugins/filter.rs` and
`crates/dwara-core/src/plugins/registry.rs`.

For workflow-oriented prose (setting up an embedding crate, a
worked filter, registration wiring, rollout) see
[Building a native filter](./building-native-filter); for the
configuration and operations view see
[Native plugin filters](./native-plugins).

## The trait

Compiled-in Rust filters implement
`dwara_core::plugins::NativeFilter`. The trait is
dyn-compatible; every method is synchronous and receives the current
headers/body **by value**; default implementations continue with the
input unchanged (a filter that does not hook a phase simply does not
override its method).

```rust
pub trait NativeFilter: Send + Sync {
    fn on_request_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome;
    fn on_request_body(&mut self, body: Vec<u8>) -> FilterOutcome;
    fn on_response_headers(&mut self, headers: Vec<(String, String)>) -> FilterOutcome;
    fn on_response_body(&mut self, body: Vec<u8>) -> FilterOutcome;
}
```

Phase placement (identical to the proxy-wasm phase contract):

| Method | Phase | Runs |
|---|---|---|
| `on_request_headers` | `request_headers` | After route resolution, before authn. |
| `on_request_body` | `request_body` | After authn/authz/rate-limit, before the route action. |
| `on_response_headers` | `response_headers` | After the upstream responds, before masking. |
| `on_response_body` | `response_body` | After masking, before compression. |

The header maps a filter sees carry the same pseudo-headers the WASM
host provides: the request map carries `:method` and `:path`, the
response map carries `:status`. Unlike the WASM host, header and
body phases are separate callbacks receiving one side each.

## Outcome and response types

The outcome of each callback:

```rust
pub enum FilterOutcome {
    Continue { headers: Vec<(String, String)>, body: Vec<u8> },
    LocalResponse(LocalResponse),
    Error(String),
}

pub struct LocalResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
```

- `Continue` threads the (possibly modified) headers/body back into
  the chain; pass the empty `Vec` for the side you did not receive.
- `LocalResponse` short-circuits: the proxy returns it immediately,
  the upstream is never dialed.
- `Error` answers 500 (mirroring a WASM trap); the message is
logged, never sent to the client.

Both types derive `Clone`/`Debug`; `LocalResponse` is also
`PartialEq`/`Eq`, which makes assertion-based tests of a filter's
short-circuit responses one `assert_eq!`.

## Registration

Registration is an embedder seam: a factory parses the plugin's
opaque `config` string (the same blob a WASM plugin gets in
`proxy_on_configure`) and produces a boxed filter.

```rust
pub type NativeFilterFactory =
    Box<dyn Fn(&Option<String>) -> Result<Box<dyn NativeFilter>, String> + Send + Sync>;
```

The registry maps an implementation name to a factory. It is
`Clone` (the inner map is shared through `Arc<RwLock<...>>`), so one
registry instance (or clones of it) can be shared across worker
tasks.

```rust
pub struct NativeRegistry { /* name -> factory map, clone-shared */ }

impl NativeRegistry {
    pub fn new() -> Self;
    pub fn register(
        &self,
        name: impl Into<String>,
        factory: NativeFilterFactory,
    ) -> Result<(), RegistryError>;
    pub fn create(
        &self,
        name: &str,
        config: &Option<String>,
    ) -> Result<Box<dyn NativeFilter>, RegistryError>;
    pub fn contains(&self, name: &str) -> bool;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn names(&self) -> Vec<String>;   // sorted for determinism
}
```

Errors from the registry (`Display` messages shown):

```rust
pub enum RegistryError {
    NotFound { name: String },          // "native filter '{name}' is not registered"
    Construction { name: String, error: String },
                                        // "native filter '{name}' construction failed: {error}"
    Duplicate { name: String },         // "native filter '{name}' is already registered"
}
```

`register` holds the write lock only to insert (a duplicate name
refuses rather than overwrites); `create` resolves the factory under
the read lock and runs it there (construction is expected to be
cheap -- parse a config string).

## The dataplane accessor

The embedding binary reaches the registry through the dataplane
accessor:

```rust
pub fn native_plugin_registry(&self) -> &NativeRegistry   // on dwara_core::dataplane::DataPlane
```

Registration happens once at startup, before traffic: construct the
`DataPlane`, register every factory by name, then serve. There is no
config-file or plugin-file mechanism that loads a native filter into
the stock gateway binary; the stock binary ships with none
registered.

## Config selection

Config selects a registered filter with `native: <name>` on a plugin
entry (exactly one of `wasm:` / `native:`, plus a non-empty `phases`
list):

```yaml
plugins:
  - name: my-native
    native: header-guard
    phases: [request_headers]
    config: '{"header":"x-guard-key","value":"open-sesame"}'
```

When the per-request chain is built, the plugin's `config` string is
passed to the factory verbatim. A factory error while the chain is
built answers 500 `plugin_unavailable`, never a silent skip; a
filter returning `FilterOutcome::Error` answers 500
`plugin_failed` -- the same fail-closed semantics a WASM trap
produces, scoped to the referencing route only.

## Where to go next

- [Native plugin filters](./native-plugins) - the option landing
  page: configuration, phase contract, WASM comparison.
- [Building a native filter](./building-native-filter) - the
  building guide: embedding crate setup, a worked filter,
  registration, rollout.
- [Extension API](../reference/extension-api) - the index of every
  extension surface's reference page.
