# Extension trait API

Signature-level reference for the five swappable subsystem seams:
every trait method, its parameter and return types, and the shared
error type. Every entry below was extracted from
`crates/dwara-core/src/extensions/`.

All five traits are `async` via the `async-trait` crate (native
RPITIT is not yet dyn-compatible on stable Rust, and
dyn-compatibility is the load-bearing requirement), dyn-compatible,
used as `Arc<dyn Trait>`, and share one error type. For the
contracts in prose (retry posture, fail-open versus fail-closed,
edition wiring) see [Extension traits](./extension-traits); for a
complete worked implementation see
[Building an extension](./building-extension).

## Shared error type

```rust
#[non_exhaustive]
pub enum ExtensionsError {
    Io(String),          // "extension io error: {m}"
    Invalid(String),     // "extension invalid-data error: {m}"
    Backend(String),     // "extension backend error: {m}"
    Unsupported(String), // "extension unsupported operation: {m}"
}
```

Non-exhaustive by design: a new backend surfaces new failure classes
via `Backend` rather than new variants. `From<std::io::Error>` maps
to `Io` (carrying the OS error message); `From<ConfigError>` maps to
`Invalid` (preserving the path-precise config error display).

## RateLimiter (`dwara_core::extensions::rate_limiter`)

```rust
pub struct RateDecision {
    pub allowed: bool,
    pub remaining: u64,
    pub retry_after_ms: Option<u64>,
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: &str, cost: u32) -> Result<RateDecision, ExtensionsError>;
}
```

One-line contract: hot-path, atomic decide-**and**-reserve (an
`allowed` decision has already deducted `cost`; there is no refund);
the caller picks the fail-open/fail-closed policy. `retry_after_ms`
is the window remainder, not a success promise. A limiter that
cannot reach its backend reports `ExtensionsError::Backend`; no
retries are built in.

`RateDecision` is `Copy`.

## ConfigSource (`dwara_core::extensions::config_source`)

```rust
#[async_trait]
pub trait ConfigSource: Send + Sync {
    async fn load(&self) -> Result<Gateway, ExtensionsError>;
}
```

One-line contract: full read of the current configuration
generation, pull-only, off the request hot path; an unreadable
source fails the publish (fail-closed at publish). `Gateway` is the
parsed configuration tree (`dwara_core::config::Gateway`).

## CacheStore (`dwara_core::extensions::cache`)

```rust
#[async_trait]
pub trait CacheStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ExtensionsError>;
    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), ExtensionsError>;
    async fn delete(&self, key: &str) -> Result<bool, ExtensionsError>;
    async fn set_with_ttl(
        &self,
        key: String,
        value: Vec<u8>,
        ttl: std::time::Duration,
    ) -> Result<(), ExtensionsError> { /* default: delegates to set */ }
    fn entry_count(&self) -> Option<u64> { None }
}
```

One-line contract: errors are treated as a miss by call sites
(degrade, never fail the request); `set_with_ttl` is a memory hint
only -- readers re-check expiry from the value itself, so
correctness never depends on the backend honoring it; `delete` of a
missing key is `Ok(false)`. The two defaulted methods exist so
existing implementations stay valid backends without a change
(extend, do not break).

## AnalyticsSink (`dwara_core::extensions::analytics`)

```rust
#[non_exhaustive]
pub struct Event {
    pub kind: String,              // event type discriminator, e.g. "request"
    pub timestamp_ms: u64,         // Unix epoch milliseconds
    pub route: Option<String>,
    pub consumer: Option<String>,
    pub endpoint: Option<String>,
    pub status: Option<u16>,
    pub listener: Option<String>,
    pub method: Option<String>,
    pub duration_ms: Option<f64>,
    pub attempts: Option<u32>,
    pub rate_limited: bool,
    pub broken: bool,
    pub shed: bool,
    pub edge_id: Option<String>,
    pub attributes: Vec<(String, String)>,  // custom dimensions
}

impl Event {
    pub fn request_now() -> Self;  // a "request" event stamped with the current time
}

#[async_trait]
pub trait AnalyticsSink: Send + Sync {
    async fn record(&self, event: Event) -> Result<(), ExtensionsError>;
}
```

One-line contract: fire-and-forget -- `Ok` means accepted, not
durably persisted; implementations bound themselves (drop-oldest
under pressure) and must never stall the dataplane; events must not
carry secret material.

## SecretSource (`dwara_core::extensions::secrets`)

```rust
pub struct Secret(String);  // Debug is redacted ("Secret([N bytes redacted])")

impl Secret {
    pub fn new(value: impl Into<String>) -> Self;
    pub fn expose(&self) -> &str;   // callers must not log or persist it
}

#[async_trait]
pub trait SecretSource: Send + Sync {
    async fn resolve(&self, name: &str) -> Result<Option<Secret>, ExtensionsError>;
}
```

One-line contract: resolution happens at config-compile time (cold
start and every reload), never per request; `Ok(None)` is a miss
(the source has no such secret); implementors re-read on each
resolve so a rotation lands on the next reload.

## Where to go next

- [Extension traits](./extension-traits) - the option landing page:
  what each trait owns, default versus enterprise implementations.
- [Building an extension](./building-extension) - the building
  guide: embedding dwara-core, a complete worked `AnalyticsSink`,
  registration, rollout.
- [Extension API](../reference/extension-api) - the index of every
  extension surface's reference page.
