# Extensibility and plugins

Dwara is extensible at three layers: plugin filters that intercept
traffic at defined phases, swappable extension traits that replace
entire subsystems, and WASM route handlers that generate a response
inside a module. All three plugin families are unified under one
dispatch chain, so a route can run a native filter, a proxy-wasm
filter, and an Extism filter in sequence.

## In this section

- [Proxy-Wasm plugins](./proxy-wasm-plugins) - the proxy-wasm host:
  community Kong and Envoy filters run unmodified inside Dwara.
- [Native plugin filters](./native-plugins) - a Rust filter trait
  compiled into the binary, running alongside proxy-wasm in the same
  dispatch chain.
- [Extism plugin development kit](./extism-pdk) - the Extism PDK
  runtime for plugins written in any language that compiles to WASM.
  Experimental; see the page for current status.
- [Nano-services (WASM handlers)](./nano-services) - a route action
  that runs a WASM module to generate the response directly, no
  upstream needed.
- [Plugin lifecycle](./plugin-lifecycle) - how plugins are loaded,
  configured, hot-reloaded, and torn down across config generations.
- [Plugin SDK](./plugin-sdk) - the types and helpers for writing
  native and proxy-wasm plugins against Dwara.
- [Extension traits](./extension-traits) - the five swappable seams
  (RateLimiter, ConfigSource, CacheStore, AnalyticsSink, SecretSource)
  that let you replace entire subsystems with a custom or enterprise
  backend.

## Runnable demo

The `demos/08-extensibility/` directory in the repository runs a live
stack for the features in this section; its README covers
prerequisites, test scripts, and teardown.

## Where to go next

- [Architecture: plugins and extensibility](../architecture/plugins-and-extensibility)
  - the internal design of the dispatch chain and the extension
  boundaries.
- [Enterprise and fleet](./enterprise) - the enterprise backends
  (Redis, Vault) are additional implementations of the same extension
  traits.
