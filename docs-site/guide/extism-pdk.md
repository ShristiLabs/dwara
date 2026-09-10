# Extism plugin development kit

> **Status: Not implemented.** The Extism PDK runtime scaffold was
> removed from the codebase (issue #259). The gateway supports
> [Proxy-Wasm](./proxy-wasm-plugins) and [native filters](./native-plugins)
> for plugin development. Extism support may be re-introduced in a
> future milestone if there is demand.

Dwara previously scaffolded a third plugin implementation path
alongside Proxy-Wasm and native filters: plugins written against the
[Extism](https://extism.org/) Plugin Development Kit (PDK). The
scaffold types were compiled but never wired into the dispatch chain,
config schema, or runtime -- the actual Extism host calls were
no-ops. Rather than ship dead code, the scaffold was removed.

If Extism support is re-introduced, it would allow plugins written in
any language with an Extism PDK SDK (Rust, Go, Python, JavaScript,
etc.) to be registered alongside native and WASM plugins in the
unified dispatch chain.
