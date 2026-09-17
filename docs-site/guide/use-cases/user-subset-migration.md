# Use case: user-subset migration to a new API version

An API ships `/v1/user`. Enhancements land as a **new endpoint**
`/v2/user` — the old one stays untouched. Only a **subset of users**
(entitlements decided by a separate microservice) should be forwarded
to `/v2/user`; everyone else keeps hitting `/v1/user`. The gateway
must consult that decision and rewrite the target per request.

This is the flagship recipe: it contrasts a config-snapshot plugin
with a per-request callout, the same design decision that recurs in
[per-request external decisions](./per-request-external-decisions).

## Why the built-ins are not enough

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| [Traffic splitting](../traffic-splitting) (`services[].split`) | Weighted/canary split across upstreams | Percentage-based, not user-based; splits upstreams, not paths |
| Route `match.headers` + `rewrite` | Header-gated rewrite to `/v2/...` | Match criteria are static config — the decision lives in the microservice |
| [Authorization](../authorization) `allowed_consumers`/`required_claims` | Gate WHO may call a route | Gates access; cannot rewrite the target path |

If the entitlement can be **materialized as a header or JWT claim**
upstream of the gateway (your IdP adds `api_version: v2`), the whole
recipe collapses to config: one route matching `headers:
{ x-api-version: "2" }` with `rewrite: replace_prefix` — no extension
at all. Check that first.

## Options, with tradeoffs

| Option | How | Latency | Freshness of the decision | Works today? |
| --- | --- | --- | --- | --- |
| **A. Entitlement-snapshot plugin** (recommended) | The microservice publishes the allow-list; it lands in the plugin's `config:` block; the plugin rewrites `:path` per request | Zero added (local lookup) | Per config reload (publisher-triggered; seconds) | Yes |
| B. Per-request callout plugin | Plugin calls the microservice (`proxy_http_call`), caches the verdict, rewrites | One hop on cache miss | Per request | Yes — see [HTTP callouts](../plugin-sdk#http-callouts-proxy_http_call) and [per-request external decisions](./per-request-external-decisions) |
| C. Auth-layer header | IdP / edge auth sets a version header; config-only rewrite | Zero | Per token/session | Yes (no extension) |

**Why A over B even though both land:** a per-request hop adds tail
latency and a new failure domain at the edge. An entitlement list
rarely needs sub-second freshness — publish-on-change plus dwara's
hot reload gives you a tight loop with **no per-request dependency**
on the microservice. Keep B for genuinely dynamic verdicts (real-time
quotas, experiments).

## Implementation (Option A)

The plugin runs at the `request_headers` phase (after route
resolution, before authn), reads the user identity, looks it up in
its config snapshot, and rewrites the path prefix. This is the
complete plugin from the
[runnable demo](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/01-user-subset-migration)
(Rust, proxy-wasm 0.2 SDK, built for `wasm32-wasip1`):

```rust
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(MigratorRoot {
            config: MigratorConfig::default(),
        })
    });
}

/// The parsed plugin configuration (the entitlement snapshot).
#[derive(Clone, Default)]
struct MigratorConfig {
    from: String,
    to: String,
    allowed_users: Vec<String>,
}

impl MigratorConfig {
    /// Parse the `config:` JSON. `from`/`to` must be non-empty strings
    /// and `allowed_users` an array of strings; anything else is an
    /// error (fail closed).
    fn parse(bytes: &[u8]) -> Result<MigratorConfig, String> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| format!("config is not valid JSON: {e}"))?;
        let string_field = |name: &str| -> Result<String, String> {
            value
                .get(name)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("missing or empty string field \"{name}\""))
        };
        let users = value
            .get("allowed_users")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "field \"allowed_users\" must be an array of strings".to_string())?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "field \"allowed_users\" must be an array of strings".to_string())
            })
            .collect::<Result<Vec<String>, String>>()?;
        Ok(MigratorConfig {
            from: string_field("from")?,
            to: string_field("to")?,
            allowed_users: users,
        })
    }
}

/// The root context: owns the config snapshot and hands each request
/// its own filter instance.
struct MigratorRoot {
    config: MigratorConfig,
}

impl Context for MigratorRoot {}

impl RootContext for MigratorRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        let bytes = self.get_plugin_configuration().unwrap_or_default();
        match MigratorConfig::parse(&bytes) {
            Ok(config) => {
                self.config = config;
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Info,
                    &format!(
                        "v2-migrator: configured from={} to={} allowed_users={}",
                        self.config.from,
                        self.config.to,
                        self.config.allowed_users.join(",")
                    ),
                );
                true
            }
            Err(error) => {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("v2-migrator: invalid config: {error}"),
                );
                false
            }
        }
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(Migrator {
            config: self.config.clone(),
        }))
    }
}

/// The per-request filter.
struct Migrator {
    config: MigratorConfig,
}

impl Context for Migrator {}

impl HttpContext for Migrator {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let user = self.get_http_request_header("x-user-id").unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();

        if !self.config.allowed_users.is_empty() && path.starts_with(&self.config.from) {
            let migrated = self.config.allowed_users.iter().any(|u| u == &user);
            let new_path = if migrated {
                format!("{}{}", self.config.to, &path[self.config.from.len()..])
            } else {
                path.clone()
            };
            // A CHANGED :path value is the final say for the upstream
            // request; writing the unchanged value back is a no-op.
            self.set_http_request_header(":path", Some(&new_path));
            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!("user={} -> {}", user, new_path),
            );
        }
        Action::Continue
    }
}
```

Semantics: an **empty** allow-list migrates nobody (a safe default
while the publisher is warming up); a user in the list gets the
`from` -> `to` prefix rewrite; everyone else is untouched.

## Configuration

The demo splits the wiring in two on purpose: the main config is the
hand-written topology; the include is machine-written publisher
output carrying the whole `plugins:` block, allow-list and all.

`dwara.yaml` (the hand-written half):

```yaml
listeners:
  - name: migration-http
    address: 127.0.0.1
    port: 8080
    protocol: http

includes:
  - plugins-config/v2-migrator.yaml   # generated by the publisher

routes:
  - name: user-api
    service: user-api-service
    match:
      path: { type: prefix, value: /v1/ }
    action: { type: proxy }
    plugins: [v2-migrator]
  # plugin-less routes take the fast path and are never rewritten

services:
  - name: user-api-service
    upstream: user-api-upstream

upstreams:
  - name: user-api-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000
```

`plugins-config/v2-migrator.yaml` (the generated half the
microservice's publisher writes):

```yaml
plugins:
  - name: v2-migrator
    wasm: ./v2-migrator/target/wasm32-wasip1/release/v2_migrator.wasm
    phases: [request_headers]
    limits: { fuel: 1000000, memory_mb: 32 }
    config: |
      { "from": "/v1/", "to": "/v2/",
        "allowed_users": ["user-42", "user-77", "user-108"] }
```

The route matches `/v1/` only: the plugin's rewrite happens **after**
route resolution and is applied to the forwarded request with no
route re-match, so one route covers both targets.

## Operational notes

1. **Publishing loop**: have the microservice write the generated
   include (or the snippet it includes) and touch the main config;
   the file watcher reloads, the module re-reads `on_configure`, and
   health is preserved (unchanged checksum = no recompile; changed
   config = new generation). A bad JSON blob fails the plugin load
   loudly — routes fail closed with `500 plugin_unavailable` — so
   gate the publisher (validate before writing). A SIGHUP forces the
   same re-read/re-validate/re-publish deterministically on platforms
   whose file-watch rename events are unreliable.
2. **Identity source**: `x-user-id` above; `request_headers` runs
   BEFORE authn by contract, so header/claim-based identity is the
   right input here (or move the decision into the `request_body`
   phase if you need post-authz placement and can accept buffering).
3. **Blast radius**: other routes are untouched; routes without the
   plugin take the allocation-free fast path.
4. **Caching interactions**: a plugin definition change bumps the
   response-cache epochs of every route referencing it, so cached
   pre-change responses are never replayed against the new verdicts.

## Testing

- Unit-test the lookup/rewrite logic as plain Rust (the parse and
  prefix-rewrite functions above are pure).
- Integration-test with the harness pattern from
  [Plugin testing](../plugin-testing).
- Use `dwara replay` to prove config-change neutrality for users
  outside the list.

The runnable demo asserts all of it live: users on and off the list,
unknown identity, the empty-list safe default, hot-reload flips (add
`user-77`, remove `user-42` — the NEXT request changes verdict, no
restart), and the plugin-less control route staying untouched.

## Option B sketch

Same phase; instead of the local lookup, `dispatch_http_call` to the
microservice with a short TTL cache keyed by user and a strict
timeout. Make the fail-open (default `/v1/`) vs fail-closed decision
deliberately: the gateway itself fails a route closed when a callout
cannot COMPLETE (timeout/refused — the plugin never sees an empty
callback), so fail-open needs a fallback the plugin applies without a
callout answer. [Per-request external
decisions](./per-request-external-decisions) is that recipe in full.

## Status

Works today, both options: the snapshot plugin (Option A) on plain
config reload, the callout plugin (Option B) on `proxy_http_call`.
Choose by freshness needs, not availability.

## Runnable demo

[`demos/13-extensibility-usecases/01-user-subset-migration/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/01-user-subset-migration)
runs Option A end to end: the plugin above, a mock entitlement
microservice, the publisher writing the generated include, and the
hot-reload flip asserted live.
