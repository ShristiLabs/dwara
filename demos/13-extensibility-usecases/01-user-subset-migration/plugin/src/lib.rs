//! v2-migrator: route a user subset to the new API version.
//!
//! The flagship recipe from the docs-site "Extension use cases and
//! recipes" page, use case 1, Option A (entitlement-snapshot plugin):
//! an API ships `/v1/user`, enhancements land as `/v2/user`, and only
//! a subset of users -- the entitlement allow-list published by a
//! separate microservice -- should be forwarded to `/v2/user`.
//! Everyone else keeps hitting `/v1/user`.
//!
//! The plugin runs at the `request_headers` phase (after route
//! resolution, before authn), reads the user identity from
//! `x-user-id`, looks it up in its config snapshot, and rewrites the
//! path prefix for migrated users only:
//!
//! - the allow-list is EMPTY: nobody migrates (a safe default while
//!   the publisher is warming up);
//! - the allow-list is non-empty and the user is in it: the target
//!   path is rewritten `from` -> `to`;
//! - the user is absent or unknown: the path is untouched.
//!
//! The config snapshot arrives as the plugin's `config:` block (JSON),
//! parsed once at `proxy_on_configure`. The entitlement microservice
//! publishes the list into that block (see ../services/publish.sh);
//! a dwara hot reload re-runs `on_configure` with the fresh bytes --
//! the module itself is unchanged, so its checksum (and health) are
//! preserved across publishes.
//!
//! Config shape (matching the documented sample):
//!
//! ```json
//! { "from": "/v1/", "to": "/v2/", "allowed_users": ["user-42"] }
//! ```
//!
//! Fail-closed semantics: config JSON that does not parse makes
//! `on_configure` return false, so the gateway marks the plugin
//! broken and routes referencing it answer 500 `plugin_unavailable`
//! rather than running with a guessed allow-list.

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
                let _ =
                    proxy_wasm::hostcalls::log(LogLevel::Error, &format!("v2-migrator: invalid config: {error}"));
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

/// The per-request filter: the documented sample's semantics, verbatim.
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
            // The documented sample's rewrite, applied by the host: a
            // CHANGED :path value is the final say for the upstream
            // request (it composes after the route's own rewrite; see
            // the "Header conventions" note in
            // crates/dwara-core/src/dataplane/plugin_dispatch.rs).
            // Writing the unchanged value back (the not-migrated case)
            // is a documented no-op.
            self.set_http_request_header(":path", Some(&new_path));
            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!("user={} -> {}", user, new_path),
            );
        }
        Action::Continue
    }
}
