//! Plugin scaffolding (DW-057).
//!
//! `dwara plugin new` generates a new proxy-wasm plugin project from a
//! template: a Rust crate targeting `wasm32-wasip1` that implements the
//! proxy-wasm ABI and hooks dwara's phase contract.
//!
//! The default scaffold includes:
//! - `Cargo.toml` (targeting `wasm32-wasip1`, depending on `proxy-wasm`)
//! - `src/lib.rs` (a minimal proxy-wasm filter with the phase callbacks)
//! - `dwara.yaml` (a minimal gateway config that loads the plugin)
//! - `README.md` (build + run instructions)
//!
//! DW-166 (#284): `--template <name>` scaffolds from one of the four
//! example plugins instead (see [`crate::plugin_templates`]): the
//! example's source is vendored with the crate name substituted, so
//! the scaffolded project carries the example's tests (host-runnable
//! via the fake host in `src/abi.rs`) and builds with zero
//! dependencies.
//!
//! ## Done-when
//!
//! New plugin from scaffold to running < 30 min documented.

use std::path::Path;

/// The scaffold result.
#[derive(Debug)]
pub struct ScaffoldResult {
    /// The directory the scaffold was created in.
    pub dir: String,
    /// The plugin name.
    pub name: String,
    /// The files created.
    pub files: Vec<String>,
}

/// Create a new plugin scaffold in the given directory.
///
/// `name` is the plugin name (used for the crate name and the
/// directory). `dir` is the parent directory; the scaffold is created
/// in `dir/<name>/`. `template` names an example plugin to scaffold
/// from ([`crate::plugin_templates`]); `None` is the hello-world
/// default.
pub fn scaffold(name: &str, dir: &str, template: Option<&str>) -> Result<ScaffoldResult, String> {
    validate_name(name)?;

    let plugin_dir = Path::new(dir).join(name);

    if plugin_dir.exists() {
        return Err(format!("directory {} already exists", plugin_dir.display()));
    }

    // (relative path, contents) pairs; parent directories are created
    // per file so the two branches share one writer.
    let files: Vec<(String, String)> = match template {
        Some(t) => {
            let template = crate::plugin_templates::find(t)?;
            crate::plugin_templates::render_files(template, name)
        }
        None => vec![
            ("Cargo.toml".to_string(), cargo_toml(name)),
            ("src/lib.rs".to_string(), lib_rs()),
            ("dwara.yaml".to_string(), dwara_yaml(name)),
            ("README.md".to_string(), readme(name)),
            (".gitignore".to_string(), gitignore()),
        ],
    };

    let mut written = Vec::new();
    for (rel, contents) in &files {
        let path = plugin_dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        write_file(&path, contents)?;
        written.push(path.display().to_string());
    }

    Ok(ScaffoldResult {
        dir: plugin_dir.display().to_string(),
        name: name.to_string(),
        files: written,
    })
}

/// Validate a plugin name: must be a valid Rust crate name.
fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("plugin name cannot be empty".to_string());
    }

    if name.len() > 64 {
        return Err("plugin name cannot be longer than 64 characters".to_string());
    }

    // Must be a valid Rust identifier: letters, digits, underscores,
    // hyphens; must start with a letter or underscore.
    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(format!(
            "plugin name must start with a letter or underscore, got '{first}'"
        ));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "plugin name can only contain letters, digits, underscores, and hyphens".to_string(),
        );
    }

    Ok(())
}

fn write_file(path: &Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn cargo_toml(name: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
description = "A proxy-wasm plugin for the dwara gateway"
license = "Apache-2.0"

[lib]
crate-type = ["cdylib"]

[dependencies]
proxy-wasm = "0.2"

[profile.release]
opt-level = "s"
lto = true
strip = true
"#,
        name = name
    )
}

fn lib_rs() -> String {
    r#"//! A minimal proxy-wasm plugin scaffold for the dwara gateway.
//!
//! This plugin logs the request path at the `request_headers` phase
//! and passes the request through. Edit the phase callbacks below to
//! implement your custom logic.
//!
//! ## Phase contract (dwara section 9.3)
//!
//! dwara calls plugin phase callbacks at defined points:
//! - `request_headers` -- after route resolution, before authn.
//! - `request_body` -- after authn/authz/rate-limit, before upstream.
//! - `response_headers` -- after the upstream responds, before masking.
//! - `response_body` -- after masking, before compression.
//!
//! A plugin can short-circuit the request by calling
//! `send_http_response` (returns a local response instead of
//! forwarding to the upstream).

use proxy_wasm::traits::*;
use proxy_wasm::types::*;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(MyPluginRoot)
    });
}

struct MyPluginRoot;

impl Context for MyPluginRoot {}

impl RootContext for MyPluginRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(MyPluginHttp))
    }
}

struct MyPluginHttp;

impl Context for MyPluginHttp {}

impl HttpContext for MyPluginHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let _ = proxy_wasm::hostcalls::log(LogLevel::Info, &format!("request path: {}", path));
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        Action::Continue
    }
}
"#
    .to_string()
}

fn dwara_yaml(name: &str) -> String {
    format!(
        r#"# A minimal gateway config that loads the plugin. It validates
# as generated: `dwara-cli validate dwara.yaml` passes before the
# .wasm exists (validation does not check file existence).
listeners:
  - name: http
    address: 127.0.0.1
    port: 8080
    protocol: http

routes:
  - name: api
    service: backend
    match:
      path:
        type: prefix
        value: /api
    action:
      type: proxy
    plugins:
      - {name}

services:
  - name: backend
    upstream: backend-upstream

upstreams:
  - name: backend-upstream
    load_balancer: round_robin
    protocol: http1
    endpoints:
      - address: 127.0.0.1
        port: 9000

plugins:
  - name: {name}
    wasm: target/wasm32-wasip1/release/{name}.wasm
    phases:
      - request_headers
      - response_headers
"#,
        name = name
    )
}

fn readme(name: &str) -> String {
    format!(
        r#"# {name}

A proxy-wasm plugin for the [dwara](https://github.com/shristilabs/dwara) gateway.

## Build

Install the wasm32-wasip1 target:

```sh
rustup target add wasm32-wasip1
```

Build the plugin:

```sh
cargo build --release --target wasm32-wasip1
```

The compiled `.wasm` file is at
`target/wasm32-wasip1/release/{name}.wasm`.

## Run

The included `dwara.yaml` is a complete, valid gateway config (verify
with `dwara-cli validate dwara.yaml`). Start the gateway with it (the
binary reads its config from `DWARA_CONFIG`, defaulting to
`./dwara.yaml` — run from this directory):

```sh
DWARA_CONFIG=dwara.yaml dwara
```

Or, if running from the dwara source tree:

```sh
DWARA_CONFIG=dwara.yaml cargo run -p dwara-bin
```

The gateway listens on `127.0.0.1:8080` and forwards `/api` requests
to `127.0.0.1:9000`. The plugin logs the request path at the
`request_headers` phase.

## Phase contract

dwara calls plugin phase callbacks at defined points (section 9.3):

1. `request_headers` -- after route resolution, before authn.
2. `request_body` -- after authn/authz/rate-limit, before upstream.
3. `response_headers` -- after the upstream responds, before masking.
4. `response_body` -- after masking, before compression.

Edit `src/lib.rs` to implement your custom logic at any of these
phases. A plugin can short-circuit the request by calling
`send_http_response` (returns a local response instead of forwarding
to the upstream).

## Plugin config

The plugin's `config` field in `dwara.yaml` is passed to the plugin's
`on_configure` callback as a byte string. Parse it as JSON or YAML in
your plugin.

## Testing

See the dwara documentation for the plugin test harness and the phase
contract conformance suite.
"#,
        name = name
    )
}

fn gitignore() -> String {
    "/target\n".to_string()
}
