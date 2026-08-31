//! Plugin scaffolding (DW-057).
//!
//! `dwara plugin new` generates a new proxy-wasm plugin project from a
//! template: a Rust crate targeting `wasm32-wasip1` that implements the
//! proxy-wasm ABI and hooks dwara's phase contract.
//!
//! The scaffold includes:
//! - `Cargo.toml` (targeting `wasm32-wasip1`, depending on `proxy-wasm`)
//! - `src/lib.rs` (a minimal proxy-wasm filter with the phase callbacks)
//! - `dwara.yaml` (a minimal gateway config that loads the plugin)
//! - `README.md` (build + run instructions)
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
/// in `dir/<name>/`.
pub fn scaffold(name: &str, dir: &str) -> Result<ScaffoldResult, String> {
    validate_name(name)?;

    let plugin_dir = Path::new(dir).join(name);
    let src_dir = plugin_dir.join("src");

    if plugin_dir.exists() {
        return Err(format!("directory {} already exists", plugin_dir.display()));
    }

    std::fs::create_dir_all(&src_dir)
        .map_err(|e| format!("cannot create {}: {e}", plugin_dir.display()))?;

    let mut files = Vec::new();

    // Cargo.toml
    let cargo_toml = cargo_toml(name);
    let path = plugin_dir.join("Cargo.toml");
    write_file(&path, &cargo_toml)?;
    files.push(path.display().to_string());

    // src/lib.rs
    let lib_rs = lib_rs();
    let path = src_dir.join("lib.rs");
    write_file(&path, &lib_rs)?;
    files.push(path.display().to_string());

    // dwara.yaml
    let dwara_yaml = dwara_yaml(name);
    let path = plugin_dir.join("dwara.yaml");
    write_file(&path, &dwara_yaml)?;
    files.push(path.display().to_string());

    // README.md
    let readme = readme(name);
    let path = plugin_dir.join("README.md");
    write_file(&path, &readme)?;
    files.push(path.display().to_string());

    // .gitignore
    let gitignore = gitignore();
    let path = plugin_dir.join(".gitignore");
    write_file(&path, &gitignore)?;
    files.push(path.display().to_string());

    Ok(ScaffoldResult {
        dir: plugin_dir.display().to_string(),
        name: name.to_string(),
        files,
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
pub fn _start() {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {{
        Box::new(MyPluginRoot)
    }});
}}

struct MyPluginRoot;

impl Context for MyPluginRoot {{}}

impl RootContext for MyPluginRoot {{
    fn on_configure(&mut self, _config_size: usize) -> bool {{
        true
    }}

    fn get_type(&self) -> Option<ContextType> {{
        Some(ContextType::HttpContext)
    }}

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {{
        Some(Box::new(MyPluginHttp))
    }}
}}

struct MyPluginHttp;

impl Context for MyPluginHttp {{}}

impl HttpContext for MyPluginHttp {{
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {{
        let path = self.get_http_request_header(":path").unwrap_or_default();
        self.log(LogLevel::Info, &format!("request path: {{}}", path));
        Action::Continue
    }}

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {{
        Action::Continue
    }}
}}
"#
    .to_string()
}

fn dwara_yaml(name: &str) -> String {
    format!(
        r#"listeners:
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
        value: /
    action:
      proxy: {{}}
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

Start the dwara gateway with the included config:

```sh
dwara run --config dwara.yaml
```

Or, if running from the dwara source tree:

```sh
cargo run -p dwara-bin -- run --config dwara.yaml
```

The gateway listens on `127.0.0.1:8080` and forwards requests to
`127.0.0.1:9000`. The plugin logs the request path at the
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
