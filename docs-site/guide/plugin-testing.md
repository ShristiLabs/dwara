# Plugin testing

Plugins deserve the same testing discipline as the gateway itself:
unit tests while you write them, integration tests through a real
gateway before you ship them, and regression gates so later changes
(config or code) cannot silently alter what a plugin does to traffic.

This guide walks the three levels in order of cost, using the
[example plugin gallery](https://github.com/shristilabs/dwara/tree/main/plugins/examples)
in the dwara repository as the runnable reference. Every command below
runs as written against a checkout of the repo.

| Level | Runs | Catches | Cost |
|---|---|---|---|
| 1. Unit tests | plain Rust, no gateway, no wasm | logic bugs, config parsing, fail-closed defaults | milliseconds |
| 2. Gateway integration | real gateway + real wasm modules | ABI/wiring mistakes, phase semantics, fail-closed behavior | seconds |
| 3. Replay regression | offline decision re-run | config changes that shift routing decisions | seconds |

## Level 1: unit tests (no gateway)

Write the plugin so the interesting logic is plain Rust and the
proxy-wasm callbacks are thin shims over it. Every example in the
gallery follows the same split:

- `src/lib.rs` holds a `RootContext` (config parsed at
  `proxy_on_configure`) and/or an `HttpContext` (per-request state),
  and pure functions that make decisions: `evaluate(config, presented)
  -> Verdict`, `redact(body, config) -> Vec<u8>`, and so on.
- `src/abi.rs` is the proxy-wasm binding layer. On wasm targets it
  calls the real host imports; on every other target it compiles an
  in-memory **fake host**, so `cargo test` on your laptop can drive
  the plugin's actual `proxy_on_*` exports and observe what the
  plugin would have done (local response sent, headers added, body
  written back).

Run the unit tests of any example:

```sh
cd plugins/examples/static-auth
cargo test
```

The decision logic tests are ordinary Rust tests:

```rust
use static_auth::{evaluate, AuthConfig, AuthDecision};

#[test]
fn wrong_token_denies_invalid() {
    let config = AuthConfig::parse(
        br#"{"header":"authorization","scheme":"Bearer","token":"s3cr3t"}"#,
    ).expect("valid config parses");
    assert_eq!(
        evaluate(&config, Some("Bearer wrong")),
        AuthDecision::DenyInvalid
    );
}
```

The callback tests go one step further and exercise the real entry
points against the fake host (`tests/callbacks.rs` in `static-auth`
and `response-body-redact`; excerpt):

```rust
use static_auth::{
    abi::{fake, ACTION_CONTINUE, ACTION_END_STREAM},
    proxy_on_configure, proxy_on_request_headers, test_reset,
};

const CONFIG: &[u8] = br#"{"header":"authorization","scheme":"Bearer","token":"s3cr3t"}"#;

#[test]
fn callback_scenarios() {
    test_reset();
    fake::set_config(CONFIG);
    assert_eq!(proxy_on_configure(1, CONFIG.len() as i32), 1);

    fake::set_request_headers(&[("authorization", "Bearer s3cr3t")]);
    assert_eq!(proxy_on_request_headers(2, 1, 1), ACTION_CONTINUE);

    fake::set_request_headers(&[]); // no credential
    assert_eq!(proxy_on_request_headers(2, 0, 1), ACTION_END_STREAM);
    let response = fake::take_local_response().expect("missing credential must 401");
    assert_eq!(response.status, 401);
}
```

What to cover at this level:

- Every decision branch (allow/deny, redacted/not-redacted), including
  boundary values (empty header, wrong scheme, 13/19-digit runs).
- Config parsing: valid configs, missing fields, wrong types. A
  plugin that cannot parse its config must fail closed (return 0 from
  `proxy_on_configure`), and that behavior deserves its own test.
- Idempotence and length-preservation for body rewrites.

## Level 2: integration through a real gateway

Unit tests cannot catch ABI mistakes, wrong phase declarations, or
misread phase semantics (a `response_body` plugin that quietly never
runs because the response streams, for example). That is what the
example harness is for. From the repository root:

```sh
bash plugins/examples/run-all.sh
```

The harness builds every example (host tests plus wasm32-wasip1
release artifacts), starts a real gateway with
`plugins/examples/gateway.yaml` and a minimal echo upstream, runs each
example's `assert.sh` against the live gateway, and tears everything
down. Each `assert.sh` is plain curl and runs standalone against any
gateway that wires the plugin:

```sh
bash plugins/examples/static-auth/assert.sh http://127.0.0.1:18101
```

When you wire your own, copy the same shape. The two moving parts are
a top-level `plugins:` entry and a route that references it:

```yaml
plugins:
  - name: static-auth
    wasm: path/to/static_auth.wasm
    phases:
      - request_headers
    config: '{"header":"authorization","scheme":"Bearer","token":"..."}'

routes:
  - name: gated
    service: echo-service
    match:
      path:
        type: prefix
        value: /gated/
    action:
      type: proxy
    plugins:
      - static-auth
```

Beyond the happy path, always assert the failure semantics, because
they are the part your incident review will care about:

- **Short-circuits do not dial the upstream.** Assert the denial
  status and body, and where possible that the upstream saw no request
  (the harness echo upstream makes this visible).
- **Broken plugins fail closed.** Point `wasm:` at a missing or
  garbage file and assert the route answers `500 plugin_unavailable`
  rather than serving unguarded traffic.
- **Phase skip conditions.** A `response_body` plugin is skipped for
  streaming (`text/event-stream`, un-framed) and content-encoded
  bodies; assert such routes stream through intact instead of hanging.
- **Body caps.** A body-phase plugin on a route buffers up to the
  route's `limits.max_body_bytes` (default 1 MiB); an over-cap body
  answers `500 plugin_body_too_large`.

Inside the repository, integration tests can do the same without
scripts: `crates/dwara-core/tests/proxy_plugins.rs` spawns the real
request path (`proxy::handle`) against in-process backends and runs
proxy-wasm plugins compiled at test time, covering all of the cases
above. Copy its fixtures when you add gateway-side behavior.

## Level 3: replay regression

The replay CLI re-runs the gateway's decision path -- route match,
authz, rate-limit verdicts, transforms, upstream selection -- for a
recorded set of requests against a candidate config, entirely offline,
and diffs the decisions. Exit code 0 means no decision differences, 1
means differences were found (usable as a CI gate), 2 means the
recording or a config failed to load.

```sh
dwara-cli replay --recording requests.json --config candidate.yaml
```

A recording is a JSON document (exported from the analytics store, or
authored by hand for fixtures): a baseline config plus the captured
requests:

```json
{
  "baseline_config": "<baseline YAML as a JSON string>",
  "requests": [
    {
      "method": "GET",
      "path": "/guard/data",
      "headers": [["x-guard-key", "open-sesame"]],
      "timestamp_ms": 1700000000000
    }
  ]
}
```

For plugin rollouts the replay question is **config-change
neutrality**: changing a plugin's `config` bytes, its `.wasm` artifact,
or adding a plugin to a route must not shift any routing decision for
existing traffic. Capture a recording under the current config, replay
it against the candidate config, and require exit 0:

```sh
dwara-cli replay --recording capture.json --config with-new-plugin-config.yaml
echo $?   # 0 = the plugin change is routing-neutral
```

A non-zero exit names the request and the stage that changed (route
match, authz verdict, upstream pick) before the change ships.

::: warning Replay does not execute plugins
Replay re-runs the decision path offline; plugin code does not run,
so plugin *behavior* changes (what your wasm does to headers or
bodies) are invisible to it. Replay guards the config's routing
surface; level 2 guards plugin behavior. Use both.
:::

## Putting it together

- While writing the plugin: level 1 after every edit
  (`cargo test`).
- Before shipping a plugin or a plugin config change: level 2 against
  a real gateway (copy `run-all.sh`), including the fail-closed
  cases.
- Before shipping any gateway config change that touches plugin
  wiring: level 3 (`dwara-cli replay ... --config ...`) as a CI gate,
  requiring exit 0 against a captured recording.

## Author CI

The levels above are what the registry's author CI template runs on
every push and tag. Copy
[`templates/plugin-ci.yml`](https://github.com/shristilabs/dwara-plugins/blob/main/templates/plugin-ci.yml)
from the [plugin registry repository](https://github.com/shristilabs/dwara-plugins)
into your plugin's `.github/workflows/`: it builds for
`wasm32-wasip1`, runs the host tests, prints the artifact's SHA-256
digest, and — on a tag — generates the registry manifest entry with
`dwara-cli plugin publish` and opens the registry PR. The registry's
[Author CI](https://github.com/shristilabs/dwara-plugins#author-ci)
notes cover the two repository secrets the publish step needs.
