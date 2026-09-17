# Use case: custom request authentication

A proprietary token scheme — not JWT, not API keys, not any standard
the gateway speaks — must be verified per request before the upstream
is dialed, with a proper `401` + `WWW-Authenticate` challenge on
failure.

## Why the built-ins are not enough

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| [API keys](../authentication-methods) | Hashed key store, per-consumer credentials | The scheme is not a plain shared key |
| [JWT/JWKS](../authentication-methods) | Signature + claims validation | The token is not a JWT |
| [HMAC signing](../hmac-signing) | Signed requests with timestamp/nonces | The scheme is not HMAC over the request |
| [OIDC introspection](../oidc) | Delegated verification against an IdP | There is no IdP; the verifier is your own logic |

A plugin is for schemes only you speak. If your scheme can be
expressed as any of the above, use the built-in — zero code, zero
module to operate.

## Options, with tradeoffs

| Option | How | Verification lives | Failure shape | Works today? |
| --- | --- | --- | --- | --- |
| **A. `request_headers` plugin** (recommended) | Plugin validates the credential and short-circuits 401 via `send_http_response` | Your module, at the edge, pre-upstream | Your status/headers/body, upstream never dialed | Yes — the shipped [`static-auth`](https://github.com/shristilabs/dwara/tree/main/plugins/examples/static-auth) example is the skeleton |
| B. Auth callout plugin | Plugin verifies via `proxy_http_call` to your auth service | A service you run | Callout timeout fails the route closed | Yes — see [per-request external decisions](./per-request-external-decisions) |
| C. Built-in auth | Whatever standard scheme fits | The gateway | Standard 401s | Yes, when the scheme is standard |

A over B when verification is local (a shared secret, a signature you
can check offline): no hop, no new failure domain. B when only a
service can decide (revocation lists, device checks).

## Implementation

The shipped example IS the skeleton:
[`plugins/examples/static-auth`](https://github.com/shristilabs/dwara/tree/main/plugins/examples/static-auth).
It gates a route behind a configured bearer-style token; anything
else is answered 401 with a `WWW-Authenticate` challenge by the
plugin itself (the upstream is never dialed).

The decision core — pure functions, unit-testable without a gateway:

```rust
/// The decision for one request.
pub enum AuthDecision {
    Allow,
    DenyMissing, // no credential presented
    DenyInvalid, // a credential was presented but is wrong
}

/// The pure decision function.
pub fn evaluate(config: &AuthConfig, presented: Option<&str>) -> AuthDecision {
    let Some(raw) = presented.filter(|v| !v.is_empty()) else {
        return AuthDecision::DenyMissing;
    };
    let candidate = match &config.scheme {
        Some(scheme) => match strip_scheme(raw, scheme) {
            Some(rest) => rest,
            None => return AuthDecision::DenyInvalid,
        },
        None => raw,
    };
    if constant_time_eq(candidate.as_bytes(), config.token.as_bytes()) {
        AuthDecision::Allow
    } else {
        AuthDecision::DenyInvalid
    }
}

/// Strip a `"<scheme> <credentials>"` prefix (the Authorization header
/// shape). The scheme match is ASCII case-insensitive, per RFC 7235.
pub fn strip_scheme<'v>(value: &'v str, scheme: &str) -> Option<&'v str> {
    let (head, rest) = value.split_once(' ')?;
    if !head.eq_ignore_ascii_case(scheme) {
        return None;
    }
    let rest = rest.trim_start();
    if rest.is_empty() { None } else { Some(rest) }
}

/// Constant-time byte-slice equality: the fold walks max(a.len(),
/// b.len()) bytes, so the running time does not depend on where the
/// first difference occurs. Length differences still leak (token
/// length is not secret).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..len {
        let byte_a = if i < a.len() { a[i] } else { 0 };
        let byte_b = if i < b.len() { b[i] } else { 0 };
        diff |= usize::from(byte_a ^ byte_b);
    }
    diff == 0
}
```

The phase shim at `request_headers` (after route resolution, before
authn) — short-circuit on deny, continue on allow:

```rust
pub extern "C" fn proxy_on_request_headers(
    _context_id: i32,
    _num_headers: i32,
    _end_of_stream: i32,
) -> i32 {
    let guard = ROOT.lock().unwrap();
    let Some(root) = guard.as_ref() else {
        let headers = challenge_headers();
        abi::send_http_response(401, &headers, &deny_body(AuthDecision::DenyMissing));
        return abi::ACTION_END_STREAM;
    };
    let presented = abi::get_request_header(&root.config.header);
    match evaluate(&root.config, presented.as_deref()) {
        AuthDecision::Allow => abi::ACTION_CONTINUE,
        denial => {
            let headers = challenge_headers();
            abi::send_http_response(401, &headers, &deny_body(denial));
            abi::ACTION_END_STREAM
        }
    }
}
```

Config parsing is fail-closed: a missing/empty/unparsable `config:`
makes `proxy_on_configure` return false, the plugin is marked broken,
and routes referencing it answer `500 plugin_unavailable` rather than
running unauthenticated.

## Configuration

Config (parsed at `on_configure`): `header` and `token` are required,
`scheme` is optional — with `"Bearer"`, the presented value must be
`Bearer <token>`; without one, the raw header value is compared.

```yaml
plugins:
  - name: static-auth
    wasm: plugins/examples/static-auth/target/wasm32-wasip1/release/static_auth.wasm
    phases: [request_headers]
    config: '{"header":"authorization","scheme":"Bearer","token":"dwara-demo-secret"}'

routes:
  - name: protected-api
    service: protected-service
    match: { path: { type: prefix, value: /protected/ } }
    action: { type: proxy }
    plugins: [static-auth]

  - name: public-api          # sibling control route: no plugin
    service: protected-service
    match: { path: { type: prefix, value: /public/ } }
    action: { type: proxy }
```

In a real deployment, source the token from a secret reference rather
than a literal — and see the operational notes on rotation.

## Operational notes

1. **Secret rotation is a plugin-config reload**: change the `config:`
   string and reload; never bake long-lived secrets into the module
   bytes (a compiled-in secret means re-publishing the artifact on
   every rotation and leaks through any copy of the `.wasm`).
2. **Placement**: `request_headers` runs before authn by contract, so
   the plugin can also lean on the built-ins behind it — a plugin that
   only decodes/normalizes a proprietary credential into a standard
   header, letting [authorization](../authorization) do the gating, is
   a smaller module than one that owns verification.
3. **Failure behavior**: wrong/missing credentials short-circuit 401
   (no upstream dial, no latency beyond the compare); a broken plugin
   fails the route closed with `500 plugin_unavailable`.
4. **Limits**: header phases are zero-copy fast, no body buffering;
   sandbox limits (`fuel`, `memory_mb`) bound the module.

## Testing

The example ships `tests/logic.rs` (pure decisions, scheme stripping,
constant-time compare) and `tests/callbacks.rs` (host-side callback
tests against a fake host) — the levels [Plugin
testing](../plugin-testing) documents. The demo asserts the wire
behavior end to end.

## Status

Works today, in every build.

## Runnable demo

[`demos/13-extensibility-usecases/03-custom-auth/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/03-custom-auth)
builds the shipped example by path: 401 + `WWW-Authenticate` on
missing, wrong, and wrong-scheme credentials (no upstream dial); the
correct token forwarded; the sibling unprotected route unaffected.
