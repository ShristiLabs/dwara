# Use case: response PII redaction at the edge

An upstream leaks card numbers and API keys into JSON response
bodies; compliance wants them masked before clients see them. You
control the gateway, not the upstream, and the fix at the source is
weeks away.

## Why the built-ins are not enough

| Built-in | What it does | Why it does not fit |
| --- | --- | --- |
| [Response field masking](../masking) (`routes[].masking`) | Replaces named JSON-pointer fields with the `***` sentinel, per consumer group | Field-shaped: you must know WHERE the value lives. Cannot mask a card number that appears anywhere in free text, or in bodies whose shape you do not control |
| [Transforms](../transforms) | Structural request/response rewrites (rewrite, remove, inject) | Operate on named fields/headers, not byte patterns |
| [WAF-lite](../waf-lite) | Pattern blocking on inbound requests | Request side only; it blocks, never rewrites response bodies |

If every leak is a known field at a known pointer, use masking — it
is config, it is fail-closed, and it is per-consumer-group. A plugin
is for pattern-shaped leaks (a Luhn-valid digit run anywhere in the
body, a literal key scattered through text).

## Options, with tradeoffs

| Option | How | Coverage | Cost | Works today? |
| --- | --- | --- | --- | --- |
| **A. Response-body plugin** (recommended) | proxy-wasm plugin at `response_body` scans and masks the buffered body | Any buffered body, any shape | One body copy + scan per response | Yes — the shipped [`response-body-redact`](https://github.com/shristilabs/dwara/tree/main/plugins/examples/response-body-redact) example is exactly this |
| B. Fix the upstream | The service stops emitting the values | Complete | Weeks, someone else's queue | Always the real fix |
| C. Field masking | `routes[].masking` on known pointers | Known fields only | Config only | Yes — no extension |

Masking at the gateway is a **seatbelt, not a fix**: run A (or C)
while B lands. Never treat the plugin as permission to keep leaking.

## Implementation

The shipped example IS the surface:
[`plugins/examples/response-body-redact`](https://github.com/shristilabs/dwara/tree/main/plugins/examples/response-body-redact).
Two pattern classes, both length-preserving (a masked body has the
same byte length as the original, so framing never shifts):

- **Card numbers**: a run of 13-19 digits (single `-` or ` `
  separators between groups allowed) that passes the Luhn checksum.
  Every digit except the last four becomes `*`; separators are kept
  (`4111-1111-1111-1111` -> `****-****-****-1111`). The checksum gate
  keeps ordinary 16-digit ids (order numbers, tracking codes)
  readable.
- **Configured literals**: each occurrence of a configured string is
  replaced with `*` repeated to the same length (`sk-live-12345`
  becomes `************`).

The core logic (from the example's `src/lib.rs`; the crate carries
its own hand-written ABI shim — see the example's `abi.rs`):

```rust
/// How many trailing card digits stay visible.
const KEEP_LAST: usize = 4;

/// The pure redaction pass: configured literals first, then card
/// masking. Returns the redacted bytes; the input is returned
/// unchanged when nothing matched.
pub fn redact(body: &[u8], config: &RedactConfig) -> Vec<u8> {
    let mut out = body.to_vec();
    for literal in &config.literals {
        replace_literal(&mut out, literal.as_bytes());
    }
    mask_card_numbers(&mut out);
    out
}

/// Replace every non-overlapping occurrence of `literal` with `*`
/// repeated to the same length (length-preserving).
pub fn replace_literal(body: &mut Vec<u8>, literal: &[u8]) {
    if literal.is_empty() || body.len() < literal.len() {
        return;
    }
    let mut i = 0;
    while i + literal.len() <= body.len() {
        if &body[i..i + literal.len()] == literal {
            for byte in &mut body[i..i + literal.len()] {
                *byte = b'*';
            }
            i += literal.len();
        } else {
            i += 1;
        }
    }
}

/// Mask Luhn-valid 13-19 digit runs, keeping the last four digits.
/// Runs are treated whole: a run that is too long, too short, or
/// checksum-invalid passes through untouched.
pub fn mask_card_numbers(body: &mut Vec<u8>) {
    let len = body.len();
    let mut i = 0;
    while i < len {
        if !body[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut digit_positions: Vec<usize> = Vec::new();
        let mut digits: Vec<u8> = Vec::new();
        let mut j = i;
        while j < len && body[j].is_ascii_digit() {
            digit_positions.push(j);
            digits.push(body[j]);
            j += 1;
            if j < len
                && (body[j] == b'-' || body[j] == b' ')
                && j + 1 < len
                && body[j + 1].is_ascii_digit()
            {
                j += 1;
            }
        }
        if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
            let keep_from = digits.len() - KEEP_LAST;
            for (index, &pos) in digit_positions.iter().enumerate() {
                if index < keep_from {
                    body[pos] = b'*';
                }
            }
        }
        i = j;
    }
}

/// The Luhn checksum (ISO/IEC 7812-1): every second digit from the
/// right is doubled (9 subtracted on overflow) and the sum must be a
/// multiple of ten.
pub fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum: u32 = 0;
    for (offset, digit) in digits.iter().rev().enumerate() {
        if !digit.is_ascii_digit() {
            return false;
        }
        let mut value = u32::from(digit - b'0');
        if offset % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    sum % 10 == 0
}
```

The phase shim is minimal — parse config at `on_configure` (returning
failure on a bad config, so routes fail closed instead of serving
unredacted bytes), redact the buffered body at `on_response_body`,
write it back only when something changed:

```rust
pub extern "C" fn proxy_on_response_body(
    _context_id: i32,
    body_size: i32,
    _end_of_stream: i32,
) -> i32 {
    let config = ROOT.lock().unwrap().as_ref()
        .map(|root| root.config.clone())
        .unwrap_or_default();
    let Some(body) = abi::get_buffer(abi::BUFFER_RESPONSE_BODY, 0, body_size) else {
        return abi::ACTION_CONTINUE;
    };
    let redacted = redact(&body, &config);
    if redacted != body {
        abi::set_buffer(abi::BUFFER_RESPONSE_BODY, 0, &redacted);
    }
    abi::ACTION_CONTINUE
}
```

## Configuration

Config is the `config:` string on the plugin entry; `literals` is
optional and card masking is always on:

```yaml
plugins:
  - name: response-body-redact
    wasm: plugins/examples/response-body-redact/target/wasm32-wasip1/release/response_body_redact.wasm
    phases: [response_body]
    config: '{"literals":["sk-live-12345"]}'

routes:
  - name: leaky-api
    service: leaky-service
    match: { path: { type: prefix, value: /api/ } }
    action: { type: proxy }
    plugins: [response-body-redact]
```

## Operational notes

1. **Body phases see buffered bodies only**: the route buffers up to
   `limits.max_body_bytes` (default 1 MiB) when a `response_body`
   plugin is declared; an over-cap body answers 500
   `plugin_body_too_large`. Streaming bodies (`text/event-stream`,
   unframed) and content-encoded bodies **skip the phase and are
   logged** — they stream through untouched. The demo proves this
   carve-out live: the same leak over SSE is NOT masked.
2. **Hot reload**: changed literals are a config reload; the module
   checksum is unchanged so plugin health is preserved.
3. **Caching interactions**: `Content-Length` is rewritten when the
   plugin changes the body (the transform is length-preserving by
   design, so this is defensive, not expected); a plugin definition
   change bumps the response-cache epochs of referencing routes.
4. **Cost**: one body copy plus the scan per buffered response;
   header phases are not involved.

## Testing

The example crate ships unit tests for the pure logic
(`tests/logic.rs`) and host-side callback tests (`tests/callbacks.rs`)
— the pattern [Plugin testing](../plugin-testing) documents. The
runnable demo below asserts the end-to-end behavior.

## Status

Works today, in every build (no cargo features).

## Runnable demo

[`demos/13-extensibility-usecases/02-response-pii-redaction/`](https://github.com/shristilabs/dwara/tree/main/demos/13-extensibility-usecases/02-response-pii-redaction)
builds the shipped example by path against a mock leaky upstream:
Luhn-gated keep-last-4 masking, the innocent 16-digit reference
untouched, the configured literal starred, and the SSE route skipping
the phase.
