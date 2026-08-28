# Response field masking (DW-029)

> Implements issue DW-029 (M2, feature analysis 5-Security "response
> field masking"). Sources: `crates/dwara-core/src/config/transforms.rs`
> (the `Masking` shape, `MASKED_VALUE`, and `CompiledMasking`), the
> runtime gates in `mask_response_body`
> (`crates/dwara-core/src/dataplane/transforms.rs`), the wiring in
> `dataplane/proxy.rs` (the decoration tail's first stage, proxy
> actions only), and validation in `src/snapshot/mod.rs`
> (`validate_masking`). Tests: `crates/dwara-core/tests/masking.rs`
> (9, end to end through the real dataplane) and the masking cases in
> `crates/dwara-core/tests/unit/transforms.rs` (4, the union and
> miss-is-the-leak grammar). Operator docs: [docs-site masking
> guide](../../docs-site/guide/masking.md).

An optional `masking` block on a Route redacts named fields from the
route's responses before anything else touches the body: every
[RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) pointer in the
block is replaced with the fixed sentinel `"***"` (a JSON string), so
a field named here never reaches the client, whatever the upstream put
in it — the mass-assignment/data-leak guard. Default-off; a route
without the block forwards untouched.

```yaml
routes:
  - name: orders
    service: orders-service
    match:
      path: { type: prefix, value: /api/orders }
    action: { type: proxy }
    masking:
      max_bytes: 131072
      fields:            # the floor: every consumer on this route
        - /user/email
        - /payment/card_number
      groups:            # extra pointers per consumer group
        partners:
          - /internal/margin
```

## The inverted gate posture: fail closed, always

The DW-028 [body transform](./transforms.md) PASSES THROUGH what it
cannot handle — an already-encoded or non-JSON body skips a
convenience transform, harmlessly. Masking inverts every one of those
gates into a refusal: the gateway cannot prove the configured fields
absent from bytes it cannot parse, and for a redaction policy a
skipped pass IS the leak. A route that configures masking pins its
proxied responses to the contract "identity-encoded JSON within the
cap, with every configured pointer present"; an upstream that violates
it answers 502.

| Refusal class (server-side reason) | Trigger | Client sees |
| --- | --- | --- |
| `response is content-encoded` | response carries `Content-Encoding` (the gateway does not decode) | 502 envelope |
| `response is not JSON` | content type is not `application/json` or `application/*+json` (parameters ignored) | 502 envelope |
| `response exceeds the masking cap` | declared `Content-Length`, or the streamed body, exceeds `max_bytes` | 502 envelope |
| `response claims JSON but does not parse` | JSON-typed body is not valid JSON | 502 envelope |
| `masking pointer '<path>' does not resolve` | a configured pointer is absent from the document (schema drift) | 502 envelope |
| `upstream stream failed mid-body` | the upstream died while the gateway buffered | 502 envelope |

The 502 is the uniform JSON envelope (`response_mask_failed`), generic
on the client side — no pointer paths, no upstream detail; the refusal
class is named only in the server-side log event (below). Buffering
before headers reach the client is what makes the refusal a clean
envelope instead of a torn stream.

Two deliberate pass-throughs, both because there is nothing to leak:
bodiless statuses (1xx, 101, 204, 304) and empty bodies (a proxied
HEAD, among others). And masking applies to PROXY action responses
only — gateway-authored bodies (`redirect`, `respond`) are operator
config bytes carrying no upstream data, so they are not a leak surface
and never face the gates (a `respond` body passes whatever its content
type).

`max_bytes` must be at least 1 and has no upper bound — the operator
owns the route's memory budget, the same stance as the DW-028
transform cap and `limits.max_body_bytes`. Upstream trailers are
dropped when masking buffers: they described the pre-mask body, and a
stale checksum beside replaced bytes would be a lie. `Content-Length`
is rewritten to the masked body's exact length.

## The union rule: groups only add

The effective pointer set for a request is the UNION of `fields` (the
floor, every consumer on the route) and the pointers of every `groups`
entry the authenticated consumer belongs to — deduplicated, so a
pointer listed in both the floor and a group applies once. A consumer
in no listed group (including the anonymous consumer) gets the floor
alone.

There is deliberately NO mechanism by which a group is exempted from
the floor. Redaction is the deny-anywhere-wins analog: an exemption
would be an allow-anywhere escape hatch on a security policy, exactly
what the authorization layer's precedence forbids. A group entry can
only ADD pointers.

## The sentinel

The replacement value is the FIXED JSON string `"***"` — not
configurable, identical on every route, so clients and audit tooling
can rely on the exact shape and nothing about a masked response
depends on per-route config a client cannot see. An operator who needs
a different shape on a specific route combines masking with a DW-028
response body transform, which runs AFTER masking and sees the
sentinel (e.g. `set /user/email` to `"[redacted]"`, or `remove` the
field entirely).

One documented ambiguity: a source value that is literally `"***"` is
indistinguishable from a masked value. The sentinel is a redaction
marker, not a data value; if a route's real payloads can carry
`"***"` in a masked field's position, treat every `"***"` at a
configured pointer as masked.

## Ordering: first in the response tail

Masking is the FIRST stage of the response decoration tail — before
the DW-028 response body transform, before response header ops, before
DW-027 compression, versioning stamps (DW-048), CORS decoration
(DW-027), and security headers (DW-028). Once the sentinel replaces a
secret, the original bytes exist nowhere in the gateway, so no later
stage can resurrect or re-emit them — pinned by test both ways: a
masked body still compresses (the gateway's own compression runs after
masking and never trips the encoding gate; only UPSTREAM-pre-encoded
responses are refused), and a response transform that removes the very
field masking addresses still resolves (masking ran first).

## The audit trail

Two events on the `dwara::policy` target, correlated by request-id —
labels and counts only, never values:

- `response_masked` (info), one per masked response: `route`,
  `consumer` (`anonymous` when unauthenticated), `masked` (the count
  of DISTINCT pointers applied), `request_id`.
- `response_mask_failed` (warn), one per refusal: `route`,
  `consumer`, `request_id`, `reason` (the refusal class from the
  table above).

## Validation

`snapshot::validate` checks the block in the standard fail-closed
publish pipeline (every issue at once; a rejected config never
replaces the running snapshot):

- The block must mask something: `fields` and `groups` both empty is
  an authoring mistake (omit the block to disable masking).
- `max_bytes` must be > 0.
- Every pointer — in `fields` and in every group entry — must parse
  as RFC 6901 (`/`-prefixed, `~0`/`~1` escapes, e.g. `/items/0/id`)
  and must not be the root pointer (`""` would replace the whole
  document with the sentinel — a body the route cannot usefully
  serve).
- Group keys must be non-empty, and each group's pointer list
  non-empty (an empty entry is an authoring mistake; the floor still
  applies to that group's consumers).
- Every group name must match SOME configured consumer's `groups`
  membership — a typo'd name silently never masks, which is
  fail-open, the exact posture this policy forbids (same check, and
  same store-managed-consumers caveat, as authorization group rules:
  consumers managed out-of-band can carry groups the config cannot
  see).
