# Response field masking

Dwara can redact named fields from a route's responses before anything
else touches the body: every [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901)
pointer you list is replaced with the fixed string `"***"`, per
consumer group. A field named here never reaches the client, whatever
the upstream put in it.

```yaml
routes:
  - name: orders
    service: orders-service
    match:
      path: { type: prefix, value: /api/orders }
    action: { type: proxy }
    masking:
      max_bytes: 131072
      fields:            # the floor: masked for every consumer
        - /user/email
        - /payment/card_number
      groups:            # extra pointers per consumer group
        partners:
          - /internal/margin
```

Masking is off by default: a route without the block forwards
responses untouched.

## The sentinel

Masked fields become the JSON string `"***"` — fixed, not configurable,
identical on every route, so clients and audit tooling can rely on the
exact shape. If you need a different shape on one route, combine
masking with a [response body transform](./transforms), which runs
after masking and sees the sentinel (rewrite it, or remove the field
entirely). Note the one ambiguity: a source value that is literally
`"***"` is indistinguishable from a masked value — treat every `"***"`
at a configured pointer as masked.

## Groups only add

The pointers applied to a response are the UNION of `fields` and the
entries of every group the authenticated consumer belongs to; a
consumer in no listed group (including anonymous callers) gets
`fields` alone. A group can only ADD pointers — there is deliberately
no way for a group to be exempted from the floor. Redaction is
deny-anywhere-wins: an exemption would be an escape hatch on a
security policy.

## Fail closed, always

A skipped masking pass would be exactly the leak the policy exists to
prevent, so every condition Dwara cannot handle is a REFUSAL, not a
passthrough. A route with `masking` pins its proxied responses to the
contract "identity-encoded JSON within `max_bytes`, with every
configured pointer present":

| Upstream response | Client receives |
| --- | --- |
| carries `Content-Encoding` (Dwara does not decode) | `502` |
| not JSON (`application/json` / `application/*+json` only) | `502` |
| larger than `max_bytes` (declared or streamed) | `502` |
| JSON-typed but not valid JSON | `502` |
| a configured pointer is missing from the document | `502` |
| dies mid-body while Dwara buffers | `502` (a clean envelope, not a torn stream) |

The `502` envelope is generic on the client side; the reason is named
only in the server-side log. Two things pass because they carry
nothing to leak: bodiless statuses (`204`, `304`, `1xx`, `101`) and
empty bodies (a proxied `HEAD`, among others). Masking also applies
only to proxied responses — bodies Dwara itself authors (`respond` /
`redirect` actions) are your config bytes, not upstream data.

`max_bytes` must be at least 1 and has no upper bound — it is the
route's memory budget, like a [body transform](./transforms) cap.
Dwara's own [compression](./edge-policies) runs AFTER masking, so a
masked response still compresses; only responses that arrive from the
upstream already encoded are refused. The forwarded `Content-Length`
is rewritten to the masked length.

## The audit trail

Every masked response emits one `dwara::policy` info event
(`response_masked`) with the route, consumer, count of distinct
pointers applied, and request id; every refusal emits one warn event
(`response_mask_failed`) naming the refusal class server-side. Labels
and counts only — masked values never appear in logs. See
[observability](./observability) for the logging pipeline.

## Ordering

Masking runs FIRST in Dwara's response pipeline — before [body
transforms](./transforms), before [compression](./edge-policies),
before [versioning stamps](./api-versioning) and CORS decoration.
Once a field is masked the original value exists nowhere in the
gateway, so no later stage can re-emit it.

## Validation

The standard [config pipeline](./configuration) checks the block at
publish: it must list at least one pointer somewhere; `max_bytes` must
be non-zero; every pointer must be valid RFC 6901 and not the root
(`""`); group entries must be non-empty; and every group name must
match a configured consumer's group membership (a typo'd group name
would silently never mask — fail-open, rejected on publish). All
issues are reported at once, and a rejected config never replaces the
running one. The exhaustive field list is the generated
[configuration schema](../reference/configuration-schema).
