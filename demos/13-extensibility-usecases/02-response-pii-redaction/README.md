# Demo 02: response PII redaction at the edge

The
[response-PII-redaction recipe](../../../docs-site/guide/use-cases/response-pii-redaction.md):
an upstream leaks card numbers into JSON bodies; compliance wants them
masked before clients see them. The demo builds the SHIPPED
[`response-body-redact`](../../../../plugins/examples/response-body-redact)
example plugin by path -- the recipe's point is that the shipped
example IS the surface -- and runs it against a mock leaky upstream.

## What runs

- `leaky-upstream.py` -- a deliberately non-compliant backend:
  - `GET /api/account` (buffered JSON): the test card
    `4111 1111 1111 1111` (Luhn-valid), the innocent 16-digit
    reference `1234567812345678` (Luhn-invalid), and the literal
    secret `sk-live-12345`
  - `GET /api/stream` (`text/event-stream`, no framing): the same
    leak over SSE
- `dwara.yaml` -- one `/api/` route with the redaction plugin at the
  `response_body` phase (literals configured; card masking always on).

## What test.sh asserts

1. the card is masked keep-last-4: `**** **** **** 1111`, digits gone
2. the innocent number passes through untouched (the Luhn gate keeps
   ordinary 16-digit ids readable)
3. the configured literal is starred, same length
4. the SSE endpoint SKIPS the `response_body` phase (streaming
   carve-out): the card streams through unmasked -- masking at the
   gateway is a seatbelt for buffered bodies, not a fix for the
   upstream

## Run

```sh
./test.sh          # builds plugins/examples/response-body-redact by
                   # path, starts the leaky upstream + gateway, asserts
```

Ports: gateway 18211, leaky upstream 18212.
