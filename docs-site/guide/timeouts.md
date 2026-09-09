# Timeouts

Every stage of an upstream call is bounded by an explicit timeout: the
dial (DNS resolution, every connection attempt, and the TLS
handshake), the exchange of the request for response headers, and the
gaps between response body frames. Unbounded waits are how one slow
upstream turns into a pile of stuck connections and exhausted
concurrency slots -- timeouts are the first layer of the resilience
stack, and everything else (retries, hedging, circuit breaking)
composes with them.

Timeouts are configured per upstream in the `timeouts` block:

```yaml
upstreams:
  - name: api
    endpoints:
      - { address: 10.0.0.1, port: 8080 }
    timeouts:
      connect_ms: 2000
      read_ms: 10000
      write_ms: 30000
```

## When to use this

Set timeouts on every upstream that faces a real network. The
defaults are deliberately generous (connect `5 s`, everything else
unbounded), so the safe posture is to pin each stage to a bound your
clients can tolerate:

- **`connect_ms`** -- a connection that cannot be established quickly
  is almost always dead or dying; fail it early and let
  [retries](./retries) or [health checks](./health-checks) pick a
  different endpoint.
- **`read_ms`** -- bounds how long a client waits for response
  headers. Without it, an upstream that accepts the request and never
  answers holds a concurrency slot forever.
- **`write_ms`** -- bounds a stalled response body. A stream that
  stops mid-body without closing is the classic slow-livelock; this
  fires on the gap between body frames.

## Fields

| Field | Default | Description |
|---|---|---|
| `connect_ms` | `5000` | Bounds the WHOLE dial: DNS resolution plus every interleaved connection attempt plus, for TLS upstreams, the handshake. |
| `read_ms` | unbounded | Per-attempt deadline covering the pooled connection setup, writing the request, and reading the response HEADERS. The response body is not covered. |
| `write_ms` | unbounded | Response-body inactivity timeout: fires when the gap between two body frames exceeds it. Not a whole-body budget -- a long, steadily-streaming response never trips it. |
| `happy_eyeballs_ms` | `250` | Delay between interleaved connection attempts when an endpoint resolves to multiple addresses (RFC 8305). `0` disables racing (strict resolver order). |

## What each timeout covers

`connect_ms` wraps the dial end to end. When an endpoint's address
resolves to multiple addresses, the first is dialed immediately and
each subsequent one after `happy_eyeballs_ms`; the timeout covers
resolution plus every interleaved attempt plus the TLS handshake.
Only the dial's single final outcome reaches breaker and passive
health accounting -- the losing arms of one dial are never counted as
endpoint failures.

`read_ms` wraps each attempt: pooled connect, writing the request,
and reading the response headers, all inside one deadline. It is a
per-ATTEMPT bound -- with [retries](./retries) enabled, each attempt
gets its own `read_ms`, while the optional
`retries.total_deadline_ms` bounds the whole chain.

`write_ms` is an inactivity timeout on the response body: it fires
when the gap between two body frames exceeds it. A response that
streams steadily for an hour is fine; a response that stalls for
`write_ms` mid-body is cut.

## Failure responses

When a bound fires, the client receives the gateway's JSON error
envelope: a read timeout is classified as `504`, a connect timeout as
a connection error (the `502` family), and a body stall terminates
the in-flight response. With `retries.retry_transport` at its default
`true`, connect and read timeouts are retryable -- see
[Retries](./retries).

## Status note

The `timeouts` block is also accepted inside a named policy bundle
(`policies[].timeouts`) for scope-based attachment; the wired knob is
`upstreams[].timeouts`, and the policy-level field is config-accepted
but not yet enforced at runtime.

## See also

- [Retries](./retries) -- timeouts feed the retry classifier.
- [Request hedging](./request-hedging) -- race a duplicate instead of
  waiting out a slow attempt.
- [Circuit breaking](./circuit-breaking) and
  [Health checks](./health-checks) -- what happens to upstreams that
  keep timing out.
