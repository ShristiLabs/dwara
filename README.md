# dwara

A high-performance API gateway written in Rust.

Status: pre-alpha. The core reverse-proxy dataplane works — routing,
streaming proxying, TLS termination/passthrough, upstream load
balancing, hot config reload, and local rate limiting — with more
traffic policy still to come in M1.

## Quickstart

Requires Rust 1.94 (pinned in `rust-toolchain.toml`).

The gateway proxies: the sample config forwards everything under `/v1`
to an upstream at `127.0.0.1:9000`. Start any HTTP server there, then
run the gateway from the repo root with the sample config:

```sh
python3 -m http.server 9000
DWARA_CONFIG=crates/dwara-bin/dwara.yaml cargo run -p dwara-bin
```

Then request through the gateway (the listener binds
`http://127.0.0.1:8080`):

```sh
curl http://127.0.0.1:8080/v1/
```

The request is streamed to the backend unbuffered and the response
streams back the same way. A path with no matching route gets `404`; a
dead backend gets `502` (or `504` on connect timeout). Stop with Ctrl-C.

The binary exits with code 1, printing every validation issue, if the
config is missing or invalid.

Environment variables (all optional):

- `DWARA_CONFIG`: path to the gateway YAML config, default `./dwara.yaml`.
- `DWARA_BIND`: when set, overrides the config listeners with a single
  cleartext HTTP listener on that address (test/dev escape hatch;
  default unset = bind every configured listener).
- `DWARA_SHUTDOWN_TIMEOUT_SECS`: graceful-drain budget on
  SIGTERM/SIGINT, default 10.

## Configuration

Gateway configuration is a YAML file parsed strictly by `dwara-core`
(`parse_gateway`): unknown fields are rejected, and errors carry the
path of the offending node. A minimal valid configuration:

```yaml
listeners:
  - name: main
    address: 0.0.0.0
    port: 8080
routes:
  - name: all
    service: echo
    match:
      path:
        type: prefix
        value: /
    action:
      type: proxy
services:
  - name: echo
    upstream: echo-upstream
upstreams:
  - name: echo-upstream
    endpoints:
      - address: 127.0.0.1
        port: 9000
```

More examples live in `crates/dwara-core/tests/fixtures/` (minimal and
full). A machine-readable `json_schema()` export exists
programmatically; it is the intended canonical reference once the
schema stabilizes. The schema still churns during M1.

Config passes through a fixed pipeline before the gateway serves it:

- **Parse** (strict): unknown fields rejected, errors carry the path of
  the offending node.
- **Validate** (semantic): duplicate names, unknown upstream/service/
  policy references, listener address+port conflicts, empty or invalid
  credentials and endpoint weights are checked, and every issue is
  reported at once rather than one per attempt.
- **Compile**: route paths are built into lookup structures. This is
  where schema-valid config can still fail (an invalid regex or
  conflicting path template names the route and pattern at fault).
- **Publish** (atomic): a config that fails anywhere above never
  replaces the running one; the gateway keeps serving the previous
  snapshot, and each successful publish gets a new generation id.

Route paths match one of three ways: `exact` (a full template, path
parameters like `/users/{id}` supported), `regex`, or `prefix`. A
request path resolves to at most ONE route, chosen in this order:

1. **Exact** — the matchit radix template; static segments beat
   parameters (`/users/active` before `/users/{id}`), and conflicting
   templates are rejected at config-compile time.
2. **Regex** — when several `regex` routes match, the FIRST-declared
   one in config order wins.
3. **Prefix** — the LONGEST matching prefix wins (byte prefix, no
   segment boundary: `/v1` also matches `/v1anything`); equal-length
   ties go to the first-declared route.

Cross-kind order is fixed: exact beats regex beats prefix, regardless
of declaration order or how specific a regex/prefix looks. A route can
also require non-path criteria: a `host` (matched case-insensitively
against the `Host` header, with or without a port — exact only, no
wildcards), a list of `methods` (empty = all methods), exact-value
`headers`, `query` parameters, and `cookies`:

```yaml
match:
  path: { type: prefix, value: /api }
  query:
    - name: apikey            # present is enough
    - name: version           # exact value required
      value: "2"
  cookies:
    - name: session
      value: abc123
```

Every criterion is AND-ed. Query and cookie matching is over the RAW
bytes the client sent: no percent-decoding for query values and no
cookie-unquoting in v1 — configure the value exactly as it appears on
the wire. A path that resolves to a route whose criteria miss does NOT
fall through to the next candidate route; the request is answered
`404`.

### Route actions

A matched route does one of three things:

- `proxy`: forward to the route's service (and its upstream). An
  optional `rewrite` (at most one per action, no chaining) rewrites the
  path before it is sent upstream — see below.
- `redirect`: answer with a 3xx whose `Location` is built from the
  optional `scheme`, `host`, and `path`; when no `path` is configured
  the inbound path and query are preserved verbatim. `status` is
  required (e.g. 301, 302).
- `respond`: answer directly with the configured `status`, optional
  plain-text `body`, and optional extra `headers` (a name-to-value map,
  emitted verbatim; invalid header names/values are rejected by
  validation).

```yaml
routes:
  - name: old
    service: echo
    match:
      path: { type: prefix, value: /old }
    action:
      type: redirect
      scheme: https
      host: api.example.com
      status: 301
  - name: health
    service: echo
    match:
      path: { type: exact, value: /ping }
    action:
      type: respond
      status: 200
      body: ok
```

Requests that match no route (path or criteria miss) get a plain-text
`404`. A route may also carry a `priority` (0-10, default 5) — see
"Load shedding and priority" under Global settings.

### Path rewrite (proxy)

A `proxy` action may carry one `rewrite`, applied to the path component
only — the query string is always re-attached verbatim. Three kinds:

- `strip_prefix`: strip the route's matched prefix (the `match.path`
  value with trailing slashes trimmed). If nothing remains, the result
  is `/`.
- `replace_prefix`: when the request path starts with `prefix`, replace
  that prefix with `replacement` (must start with `/` or be empty);
  otherwise the path is forwarded unchanged.
- `regex`: replace the FIRST match of `pattern` with `substitution`.
  The substitution may reference numbered capture groups (`$1`,
  `${2}`, ...) and named groups of the pattern, falling back to the
  route's `{param}` path-template captures; unknown references expand
  to the empty string. The pattern must compile; this is checked at
  config-compile time, never at request time.

```yaml
routes:
  - name: api-strip
    service: echo
    match:
      path: { type: prefix, value: /v1/ }
    action:
      type: proxy
      rewrite: { type: strip_prefix }
  - name: api-relabel
    service: echo
    match:
      path: { type: regex, value: "^/api/(.*)$" }
    action:
      type: proxy
      rewrite:
        type: regex
        pattern: "^/api/(.*)$"
        substitution: "/internal/$1"
```

### Proxying semantics

Proxying streams end to end: neither request nor response bodies are
buffered by the gateway — SSE and large bodies pass through with
hyper's natural frame-based backpressure. Hop-by-hop headers
(`Connection` and everything it names, `Keep-Alive`, `TE`, `Trailer`,
`Transfer-Encoding`, `Proxy-*`, plus `Upgrade` on non-upgrade
requests) are stripped in both directions. The outbound `Host` is set
to the upstream authority (`address:port` of the endpoint), not the
inbound host.

Protocol upgrades tunnel generically: an HTTP/1.1 request with an
`Upgrade` header whose upstream answers `101` (e.g. WebSocket) has
both connections upgraded and spliced byte-for-byte until either side
closes. An `Upgrade` request received over HTTP/2 or h2c is answered
`501 Not Implemented`.

Upstream failures are classified, and details are logged server-side
only: connect timeout or per-attempt read timeout (`timeouts.read_ms`)
-> `504`; endpoint refused, pool failure, or no endpoints -> `502`;
upstream TLS configuration errors -> `500`.

### Global settings

- `max_concurrent_requests` (top-level, DW-015): the maximum number of
  requests admitted concurrently across the WHOLE gateway. Absent (the
  default) is unlimited. A request over the cap is rejected immediately
  (no queueing) with 503 "gateway saturated". A slot is reserved at
  admission and held until the response BODY completes or the client
  connection drops — a streaming response holds its slot for the whole
  stream. The reserved `/healthz` and `/readyz` paths bypass the cap, so
  liveness/readiness probes still answer under saturation. An explicit
  `0` is rejected by validation (omit the field for unlimited). A reload
  builds a new cap; requests already admitted keep their slots.

```yaml
max_concurrent_requests: 4096
```

### Load shedding and priority

Routes and consumers carry an optional `priority` — an integer 0
(lowest) to 10 (highest), default 5 when omitted; validation rejects
anything above 10. Priority shapes how the gateway concurrency cap
(`max_concurrent_requests`) behaves under saturation:

- Route resolution happens BEFORE cap admission, so the request's
  priority class is known when the shed decision is made. A side
  effect: requests that match no route (plain `404`) never consume a
  cap slot, and neither do the reserved `/healthz` and `/readyz`
  paths.
- When ANY route or consumer is configured at priority >= 8
  ("high"), 10% of the cap (minimum 1) is carved out as a reserved
  sub-allowance that only high-priority requests may draw from once
  the general allowance is full. Under overload, normal traffic is
  shed first — 503 "gateway saturated" as soon as the general
  allowance fills — while high-priority traffic survives until the
  reserved bucket fills too.
- This is reserved capacity, NOT preemption: requests already in
  flight keep their slots until they complete; the gateway cannot
  displace a running normal request to make room for a high-priority
  one.
- Consequence of the minimum-1 carve: a cap of 1 with any high
  priority configured reserves the entire cap — the general allowance
  becomes 0 and ONLY high-priority requests are ever admitted. Use a
  cap of 1 only for high-priority-only traffic.
- With no route or consumer at priority >= 8, nothing is carved and
  every request draws from the full cap exactly as before —
  priority-free configs behave identically to the plain cap.
- A shed is a 503, not a 429 (429 is reserved for rate limiting),
  carries no `Retry-After` (immediate re-dispatch against a saturated
  gateway is not advisable), and no marker header — the response is a
  plain 503 with "gateway saturated" as the body.

```yaml
routes:
  - name: critical
    service: billing
    priority: 9          # survives overload; shed last
    match:
      path: { type: prefix, value: /billing }
    action:
      type: proxy
```

Consumers also accept a `priority`; it takes effect only once request
authentication identifies the consumer (a later M1 release) — until
then, shedding priority comes from the matched route. When known, the
consumer's priority overrides the route's.

### Forwarded headers and trusted proxies

Gateway-level `trusted_proxies` (a list of IP addresses or CIDR
ranges, e.g. `10.1.2.3` or `10.0.0.0/8`) controls
`X-Forwarded-For` handling; anything else in the list fails
validation:

```yaml
trusted_proxies:
  - 10.0.0.0/8
```

- `X-Forwarded-For`: if the direct connection peer is inside
  `trusted_proxies`, the inbound XFF chain is preserved and the peer
  appended (`"<inbound>, <peer>"`). Otherwise — including the empty
  default, which trusts nobody — the inbound XFF is discarded and
  replaced with exactly the peer, so a spoofed chain from an
  untrusted client never reaches the upstream.
- `X-Real-IP`: always the direct connection peer, no configuration.

### Upstreams

Each upstream is a load-balanced pool of endpoints with its own
connection pool. Fields:

- `load_balancer`: the pick algorithm, one of `round_robin` (default),
  `least_requests`, `random`, or `ip_hash` — see below.
- `protocol`: `http1` (plaintext, default), `https` (TLS, ALPN
  `http/1.1`), or `http2` (TLS, ALPN `h2`, HTTP/2 only).
- `connection_cap`: maximum concurrent outbound connections to the
  upstream (active plus pooled idle). Excess connection attempts wait
  for a slot rather than fail. Defaults to 64.
- `timeouts.connect_ms`: connect timeout in milliseconds, covering the
  TCP connect plus, for TLS upstreams, the handshake. Defaults to 5000.
- `timeouts.read_ms`: per-attempt deadline in milliseconds covering the
  whole exchange up to the response HEADERS: connection-cap queue wait,
  connect, request write, and header read. When the deadline expires
  before headers resolve, the attempt fails `504` (and is
  retryable as a transport failure when retries are on). The response
  BODY is not covered by `read_ms`. Absent = unbounded.
- `timeouts.write_ms`: response-body INACTIVITY timeout in milliseconds
  — the maximum gap between two consecutive body frames, not a total
  streaming budget (a body that keeps trickling frames never trips it).
  A longer stall terminates the stream (frames already forwarded to the
  client end abruptly; no synthesized tail) and is reported as a
  passive-health failure for the endpoint. Absent = unbounded.
- `retries`: upstream retries block; absent (default) disables retries
  entirely. See below.
- `breaker`: per-upstream circuit breaker block; absent (default)
  disables the breaker entirely. See "Circuit breaking and capacity
  limits" below.
- `max_pending`: cap on requests WAITING for an outbound connection
  slot; absent (default) queues without bound (the `connection_cap`
  behavior). See "Circuit breaking and capacity limits" below.
- `slow_start_ms`: slow-start window in milliseconds; absent or 0
  (default) disables the ramp. See below.
- `health`: passive health / outlier detection block; absent (default)
  disables it entirely. All keys inside the block default. See below.
- `active_health`: active health probing block; absent (default)
  disables probing. Requires a `health` block (validation rejects the
  pairing otherwise). All keys inside the block default. See below.

Each endpoint carries a `weight` (default 1, must be > 0). For
`https`/`http2` upstreams, server certificates are verified against the
Mozilla (webpki) public CA root set. Zero values for `connection_cap`
and the timeout fields are rejected by validation.

```yaml
upstreams:
  - name: echo-upstream
    load_balancer: round_robin
    protocol: https
    connection_cap: 32
    slow_start_ms: 30000
    timeouts:
      connect_ms: 2000
    endpoints:
      - address: 10.0.0.5
        port: 8443
        weight: 3
      - address: 10.0.0.6
        port: 8443
```

Load-balancing algorithms:

- `round_robin` — smooth weighted round-robin (the nginx algorithm)
  over per-endpoint weights: picks interleave deterministically in
  proportion to weight, and over any full period (sum of weights) each
  endpoint is picked exactly its weight many times.
- `least_requests` — the endpoint with the fewest in-flight requests
  wins; ties break to the first-declared endpoint. In-flight is counted
  from dispatch until response headers resolve (long streaming bodies
  count as one request).
- `random` — power of two choices: two distinct endpoints are drawn at
  random and the one with fewer in-flight requests wins.
- `ip_hash` — consistent hashing (ketama) on the client's connection
  IP: the same client IP maps to the same endpoint (sticky), vnode
  count is proportional to endpoint weight, and adding or removing an
  endpoint remaps only about 1/(n+1) of keys. On the TLS-passthrough
  path there is no per-request IP key, so `ip_hash` degrades to smooth
  weighted round-robin there.

Slow start (`slow_start_ms`, at most 600000): an endpoint entering the
set ramps its effective weight from a floor of 1 up to its configured
weight over the window, measured from when it entered the set. The ramp
applies to `round_robin`; `least_requests` needs no ramp (it already
balances on observed load) and `ip_hash` ring weights stay fixed to
preserve key stability.

Hot swap: a config reload swaps the endpoint set, weights, and
algorithm without a restart. Endpoints whose `address:port` is unchanged
keep their in-flight counters, round-robin phase, and slow-start clock;
new addresses start fresh. Removed endpoints drop their state —
re-adding one later is a fresh entry.

Passive health (`health` block, DW-012): ejection driven by real traffic
outcomes — no synthetic probes are sent to endpoints in rotation. A
failure is a transport error (connect timeout, refusal, reset) or an
HTTP response status >= 500; 1xx-4xx count as successes (429 and 408
describe the caller, not endpoint health). An endpoint is ejected from
all load-balancing algorithms when EITHER it accumulates
`consecutive_failures` (default 5) failures in a row, OR its failure
share within the rolling `window_ms` (default 60000) is >=
`failure_ratio` (default 0.5) with at least `failure_min_volume`
(default 20) observations in the window — the volume gate keeps a brief
blip from ejecting on a trickle of traffic. After `eject_ms` (default
30000) the endpoint goes half-open: the next `half_open_probes` (default
1) requests are trial probes; a successful probe restores it to healthy
with a clean history, a failed probe re-ejects for another `eject_ms`.
If EVERY endpoint of an upstream is ejected, the balancer fails open —
picks fall back to the full endpoint set rather than blackholing traffic
(so a fully degraded pool degrades, it does not become a guaranteed
503). Health state is keyed by `address:port` and survives config
reloads alongside in-flight counters; new health parameters apply to new
observations.

```yaml
upstreams:
  - name: echo-upstream
    health:
      window_ms: 60000          # rolling observation window
      consecutive_failures: 5   # eject after N failures in a row
      failure_ratio: 0.5        # or >= this failure share in-window
      failure_min_volume: 20    # ... with at least this many observations
      eject_ms: 30000           # time out of rotation before probing
      half_open_probes: 1       # trial requests per recovery attempt
```

A `health:` block with no keys enables ejection with the defaults above.

Active health checks (`active_health` block, DW-013): dwara PROBES each
endpoint on its own schedule, in addition to watching real traffic.
Requires the passive `health` block (the probe results report into the
same per-endpoint ejection machinery, which owns the eject and half-open
windows). One probe loop per endpoint sleeps `interval_ms` plus a
uniform random `0..jitter_ms` (full jitter) and then probes the endpoint
DIRECTLY — bypassing load balancing and the connection pool, since a
probe must examine one specific endpoint. An `http` probe issues
`GET {path}` over HTTP/1.1 on its own connection (TLS with webpki root
verification toward `https`/`http2` upstreams) and counts a 2xx status
as success; anything else — 3xx included, redirects are not followed —
4xx, 5xx, truncation, timeout, or transport error is a failure. A `tcp`
probe succeeds when the TCP connect completes within `timeout_ms`; use
it for `http2` upstreams whose servers refuse HTTP/1.1 on a separate
connection.

Fields (all default; zero values for the millisecond and threshold
fields are rejected, `interval_ms` must be >= `timeout_ms` and >=
`jitter_ms`, and `jitter_ms: 0` disables jitter):

- `kind`: `http` (default) or `tcp`.
- `path`: path probed by `http` checks, default `/healthz`. Ignored by
  `tcp`.
- `interval_ms`: time between probe attempts, default 5000.
- `timeout_ms`: per-probe timeout (connect plus response for `http`),
  default 2000.
- `success_threshold`: consecutive probe successes required to (re)admit
  an ejected endpoint, default 2.
- `failure_threshold`: consecutive probe failures required to eject,
  default 3.
- `jitter_ms`: full-jitter bound, default 500.

Interplay with passive ejection: probe results feed the SAME ejection
tracker as traffic outcomes, and the two share the per-endpoint
consecutive-failure streak — either signal can eject, on its own
threshold (passive `consecutive_failures` or active
`failure_threshold`). Probe outcomes never enter the passive
failure-ratio/volume window, so synthetic probes do not pollute
real-traffic ratios. Ejected endpoints stay out of rotation for
`health.eject_ms`, and probe failures while ejected cannot extend that
window. Recovery is probe-driven: `success_threshold` consecutive
successful probes re-admit the endpoint outright — even before
`eject_ms` expires, and even for endpoints carrying no traffic (which
passive health alone can never recover). Probe loops are restarted on
every config reload, but the shared tracker (keyed by `address:port`)
survives the swap, so an ejection streak outlives the restart.

```yaml
upstreams:
  - name: echo-upstream
    health: {}                    # required: owns eject/half-open windows
    active_health:
      kind: http
      path: /healthz
      interval_ms: 5000
      timeout_ms: 2000
      success_threshold: 2
      failure_threshold: 3
      jitter_ms: 500
```

An `active_health:` block with no keys enables HTTP probes with the
defaults above.

Retries (`retries` block, DW-014): a failing proxied request is re-sent
to the upstream, up to `attempts` additional times with exponential
backoff and full jitter. All knobs live on the upstream (there is no
per-route retry configuration). Absent — or `attempts` left at its
default 0 — disables retries entirely: every request gets exactly one
attempt and the proxy path keeps its zero-copy streaming body.

Fields (all default; `attempts` is capped at 10, `backoff_base_ms`
must be > 0, `backoff_cap_ms` >= `backoff_base_ms`, `budget_percent`
must be in (0, 100], and every `retry_statuses` entry must be a valid
4xx/5xx status — all rejected by validation):

- `attempts`: maximum retries beyond the first attempt, default 0 (off).
- `retry_post`: retry non-idempotent POST requests, default false. POST
  is never retried unless explicitly opted in — a retried POST may
  replay a body the upstream already partially processed.
- `backoff_base_ms` / `backoff_cap_ms`: the nominal delay before retry
  n is `min(base * 2^(n-1), cap)`; the actual sleep is a uniform random
  duration in `[0, nominal]` (full jitter), avoiding thundering-herd
  synchronization. Defaults 25 / 250.
- `retry_statuses`: response statuses that trigger a retry, default
  `[502, 503, 504]`. An empty list disables status-based retries.
- `retry_transport`: retry on transport-class failures (connect or
  per-attempt read timeout, refusal, reset, framing), default true.
  Configuration errors (no endpoints, invalid TLS host) are never
  retried — they would fail identically on every attempt.
- `budget_percent`: maximum share of requests to this upstream, in a
  rolling 10-second window, that may be retries, default 10. The retry
  is charged before it runs, so a fresh window with little volume
  grants few or no retries; when the budget is exhausted, failing
  requests fail through to the client instead of retrying. Budget
  state survives config reloads.
- `buffer_max_bytes`: request-body buffering cap in bytes, default 0
  (no buffering). A body is replayable on retries only when it was
  fully buffered within this cap; a body that exceeds the cap streams
  (the already-buffered prefix plus the remainder, in order) with
  exactly one attempt — over-cap requests are never retried, they do
  not error.

Rules:

- Idempotency: GET, HEAD, OPTIONS, TRACE, and PUT are retry-eligible by
  method; POST only with `retry_post: true`.
- Headers-final: retries happen strictly before response headers arrive
  on the final attempt. A response body that dies mid-stream (transport
  error or `write_ms` stall) is NEVER retried — the attempt was final
  once its headers resolved — and the abort is reported as a
  passive-health failure for the endpoint instead.
- Protocol upgrade requests (`Upgrade` header) are never retried.
- Each retry re-picks the endpoint through the load balancer, so health
  ejection and weights apply per attempt.

```yaml
upstreams:
  - name: echo-upstream
    retries:
      attempts: 2
      retry_post: false
      backoff_base_ms: 25
      backoff_cap_ms: 250
      retry_statuses: [502, 503, 504]
      retry_transport: true
      budget_percent: 10
      buffer_max_bytes: 1048576
```

A `retries:` block with no keys is equivalent to retries off.

### Circuit breaking and capacity limits

Circuit breaking (`breaker` block, DW-015) gates an ENTIRE upstream —
all endpoints — when the upstream is failing as a whole. It is a
different layer from per-endpoint ejection (the `health` block above):
ejection removes individual endpoints from rotation, the breaker stops
sending ANY traffic to the upstream for a cooling-off period. The two
never consume each other's state — a breaker-open period ejects nothing
(passive health sees no traffic, hence no failures), and ejections never
open the breaker. Even when every endpoint is ejected and the balancer
fails open, that pick still flows THROUGH the breaker.

The breaker OPENS when either trips:

- the consecutive-failure streak reaches `consecutive_failures`
  (default 5), or
- the rolling 60-second window holds at least `error_volume` (default
  20) observations AND failures/observations >= `error_ratio` (default
  0.5) — the volume gate keeps a brief blip from tripping on a trickle
  of traffic.

Failure classification is identical to passive health: a transport
error or an HTTP status >= 500, observed when an attempt's response
HEADERS resolve. Every retry attempt reports too. A mid-BODY abort
after headers resolved does not trip the breaker (it is still reported
to endpoint health). While OPEN, every request fails fast with 503
"upstream circuit open" and a `Retry-After` header carrying the seconds
until half-open (rounded up, minimum 1) — no endpoint pick, no
retries. Requests already in flight when the breaker opened complete
normally. After `open_ms` (default 30000) the breaker goes half-open:
the next `half_open_probes` (default 1) requests are admitted as trial
probes; a successful probe CLOSES the breaker with all counters and the
window reset, a failed probe re-OPENS it for another `open_ms`. While
all probes are in flight, further requests fail fast with
`Retry-After: 1`.

Breaker state (state, streak, window) survives config reloads keyed by
upstream name, like balancer state and the retry budget; breaker
parameters apply from the new config. Fields (all default; zero values
and an `error_ratio` outside (0, 1] are rejected by validation):

- `consecutive_failures`: consecutive failures that open the breaker,
  default 5.
- `error_ratio`: in-window failure share that opens the breaker once
  the volume gate is met, default 0.5.
- `error_volume`: minimum observations in the 60 s window before the
  ratio is evaluated, default 20.
- `open_ms`: cooling-off period before a half-open probe is admitted,
  default 30000.
- `half_open_probes`: concurrent trial requests admitted in half-open,
  default 1.

```yaml
upstreams:
  - name: echo-upstream
    breaker:
      consecutive_failures: 5
      error_ratio: 0.5
      error_volume: 20
      open_ms: 30000
      half_open_probes: 1
```

A `breaker:` block with no keys enables the breaker with the defaults
above.

Pending cap (`max_pending`, DW-015): bounds how many requests may WAIT
for an outbound `connection_cap` slot to this upstream. Absent (the
default) queues without bound; a positive value rejects excess requests
IMMEDIATELY with 503 "upstream saturated" instead of letting them wait.
A pending slot is held only while the request is waiting; the moment a
connection slot is acquired (the request is connecting, no longer
pending) the pending slot frees for the next request. `max_pending: 0`
is rejected by validation (omit the field for unbounded). The 503 is
not retried — the upstream is saturated by definition; a retry would
add load.

Local rate limiting (DW-017) runs BEFORE every layer below — after
route resolution but before the gateway concurrency cap — so a rejected
request is the cheapest thing the gateway can do with a request and
never holds a cap slot. See "Rate limiting" below.

The admission layers stack in a fixed order, outermost first:

1. local rate limiting (`rate_limits`, see Rate limiting) — over-limit:
   429 + `Retry-After`;
2. gateway concurrency cap (`max_concurrent_requests`, see Global
   settings) — over-cap: 503 "gateway saturated";
3. per-upstream circuit breaker (`breaker`) — open: 503 "upstream
   circuit open" + `Retry-After`;
4. per-endpoint ejection (the `health` block) — an ejected endpoint is
   skipped by the balancer;
5. per-upstream pending cap (`max_pending`) — queue full: 503
   "upstream saturated";
6. connect (`connection_cap`, `timeouts.connect_ms`).

### Rate limiting

Local, in-gateway rate limiting (DW-017) is configured on **policies**
(top-level `policies` list) and applies to requests on routes and
services that reference the policy by name via their `policies` list.
Precedence follows the frozen chain consumer > route > service >
listener > global, but limiting does NOT pick one winner: rules from
every applicable policy ALL apply and are AND-ed — a request denied by
any rule is denied. The consumer link goes live with authentication
(a later M1 release); listener- and global-attached policies have no
config attachment point yet. Today: route- and service-attached
policies limit; a request whose route and service reference no policy
with rate rules is not limited and carries no rate headers.

A policy carries a list of rules under `rate_limits`; each rule has
these fields:

- `name`: optional label, documentation only.
- `selector`: the key components the limit is counted over — one or
  more of `ip` (the direct connection peer, the same IP used for
  `X-Real-IP`), `credential` (the authenticated consumer), and `route`
  (the matched route's name). Order does not matter.
- `requests_per`: the sustained rate — any combination of `s`
  (per second), `minute`, and `hour`. At least one must be set and each
  set value must be > 0 (validation rejects otherwise).
- `burst`: bucket size, defaulting to the window's request count.
  Must be >= 1 when present.

```yaml
policies:
  - name: api-limits
    rate_limits:
      - name: per-client-burst
        selector: [ip, route]
        requests_per: { s: 10, minute: 600 }
        burst: 20
      - name: route-wide
        selector: [route]
        requests_per: { hour: 100000 }
routes:
  - name: api
    service: echo
    policies: [api-limits]
    match:
      path: { type: prefix, value: /api }
    action:
      type: proxy
```

**Selector semantics.** All listed selectors are joined into ONE
counter key, which decides whether buckets are shared or independent:

- `selector: [ip]` — one bucket per client IP. Attached at a service,
  this is a per-client budget shared across every route of the service.
- `selector: [route]` — ONE bucket for the whole route: every client
  draws from the same budget (a global cap on the route).
- `selector: [ip, route]` — one bucket per (client IP, route) pair:
  each client gets an independent budget per route.
- `credential` falls back to the client IP until authentication
  identifies consumers, so anonymous traffic limits per client rather
  than sharing one global "anonymous" bucket. `selector: [credential,
  route]` becomes per-(client, route) until then.

**Burst and sustained rate.** Windows are GCRA buckets: `requests_per`
is the sustained replenishment rate and `burst` is the bucket size. A
window of `s: 10` with `burst: 20` admits 20 rapid requests up front
(the burst), then sustains 10 r/s; traffic above the sustained rate
starts drawing 429s once the bucket empties. With the default burst
(= the window's request count) the very first window can admit up to
`burst + replenished` requests, the standard GCRA shape.

**Stacked windows.** Setting several windows in one rule (`s` AND
`minute` AND `hour`) stacks them: a request is admitted only if EVERY
window allows it — 10 r/s AND 600 r/min means a client can spend the
minute budget no faster than 10 r/s. Windows are evaluated
shortest-first and evaluation stops at the first denial, so a request
rejected by the hourly window has still spent its second-window token
— slightly stricter than an atomic all-windows check, never more
permissive, and the waste replenishes with the fastest window.

**429 contract.** A request over the limit is answered `429` with body
`rate limit exceeded` and these headers from the BINDING constraint
(the window that denied; on success, the window with the least
remaining budget):

- `Retry-After`: whole seconds until the next conforming retry,
  rounded up, minimum 1.
- `X-RateLimit-Limit`: the binding window's burst size.
- `X-RateLimit-Remaining`: budget left in the binding window
  (`0` on a 429).
- `X-RateLimit-Reset`: Unix epoch seconds of the binding window's
  estimated full replenishment.

Admitted requests under a matched policy carry the same three
`X-RateLimit-*` headers on their response (including streaming proxy
responses and `respond`/`redirect` actions); requests no policy
matched carry none.

**Reload caveat.** Rate-limit state lives inside the config
generation: every config reload rebuilds the engine and RESETS all
buckets — a reload is a fresh budget for everyone.

**Legacy field.** A policy's older `rate_limit` field
(`{requests, window_seconds}`) still applies and compiles to one rule
with `selector: [route]`, a single window of `requests` per
`window_seconds`, and `burst = requests`. Both fields may be set on
one policy; both apply. Use `rate_limits` for new configs.



### TLS

Listeners are `http` (cleartext) or `https` (TLS). An `https` listener
requires a `tls` block with one of two modes.

**Terminate** (default): dwara ends TLS at the edge (rustls, aws-lc-rs
provider; TLS 1.2 and 1.3 with rustls's default cipher policy). ALPN
advertises `h2` and `http/1.1`, so both HTTP/2 and HTTP/1.1 work over
one listener. Multiple certificates are selected by SNI: entries in
`certificates` are matched (exact, case-insensitive) against the
client's server name; the single `cert_file`/`key_file` pair is the
fallback for unmatched or absent SNI, and with no single pair the first
`certificates` entry is the fallback. A single pair alone (no
`certificates`) is the simplest form; a `certificates`-only config is
also valid.

```yaml
listeners:
  - name: edge
    address: 0.0.0.0
    port: 443
    protocol: https
    tls:
      mode: terminate
      cert_file: /etc/dwara/certs/default.crt.pem   # fallback pair
      key_file: /etc/dwara/certs/default.key.pem
      certificates:
        - server_names: [a.example.com]
          cert_file: /etc/dwara/certs/a.crt.pem
          key_file: /etc/dwara/certs/a.key.pem
        - server_names: [b.example.com]
          cert_file: /etc/dwara/certs/b.crt.pem
          key_file: /etc/dwara/certs/b.key.pem
```

**Passthrough**: dwara never decrypts. The ClientHello is peeked (not
consumed), the SNI server name is matched exactly (case-insensitive)
against `sni_routes`, and the raw TLS bytes are spliced bidirectionally
to the upstream. A non-TLS client, a ClientHello with no SNI, or an
unmatched name has its connection closed. Certificate fields are
rejected in this mode; `sni_routes` are rejected in terminate mode.

```yaml
listeners:
  - name: edge
    address: 0.0.0.0
    port: 443
    protocol: https
    tls:
      mode: passthrough
      sni_routes:
        - server_names: [back.example.com]
          upstream: backends
upstreams:
  - name: backends
    endpoints:
      - address: 10.0.0.5
        port: 8443
      - address: 10.0.0.6
        port: 8443
```

A passthrough route's connection is forwarded to an endpoint of its
upstream chosen by that upstream's load balancer (for `ip_hash`, the
smooth round-robin fallback — a byte splice has no per-connection IP
key); picks follow config reloads live.

Cleartext `http` listeners accept HTTP/1.1 and h2c (HTTP/2 prior
knowledge) — the connection preface is sniffed, no upgrade or ALPN
needed.

## Operations

Reload: the config file is watched (the file's directory, so atomic
write-temp-plus-rename replacement is observed; events are debounced)
and `SIGHUP` also triggers a reload. A reload re-reads the file,
validates, and publishes a new generation atomically; the route table
and the upstream connection pools hot-swap together, so a new route
never runs against old pools; upstream endpoint sets, weights, and
load-balancer settings swap in the same atomic publish. In-flight requests keep the generation
they started with until they complete. A rejected
reload (unreadable, parse, or validation failure) logs every issue and
keeps serving the running generation — the process never exits on a
bad reload. If the file watch cannot start, SIGHUP reload still works.

Certificates hot-reload on terminate listeners: the cert/key files are
watched (same directory-watch pattern as the config), and a change
rebuilds the TLS configuration and swaps it in live — no connections
are dropped. New handshakes use the new material; handshakes and
sessions already in flight keep what they negotiated. A config reload
also refreshes TLS material. A failed TLS reload (e.g. an unreadable
PEM) is logged and keeps the previous certificates. Limitations: the
listener bind set (listeners, addresses, ports) is fixed at startup —
adding or removing listeners or changing address/port takes effect on
restart; only route/config changes and certificate material reload
live. Passthrough splices are also not drained on graceful shutdown;
they run until the process exits.

Health endpoints: dwara reserves `/healthz` and `/readyz` and serves
them on every terminate and cleartext listener BEFORE route resolution.
`/healthz` answers 200 whenever the process is up (liveness);
`/readyz` answers 200 once a config generation has been published
successfully and 503 before that (readiness — it tracks the gateway's
own state, not upstream health). Caveat: these paths are not routable —
a configured route matching `/healthz` or `/readyz` (exact, regex, or
prefix) is permanently shadowed by the reserved handlers; this is
accepted v1 behavior, not a validation error. TLS-passthrough listeners
never serve them (they do not speak HTTP).

Shutdown: `SIGTERM`/`SIGINT` stop accepting, drain live connections
(including ones still in the kernel accept backlog) within
`DWARA_SHUTDOWN_TIMEOUT_SECS`, then exit 0. Connections still draining
past the budget are force-closed.

## Crates

| Crate | Role |
| --- | --- |
| `dwara-core` | Config model, routing types, swappable trait definitions |
| `dwara-bin` | Gateway server binary |
| `dwara-admin` | Admin / management-plane API |
| `dwara-cli` | Operator command-line client |

## Extension points

State-holding subsystems are defined as swappable traits in
`dwara-core::extensions`: `RateLimiter`, `ConfigSource`, `CacheStore`,
`AnalyticsSink`, and `SecretSource`. Each trait's rustdoc states its
contract (purpose, semantics, failure model). Local in-memory, file, and
environment-variable implementations ship today; alternative backends
plug in by implementing the same traits.

## Development

CI runs on pushes and pull requests to `main` (when Rust sources,
manifests, toolchain files, or the workflow itself change). Blocking
gates: `cargo fmt --check`, clippy with `-D warnings`, build, tests,
and [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) checks
(advisories, licenses, bans — policy in `deny.toml`). A CycloneDX SBOM
is generated and uploaded as an artifact on each run.

Run the same checks locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## License

Apache-2.0
