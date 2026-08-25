# dwara

A high-performance API gateway written in Rust.

Status: pre-alpha. The core reverse-proxy dataplane works — routing,
streaming proxying, TLS termination/passthrough, upstream load
balancing, and hot config reload — with traffic policy still to come in
M1.

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
      path: { type: exact, value: /healthz }
    action:
      type: respond
      status: 200
      body: ok
```

Requests that match no route (path or criteria miss) get a plain-text
`404`.

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
only: connect timeout -> `504`; endpoint refused, pool failure, or no
endpoints -> `502`; upstream TLS configuration errors -> `500`.

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
- `slow_start_ms`: slow-start window in milliseconds; absent or 0
  (default) disables the ramp. See below.
- `health`: passive health / outlier detection block; absent (default)
  disables it entirely. All keys inside the block default. See below.

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
