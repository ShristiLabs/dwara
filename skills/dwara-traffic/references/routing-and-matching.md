# Routing and matching in detail

## Listener surface

```yaml
listeners:
  - name: edge-https
    address: 0.0.0.0
    port: 8443
    protocol: https            # http | https | h3 | tcp | udp
    proxy_protocol: false      # accept PROXY v1/v2 header (behind an L4 LB)
    tls:
      mode: terminate          # terminate | passthrough (SNI-based)
      cert_file: /certs/server.crt
      key_file: /certs/server.key
      client_ca_file: /certs/client-ca.crt     # optional mTLS client auth
      certificates:            # optional multi-SNI pairs; the flat pair above
        - server_names: [api.example.com]      # is the fallback for unmatched SNI
          cert_file: /certs/api.crt
          key_file: /certs/api.key
    alt_svc: h2=":8080"        # advertise upgrade path (or h3 with a port)
    authorization: { ... }     # listener-level authz link
    policies: [listener-rate-limit]
```

Reserved paths served by the gateway on every listener: `/healthz`,
`/readyz`, `/metrics`.

## Match criteria semantics

```yaml
match:
  path:
    type: exact      # exact | prefix | regex
    value: /v1/users/{id}   # exact supports {param} templates
  methods: [GET, POST]      # case-insensitive; empty = all;
                            # HEAD is NOT implicitly granted by GET
  host: api.example.com     # exact, case-insensitive
  headers:                  # exact-value only (map), no regex
    x-api-version: "1"
  query:                    # name-only = presence; value = exact raw bytes
    - name: trace           # (no percent-decoding)
  cookies:
    - name: session         # same presence/exact semantics (no unquoting)
  accept: application/json  # bare type/subtype; no wildcards/params;
                            # any-entry-wins, case-insensitive; `*/*` never
                            # matches; responses get `Vary: Accept`
```

All non-path criteria AND together, applied **after** path resolution.
A miss is a 404 - the gateway does not try the next route candidate.

## Actions

```yaml
action:
  type: proxy
  rewrite:
    type: strip_prefix      # strips the matched pattern; remainder "/" -> path root
    # type: replace_prefix  # prefix + replacement (literal)
    # type: regex           # pattern + substitution ($1..$9, ${n}, named groups)

  # type: redirect          # scheme/host/path all optional (omitted =
  #                         # preserve inbound); status REQUIRED (301/302/308...)
  # type: respond           # status + optional body/headers (gateway-served)
  # type: mock              # status + body | body_file (read at publish time)
  #                         # + headers + delay_ms (simulated latency)
  # type: ai                # see the dwara-ai-gateway skill
```

- Exactly **one** rewrite per action, no chaining. The query string always
  passes verbatim.
- `regex` substitutions compile-check at config time; unknown group refs
  expand to empty.
- `respond`/`mock` never dial the upstream - but a `service` + `upstreams`
  chain is still schema-required.

## Per-route policy surface (high-value keys)

- `auth_required: true` + `authorization` (see dwara-security skill)
- `transforms` (request/response header set/add/remove, query add)
- `security_headers`, `cors`, `compression`, `limits`
  (max_body_bytes/max_header_bytes/max_header_count)
- `cache` (see caching-and-transforms.md)
- `waf` (heuristic filters), `request_validation.body_schema`,
  `masking` (fail-closed field redaction)
- `mirror` (shadow traffic), `fault_injection` (chaos), `maintenance`
  (503 + Retry-After), `deprecation`/`slo`, `websocket`, `priority`,
  `policies`

## Versioning and deprecation

There is no dedicated version knob - version by path prefix + rewrite, or
by exact `headers`/`query`/`accept` matching. Deprecation signals are
first-class:

```yaml
deprecation:
  since: Wed, 01 Jan 2025 00:00:00 GMT     # -> Deprecation: @<unix> (RFC 9745)
  sunset: Fri, 01 Jan 2027 00:00:00 GMT    # -> Sunset header (RFC 8594)
  uri: https://docs.example.com/migration  # -> Link; rel="deprecation"
```

The gateway **replaces** upstream-supplied values when the block is
present. A `sunset` in the past fails the whole config at validation -
remove the route instead of advertising a dead sunset. Dates must be valid
IMF-fixdate (day-of-week must match the date).
