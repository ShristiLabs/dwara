# API versioning

dwara has no version knob: API versions are expressed with routing,
and the gateway adds two aids on top — a `match.accept` criterion that
selects a route by media type, and a per-route `deprecation` block
that announces the retirement of an API version with the standard
response headers. This page shows the four versioning patterns and how
to deprecate a version clients can read. For the exhaustive field
list see the [configuration schema](../reference/configuration-schema).

## Choosing a versioning pattern

All four shapes are plain route configuration. Whichever you pick,
remember the one rule they share: **a request resolves to at most one
route** — if a route's path matches but its other criteria don't, the
request is answered `404`; it does not fall through to another
candidate. Multiple versions of one path cannot be selected by header
or Accept; a version family uses distinct paths (`/v1/`, `/v2/`, ...)
with the unversioned default on its own path.

### Path segments (`/v1/users`, `/v2/users`)

The most common shape: one prefix route per version, each stripping
its own version segment toward a version-agnostic upstream.

```yaml
routes:
  - name: users-v1
    service: users
    match:
      path: { type: prefix, value: /v1 }
    action:
      type: proxy
      rewrite: { type: replace_prefix, prefix: /v1, replacement: "" }
  - name: users-v2
    service: users
    match:
      path: { type: prefix, value: /v2 }
    action:
      type: proxy
      rewrite: { type: replace_prefix, prefix: /v2, replacement: "" }
  - name: users-default     # the unversioned default, on its own path
    service: users
    match:
      path: { type: prefix, value: / }
    action:
      type: proxy
```

`/v1/users` and `/v2/users` both reach `/users` at the upstream. See
[configuration: route matching](./configuration#route-matching) for
the path precedence rules.

### A version header (`X-API-Version: "2"`)

The exact header matcher constrains a route to one header value:

```yaml
routes:
  - name: users-v2-header
    service: users
    match:
      path: { type: prefix, value: /users }
      headers:
        x-api-version: "2"
    action:
      type: proxy
```

The match is exact: the whole header value must equal the configured
string. A request with `x-api-version: "1"` or without the header gets
a `404` — there is no fallback route on the same path.

### A query parameter (`?version=2`)

```yaml
routes:
  - name: users-v2-query
    service: users
    match:
      path: { type: prefix, value: /users }
      query:
        - name: version
          value: "2"
    action:
      type: proxy
```

Omit `value` to match on presence only. Values compare on the raw
bytes (no percent-decoding).

### Media types (`Accept: application/vnd.acme.v2+json`)

The versioned-media-type convention embeds the version in the subtype.
The `accept` criterion names one bare media type, and the route
applies when the request's `Accept` header lists that type/subtype:

```yaml
routes:
  - name: users-v2-media
    service: users
    match:
      # the media type rides on a versioned path: accept cannot be the
      # sole differentiator of one path (no same-path multi-version)
      path: { type: prefix, value: /v2 }
      accept: application/vnd.acme.v2+json
    action:
      type: proxy
  - name: users-media-default
    service: users
    match:
      path: { type: prefix, value: / }
    action:
      type: proxy
```

How `accept` matches:

- **Any list entry wins.** `Accept: application/json;q=0.8,
  Application/VND.Acme.V2+JSON` selects the route — matching is
  case-insensitive, and parameters and q-values on the request side
  are ignored (a client naming the type with `q=0` still selects it).
- **Wildcards and a missing `Accept` header never match.** `Accept:
  */*` is the most common Accept there is; version selection requires
  the client to name the version explicitly. A request for the
  versioned path that doesn't name the media type gets a `404` —
  route selection does not retry a shorter overlapping prefix.
  Clients that don't negotiate a version use the default path
  (`/users`), not the versioned path.
- **The configured value is a bare `type/subtype`** like
  `application/vnd.acme.v2+json`: no wildcards, no `;parameters`
  (validation rejects them). Case and surrounding whitespace in the
  configured value don't matter — it is normalized when the config
  compiles.
- **Every response of a matched route carries `Vary: Accept`**, folded
  into one line with any `Vary: Origin` (CORS) and `Vary:
  Accept-Encoding` (compression) the response already has, so shared
  caches key on the negotiated representation.

## Announcing a deprecation

Add a `deprecation` block to the route of the retiring version. The
gateway then stamps the standard signal headers on **every response of
that route** — proxied, redirected, and direct `respond` actions
alike:

```yaml
routes:
  - name: users-v1
    service: users
    match:
      path: { type: prefix, value: /v1 }
    action:
      type: proxy
      rewrite: { type: replace_prefix, prefix: /v1, replacement: "" }
    deprecation:
      since: "Mon, 01 Jan 2024 00:00:00 GMT"
      sunset: "Tue, 01 Jan 2030 00:00:00 GMT"
      uri: "https://docs.example.com/migrate/users-v1"
```

| Field | Response header | Notes |
| --- | --- | --- |
| `since` | `Deprecation: @<unix-seconds>` | When the version was (or will be) deprecated. A past date is normal — the deprecation is in effect. |
| `sunset` | `Sunset: <HTTP-date>` | When the version is expected to stop working; emitted exactly as configured. |
| `uri` | `Link: <uri>; rel="deprecation"` | The migration notice. Requires `since`. Must be an absolute `http(s)` URL. |

All three fields are optional (`uri` needs `since`), but a block with
neither `since` nor `sunset` is rejected — it would emit nothing.

### What clients see

With the block above, a plain `GET /v1/users` produces:

```text
HTTP/1.1 200 OK
Deprecation: @1704067200
Sunset: Tue, 01 Jan 2030 00:00:00 GMT
Link: <https://docs.example.com/migrate/users-v1>; rel="deprecation"
Content-Type: application/json
```

`@1704067200` is `Mon, 01 Jan 2024 00:00:00 GMT` as Unix seconds —
the RFC 9745 structured-date form of the `Deprecation` header.
`Sunset` is the RFC 8594 header and keeps the configured date
verbatim.

Three rules govern the headers' relationship to what the upstream
sends:

- On a route **with** a `deprecation` block, the gateway is the source
  of truth: upstream `Deprecation`/`Sunset` values are **replaced**.
- On a route **without** one, upstream values pass through untouched.
- `Link` is a list header: the gateway's deprecation link is
  **appended** after any links the upstream sent.

The headers describe the route's lifecycle, so they appear on the
route's own responses — not on the gateway's short-circuit answers
(a `401` from authentication, `403`, `429` from rate limiting,
`413`/`431` from request limits, `503` shedding, and CORS preflights).
And they keep appearing after the sunset date passes: changing or
removing them is a config publish (see below).

### Date validation and reload behavior

Dates must be written in the one HTTP-date form HTTP generators are
required to send — **IMF-fixdate**: `Sun, 06 Nov 1994 08:49:37 GMT`
(weekday and GMT are mandatory; a weekday that disagrees with the date
is rejected as a typo). Validation also rejects:

- a `sunset` in the past — remove the route or extend the date, don't
  advertise a removal that already happened;
- a `sunset` before `since` (equal dates are fine — same-day
  deprecation and removal);
- a `since` before 1970 (it cannot render as `@<unix-seconds>`);
- a `uri` without `since`, or one that is not an absolute `http(s)`
  URL.

The past-`sunset` check is deliberately fail-closed at publish time:
if a config carrying a stale sunset is loaded — at startup or by a
hot reload — the whole config is rejected and the previous one keeps
serving until the date is fixed. The reverse is also true: a running
gateway does not watch the clock. A published `sunset` keeps being
emitted after the date passes; retiring the signals means publishing a
new config.

Validate before deploying with `dwara-cli validate` (see
[CLI](./cli)); the [admin API](./admin-api) `PATCH /config` runs the
same validation.

### Browser caveat: `accept` + CORS on one route

A route with both an `accept` criterion and a `cors` block cannot be
preflighted by accident. Browsers send `Accept: */*` (or no Accept at
all) for preflights — a wildcard never names the version, so the route
doesn't match and the browser sees a `404` before any CORS logic
runs. Practical arrangements: put the versioned media-type contract on
a path that browsers reach with simple/actual requests only, or
version browser-facing APIs by path instead of media type. See
[CORS, compression, and request limits](./edge-policies) for the CORS
rules themselves.
