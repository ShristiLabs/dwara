# WAF-lite filtering

dwara includes a lightweight web application filter (WAF-lite) that
inspects incoming requests for common attack signatures: SQL injection,
XSS, and path traversal. It is a heuristic pattern-matching filter, not
a full [WAF](https://en.wikipedia.org/wiki/Web_application_firewall) (Web Application Firewall) — it catches obvious attack payloads before they reach your
upstream, with a bounded inspection cost and a dry-run mode for safe
rollout.

## When to use this

WAF-lite is a first-line defense that catches obvious attack payloads
([SQL injection](https://owasp.org/www-community/attacks/SQL_Injection) (an attack that injects SQL via user input),
[XSS](https://owasp.org/www-community/attacks/xss/) (Cross-Site Scripting — injecting browser-executed script), and
[path traversal](https://owasp.org/www-community/attacks/Path_Traversal) (escaping a directory with `../` sequences)) before they reach the
upstream, with a dry-run mode for safe rollout. It is NOT a full WAF —
pair it with upstream input validation. It is per-route opt-in, so you
can enable it on the routes that accept untrusted input and leave it
off elsewhere.

## Enabling the WAF

The WAF is per-route opt-in. Add a `waf` block to any route:

```yaml
routes:
  - name: api
    match: { path: { type: prefix, value: /api } }
    action: { type: proxy }
    waf:
      enabled: true
```

With just `enabled: true`, all three filter categories run on every
matching request, inspecting the path, query string, selected headers
(User-Agent, Referer, Cookie, X-Forwarded-For), and body (when JSON or
[form-urlencoded](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST) (application/x-www-form-urlencoded, the default web form format), up to 128 KiB). A match returns `403 waf_blocked`.

## Filter categories

Choose which categories to run with the `filters` list:

```yaml
    waf:
      enabled: true
      filters: [sqli, xss]
```

| Filter | What it catches |
|---|---|
| `sqli` | `UNION SELECT`, `OR 1=1`, `'; DROP TABLE`, `--` comments, `xp_cmdshell`, hex-encoded keywords, stacked queries, time-based blind injection |
| `xss` | `<script>`, `javascript:`, `onerror=`, `<iframe>`, `document.cookie`, `eval(`, HTML entity-encoded variants, `<svg onload>` |
| `path_traversal` | `../`, `..\`, `%2e%2e%2f`, double URL-encoding, null byte (`%00`), `/etc/passwd`, `C:\Windows\` |

Omit `filters` or leave it empty to run all three (the default).

## Dry-run mode (audit-log-only)

Before enforcing the WAF, observe what it would catch with `dry_run:
true`:

```yaml
    waf:
      enabled: true
      dry_run: true
```

In dry-run mode, the WAF evaluates every filter and logs matches but
does NOT block — the request continues to your upstream. Check the
`dwara_waf_total{outcome="logged"}` counter and the `dwara::policy`
warn events to see what would have been blocked. Once you are satisfied
with the false-positive rate, switch to `dry_run: false` (or remove the
field) to enforce.

## Body inspection

The WAF inspects request bodies when the content type is JSON,
form-urlencoded, or text/plain, up to `max_body_inspect_bytes`:

```yaml
    waf:
      enabled: true
      max_body_inspect_bytes: 65536  # 64 KiB
```

- Default: 131072 (128 KiB).
- `0`: disable body inspection entirely (the body streams through
  untouched).
- Maximum: 1048576 (1 MiB).

Bodies larger than the cap are inspected only up to the cap. A malicious
payload beyond the cap is not caught — this is the trade-off for a
bounded inspection cost.

## Custom patterns

Add your own [regex](https://en.wikipedia.org/wiki/Regular_expression) (a pattern-matching language) patterns alongside the built-in signatures:

```yaml
    waf:
      enabled: true
      custom_patterns:
        - "(?i)internal_api_key_\\d+"
        - "(?i)\\bssrf\\b"
```

Custom patterns are appended to every enabled filter category. Invalid
regexes are rejected at config validation time (the config will not
publish).

## Metrics

The `dwara_waf_total{route,filter,outcome}` counter tracks every WAF
inspection:

| Outcome | Meaning |
|---|---|
| `blocked` | A match was found and the request was rejected with 403. |
| `logged` | A dry-run match (the request was allowed). |
| `passed` | No match (counted once per inspected request, `filter="all"`). |

## Request-path position

The WAF runs after the route method allowlist and before the route
limits — a content filter that rejects malicious requests before any
resource is spent on authentication or rate limiting. It inspects the
ORIGINAL request (before path rewrite or transforms).

## Limitations

- The WAF is heuristic, not semantic. It catches common attack
  signatures but cannot detect novel or obfuscated attacks that a
  full WAF with a rules engine would catch.
- Body inspection buffers up to `max_body_inspect_bytes`. This is the
  one explicitly buffering piece the WAF introduces; the rest of the
  dataplane streams untouched.
- The WAF does not inspect response bodies (it is a request-side filter
  only).
- The WAF does not replace authentication, authorization, or input
  validation in your upstream — it is a first-line defense that reduces
  the attack surface reaching your backend.
