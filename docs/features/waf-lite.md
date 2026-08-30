# WAF-lite heuristic filtering (DW-051)

A lightweight, heuristic-based web application filter that inspects
incoming requests for common attack signatures: SQL injection, XSS, and
path traversal. This is NOT a full WAF (ModSecurity, Coraza) — it is a
first-line traffic filter that rejects obvious attack payloads before
authentication or rate limiting, with a bounded inspection cost and a
dry-run (audit-log-only) mode for safe rollout.

## What it does

Per-route opt-in: a route with a `waf` block gets every matching
request inspected across four targets:

1. **Path** — the original request URI path (before path rewrite /
   transforms).
2. **Query string** — the raw query string.
3. **Headers** — User-Agent, Referer, Cookie, X-Forwarded-For.
4. **Body** — when the content type is `application/json`,
   `application/x-www-form-urlencoded`, or `text/plain`, up to
   `max_body_inspect_bytes` (default 128 KiB; 0 disables body
   inspection).

Each target is matched against regex patterns from the enabled filter
categories:

- **sqli** — `UNION SELECT`, `OR 1=1`, `'; DROP TABLE`, `--` comments,
  `xp_cmdshell`, hex-encoded SQL keywords, stacked queries, time-based
  blind injection (`SLEEP()`, `BENCHMARK()`), and more.
- **xss** — `<script>`, `javascript:`, `onerror=`, `onload=`,
  `<iframe>`, `document.cookie`, `eval(`, HTML entity-encoded variants
  (`&lt;script`), `<svg onload>`, and more.
- **path_traversal** — `../`, `..\`, `%2e%2e%2f`, double URL-encoding
  (`%252e%252e%252f`), null byte injection (`%00`), `/etc/passwd`,
  `C:\Windows\`, and more.

## Request-path position

The WAF check runs **after the route method allowlist, before the route
limits** (DW-027). Rationale: the WAF is a content filter that should
reject malicious requests before any resource is spent on
authentication, rate limiting, or cap admission. It inspects the
ORIGINAL request (before path rewrite / transforms / header injection).

Full request-path order (relevant excerpt):

```
route resolution → maintenance → method allowlist → WAF-lite (DW-051)
→ route limits → CORS preflight → authn → authz → rate limit → ...
```

## Configuration

```yaml
routes:
  - name: api
    match: { path: { type: prefix, value: / } }
    action: { type: proxy }
    waf:
      enabled: true              # default false
      dry_run: false             # audit-log-only mode
      filters: [sqli, xss, path_traversal]  # default: all three
      max_body_inspect_bytes: 131072  # 128 KiB; 0 = no body inspection
      custom_patterns: []        # additional regex patterns
```

### Fields

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch. When false, the WAF block is inert. |
| `dry_run` | `false` | Audit-log-only mode: evaluate and log matches without blocking. |
| `filters` | all three | Which filter categories to run. |
| `max_body_inspect_bytes` | `131072` | Body inspection byte cap (0 = no body inspection; max 1048576). |
| `custom_patterns` | `[]` | Additional regex patterns appended to the built-in signatures. |

### Validation

- When `enabled` is true, `filters` must be a subset of `{sqli, xss,
  path_traversal}` (or absent for all three).
- `max_body_inspect_bytes` must be 0 or 1..=1048576 (1 MiB).
- Every `custom_patterns` entry must compile as a valid regex.

## Dry-run mode (audit-log-only)

When `dry_run: true`, the WAF evaluates every filter and LOGS matches
(a `dwara::policy` warn event + the
`dwara_waf_total{outcome="logged"}` counter) but does NOT block — the
request continues to the upstream. This lets an operator observe what
the WAF would catch before enforcing it, the same DW-041 monitor-mode
pattern used by route limits, authz, rate limits, and load shedding.

## Metrics

`dwara_waf_total{route,filter,outcome}` — counter:

- `outcome="blocked"` — a match was found and the request was rejected
  with 403 `waf_blocked`.
- `outcome="logged"` — a dry-run match (the request was allowed).
- `outcome="passed"` — no match (counted once per inspected request,
  `filter="all"`).

All three labels are config-bounded (route names and the closed
filter/outcome sets).

## Match result

A match produces a `WafMatch { filter, pattern, target, value_preview }`:
- `filter` — the category (`sqli`, `xss`, `path_traversal`).
- `pattern` — the regex that matched.
- `target` — where the match was found (`path`, `query`, `header`,
  `body`).
- `value_preview` — the matched value truncated to 64 chars (never the
  full payload — could be huge or sensitive).

## Body inspection and streaming

The WAF body inspection is the ONE explicitly buffering piece the WAF
introduces. It buffers up to `max_body_inspect_bytes` from the request
body, inspects the buffered slice, and then replays the buffered bytes
plus the remaining stream to the rest of the request path. When the
body exceeds the cap, only the prefix is inspected (a malicious payload
beyond the cap is not caught — the trade-off for a bounded inspection
cost). When `max_body_inspect_bytes: 0`, no body inspection occurs and
the body streams through untouched.

## False-positive posture

The built-in patterns are tuned for HIGH-CONFIDENCE attack signatures
(literal SQL keywords in suspicious combinations, HTML tag openings,
encoded traversal sequences) rather than broad heuristics that would
flag legitimate API traffic. A battery of 20+ legitimate request
patterns is tested in both the unit and integration suites to guard
against regressions. The dry-run mode lets an operator measure the
actual false-positive rate against real traffic before enforcing.

## Implementation

- `crates/dwara-core/src/dataplane/waf.rs` — the WAF engine: pattern
  compilation, head/body inspection, the `WafBody` reconstruction type.
- `crates/dwara-core/src/config/mod.rs` — the `RouteWaf` config struct.
- `crates/dwara-core/src/snapshot/mod.rs` — validation (filter names,
  body cap, custom pattern regex compilation).
- `crates/dwara-core/src/dataplane/proxy.rs` — the request-path
  integration (handle_inner → WAF check → handle_routed).
- `crates/dwara-core/src/observability.rs` — the `dwara_waf_total`
  metric.
