# Request pipeline order

Do not reorder casually. Each phase is documented with its HTTP status and
DW-xxx reference.

## Inbound path

1. Reserved paths (`/healthz`, `/readyz`, `/metrics`)
2. Route resolution
3. Route maintenance (503 + Retry-After, preflight-exempt, DW-041)
4. Route method allowlist (405 + Allow, preflight-exempt, DW-030)
5. WAF-lite heuristic filtering (DW-051: SQLi/XSS/path-traversal on path,
   query, headers, body; 403 `waf_blocked` or dry-run; per-route opt-in)
6. Anomaly scoring (DW-090: header entropy, header count/bytes, path
   length/depth, query count, body size, unusual method; 403
   `anomaly_blocked` or dry-run; per-policy opt-in)
7. Route limits (413/431)
8. CORS preflight short-circuit (204, pre-authn)
9. WebSocket origin gate (DW-039: 403 if `websocket.origins` configured
   and unmatched)
10. Authentication
11. Authorization
12. Rate limit
13. Gateway cap admission (priority-aware)
14. Circuit breaker
15. Endpoint pick
16. Pending cap
17. Connect (request transforms run here -- DW-028: query ops after path
    rewrite, header ops after trusted-header injection, JSON body transform
    before retry buffering; policies above evaluated the ORIGINAL request)

## Response path

1. Field masking (DW-029: union of route floor + consumer groups;
   fail-closed 502 on encoded/non-JSON/over-cap/unparseable bodies)
2. Body/header transforms (DW-028)
3. Route compression (DW-027)
4. Versioning stamps (Vary: Accept fold + Deprecation/Sunset/Link, DW-048)
5. CORS decoration (DW-027)
6. Security headers (DW-028, every route-matched response incl. short-circuits)
7. Rate headers

## Unrouted traffic

Stops at route resolution. Listener/global policies rate-limit before the
404. Authn/authz never run pre-route.

## Dry-run (DW-041)

Does not reorder anything. A phase with `dry_run` attachment evaluates in
place and reports instead of rejecting (route limits, authz, rate limits,
load shedding).
