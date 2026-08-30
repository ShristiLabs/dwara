# Response caching

Dwara can cache a route's GET responses locally and replay them for
identical requests, cutting upstream load and tail latency. Caching is
off by default: a route opts in with a `cache` block, and only requests
Dwara can key safely are ever cached.

```yaml
routes:
  - name: catalog
    service: catalog-service
    match:
      path: { type: prefix, value: /api/catalog }
    action: { type: proxy }
    cache:
      ttl_secs: 30                      # required: freshness, in seconds
      stale_while_revalidate_secs: 60   # optional: serve stale while refreshing
      max_body_bytes: 1048576           # optional: per-entry cap (default 1 MiB)
      vary: [x-tenant]                  # optional: extra request headers to key on
      coalescing: { wait_ms: 5000 }     # optional: collapse concurrent misses (below)
```

## What gets cached

A request is cacheable when the route has a `cache` block and the
request is a plain `GET` — no body, no `Authorization` header, no
`Cookie` header, no protocol upgrade. Everything else (POSTs, credentialed
fetches, WebSockets handshakes) always goes upstream.

A response is stored only when it is safe to replay: status 200, no
`Set-Cookie`, no `Cache-Control: no-store` / `private` / `no-cache`,
not content-encoded, and its `Vary` only names dimensions the route
keys on. Responses larger than `max_body_bytes` stream through unstored.

Every cached entry is keyed by route, consumer, path, query, and the
vary dimensions — two consumers never share an entry, so
[masking](./masking) variants can never leak across consumers.

## Hit, stale, revalidated

Every response that reaches the cache decision carries an `x-cache`
header (gateway-generated short-circuits — 401/429/503, maintenance —
answer before the cache and carry no stamp):

| Value | Meaning |
| --- | --- |
| `hit` | served from a fresh cached entry |
| `stale` | the entry expired but served inside the stale window while a background refresh runs |
| `miss` | fetched from the upstream |
| `revalidated` | the upstream confirmed the cached body unchanged (ETag / 304) |
| `bypass` | this request shape is never cached |

Freshness is `ttl_secs`, always — the origin's own `max-age` does not
extend it (only the storage vetoes above are honored). Inside
`stale_while_revalidate_secs` after expiry, clients keep getting
instant answers while one background request refreshes the entry. Past
the window the next request revalidates conditionally: if the upstream
answers `304 Not Modified`, the stored body re-serves without
re-sending it. A client that sends a matching `If-None-Match` on a
fresh entry gets an immediate `304`.

## Request coalescing

When N identical cacheable GETs miss at the same moment (a cache-cold
route, a burst after a deploy), only the FIRST should pay for the
upstream call. Adding a `coalescing` block to the route's `cache`
enables exactly that: the first miss (the leader) fetches upstream
while the rest (followers) wait — bounded by `wait_ms` (default 5 s)
— and then receive the leader's stored answer (`x-cache: hit`), like
any other cache hit.

```yaml
    cache:
      ttl_secs: 30
      coalescing: {}          # enable with the default 5 s wait bound
```

Coalescing applies only to the miss path of cache-enabled routes:
requests the cache bypasses (non-GET, credentialed, body-bearing) and
routes without a `cache` block are never coalesced — there is no
shared cacheable outcome to hand a follower. Followers are keyed by
the full cache key (route, consumer, path, query, vary), so a follower
can only ever receive an answer computed for an identical request of
its own consumer.

Coalescing never makes things worse — every fallback is "do your own
fetch":

- the leader's response is not storable (for example `no-store`) or
  the leader fails: each follower fetches on its own, with the route's
  full retry policy;
- a purge or config change lands mid-flight: followers fetch on their
  own rather than inherit an invalidated answer;
- a follower's `wait_ms` expires: it fetches on its own;
- more than 256 distinct keys are already in flight: new misses fetch
  independently instead of joining.

## Purging

The [admin API](./admin-api) invalidates cached entries:

```sh
curl -X POST --cert admin.crt --key admin.key \
  --cacert ca.crt https://127.0.0.1:19000/cache/purge \
  -H 'content-type: application/json' \
  -d '{"route": "catalog"}'        # or {"all": true}
```

The response names what was purged and the invalidation epoch it
reached. Purge is an O(1) generation advance — it completes in well
under 100 ms no matter how many entries are live.

Invalidation also happens automatically: any configuration change that
alters a route (its transforms, masking, or cache policy) retires that
route's cached entries, because they were shaped by the old policy.
Unrelated config changes leave the cache warm.

## Bounds

The store is bounded by bytes (64 MiB by default across all routes),
per-entry size (`max_body_bytes`), entry lifetime (`ttl_secs` plus
the stale window), and one hour of idleness (unvisited entries are
evicted even when still fresh). Only opted-in routes ever buffer a
response body, never beyond the configured cap.

## Metrics

The `/metrics` endpoint exposes `dwara_cache_lookups_total{outcome=...}`
(hit/stale/miss/bypass), `dwara_cache_stores_total{outcome=...}`,
`dwara_cache_revalidated_total`, `dwara_cache_purges_total{scope=...}`,
and the live-entry gauge `dwara_cache_entries` — see
[Observability](./observability). With coalescing enabled,
`dwara_coalescing_leaders_total`,
`dwara_coalescing_followers_total{outcome=served|fell_back_timeout|fell_back_unshared|fell_back_epoch}`,
`dwara_coalescing_saved_upstream_calls_total` (upstream calls avoided),
and the `dwara_coalescing_waiters` gauge report how much the collapse
is saving and why followers fell back.
