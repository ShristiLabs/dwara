# Demo 07: Per-request external decisions (entitlement with a TTL cache)

Recipe 7 from the docs-site guide
[per-request external decisions](../../../docs-site/guide/use-cases/per-request-external-decisions.md):
the verdict genuinely must be computed per request by an external
service — entitlement checks, experiment bucketing, fraud scores. A
proxy-wasm plugin asks the decision service over `proxy_http_call`,
applies the verdict as request headers, and caches it briefly so the
per-request hop does not land on every call.

## What runs

- `plugin/` — `entitlement-guard`, an SDK-style proxy-wasm crate
  (`proxy-wasm` 0.2, `wasm32-wasip1`). At `request_headers` it reads
  `x-user`, consults its shared-data cache (VM-scoped: one map for
  every per-request instance of the module), and on a miss dispatches
  an HTTP callout and returns `Action::Pause`. In
  `proxy_on_http_call_response` it reads the `x-verdict` header
  (MapType 6), stamps `x-entitlement` / `x-entitlement-source` on the
  request, caches the verdict for 2 seconds, and resumes.
- `services/decision-service.py` — the mock decider: per-user hit
  counts (`/counts`), a denied user, and a slow user that outlives the
  plugin's 400 ms callout timeout.
- `services/user-api.py` — the protected upstream; it echoes the
  entitlement headers so the assertions can see the applied verdict.
- `dwara.yaml` — one `/api/*` route carrying the plugin.

## What the test proves

1. the first request per user hits the decision service and the
   upstream sees the applied verdict;
2. a request inside the TTL window is served from the plugin's cache
   (the service count does not move);
3. a different user is uncached and hits the service;
4. a denied verdict short-circuits the request with the plugin's 403
   (a non-2xx callout response is data the plugin decides on);
5. a decision slower than the callout timeout fails the route CLOSED
   (500 `plugin_failed`) — dwara's documented deviation from Envoy's
   empty-callback delivery; size the timeout deliberately.

## Run

```sh
./test.sh
```

Ports: gateway 18261, decision service 18262, user API 18263.
