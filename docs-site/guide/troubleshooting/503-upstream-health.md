# 503 Service Unavailable

A 503 response means the gateway could not reach a healthy upstream
or the upstream returned an error that the gateway translated to 503.

## Symptoms

- Client receives `503 Service Unavailable` with
  `{"error":{"code":"...","message":"...","request_id":"..."}}`.
- Access log shows `status=503` with the route and upstream.
- Metrics show `dwara_upstream_health_total{upstream,state=unhealthy}`
  increasing.

## Likely causes

### Upstream is down

The upstream's endpoints are not accepting connections or are
returning errors.

**Diagnose:**

```sh
# Check upstream health from the admin API
curl -k https://127.0.0.1:2019/health | jq '.upstreams'

# Check the upstream directly (bypass the gateway)
curl -v http://<upstream-address>:<port>/
```

**Fix:** Restart the upstream service or fix its configuration.

### Circuit breaker is open

The gateway's circuit breaker has tripped after too many failures,
and is short-circuiting requests to avoid cascading load.

**Diagnose:**

```sh
# Check breaker state from metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_breaker
```

Look for `dwara_breaker_state{upstream="...",state="open"}`.

**Fix:** Wait for the breaker's recovery window to elapse (it will
transition to `half-open` and probe). If the upstream is healthy but
the breaker is too sensitive, tune the breaker thresholds in the
upstream config:

```yaml
upstreams:
  - name: my-upstream
    breaker:
      failure_threshold: 10      # increase if too sensitive
      recovery_timeout_ms: 5000  # decrease for faster recovery
```

### No healthy endpoints

All endpoints in the upstream pool are marked unhealthy.

**Diagnose:**

```sh
# Check endpoint health
curl -k https://127.0.0.1:2019/health | jq '.upstreams[] | select(.name=="my-upstream")'
```

**Fix:** Check the health check configuration. If passive health
checks are too aggressive (marking endpoints unhealthy on transient
errors), tune the thresholds:

```yaml
upstreams:
  - name: my-upstream
    health:
      passive:
        failure_threshold: 5
        success_threshold: 1
```

### Maintenance mode

The route is in maintenance mode, which returns 503 with
`Retry-After`.

**Diagnose:**

```sh
# Check if the route has maintenance mode enabled
curl -k https://127.0.0.1:2019/config | jq '.routes[] | select(.name=="my-route") | .maintenance'
```

**Fix:** Disable maintenance mode in the config or wait for the
maintenance window to end.

## See also

- [Circuit breaking](../circuit-breaking)
- [Operations](../operations)
