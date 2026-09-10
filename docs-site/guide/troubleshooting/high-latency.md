# High latency

High latency means requests are taking longer than expected. The
gateway adds overhead, but most latency comes from upstream response
time, connection pool issues, or queueing.

## Symptoms

- Clients experience slow response times.
- The access log shows high `duration_ms` values.
- Metrics show the latency histogram shifting right.

## Likely causes

### Upstream is slow

The upstream service is taking too long to respond.

**Diagnose:**

```sh
# Check upstream latency from metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_upstream_duration

# Check the access log for slow requests
# Filter for requests with duration > 1000ms
```

**Fix:** Profile and optimize the upstream service. If the upstream
has a `timeout_ms` set, ensure it is not too low (causing premature
timeouts) or too high (letting slow requests consume connections).

### Connection pool exhaustion

The connection pool is too small for the load, causing requests to
wait for a free connection.

**Diagnose:**

```sh
# Check connection pool metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_pool
```

Look for `dwara_pool_wait_duration_seconds` increasing.

**Fix:** Increase the pool size in the upstream config:

```yaml
upstreams:
  - name: my-upstream
    pool:
      max_connections: 200
      max_idle_per_host: 50
      idle_timeout_ms: 60000
```

### Admission queueing

The gateway's concurrency cap has been reached and requests are
queueing before being processed.

**Diagnose:**

```sh
# Check admission queue metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_admission
```

Look for `dwara_admission_queue_depth` increasing and
`dwara_admission_queue_wait_seconds` rising.

**Fix:** Increase the concurrency cap or scale out the gateway:

```yaml
listeners:
  - name: main
    concurrency:
      max_connections: 20000
```

### TLS handshake overhead

TLS handshakes add latency on every new connection. If connections
are not being reused (keep-alive), each request pays the handshake
cost.

**Diagnose:**

```sh
# Check TLS handshake metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_tls_handshake
```

**Fix:** Ensure the client is using HTTP keep-alive. For the
upstream, ensure the connection pool is configured with adequate
idle connections.

### DNS resolution delays

If the upstream uses a hostname instead of an IP address, DNS
resolution can add latency on the first request or after the DNS
cache expires.

**Diagnose:**

```sh
# Check DNS resolution metrics
curl -k https://127.0.0.1:2019/metrics | grep dwara_dns
```

**Fix:** Use the `dns` block on the upstream to configure DNS
caching:

```yaml
upstreams:
  - name: my-upstream
    endpoints:
      - address: my-service.internal
        port: 8080
    dns:
      ttl_secs: 60
      refresh_secs: 30
```

## See also

- [Operations](../operations)
- [Admission queues](../admission-queue)
