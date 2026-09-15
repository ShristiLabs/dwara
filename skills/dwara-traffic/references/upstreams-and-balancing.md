# Upstreams, balancing, health

## Anatomy

```yaml
upstreams:
  - name: api-upstream
    load_balancer: least_requests   # round_robin | least_requests | random |
                                    # ip_hash | maglev | peak_ewma
    protocol: http1                 # http1 | https | h2c | h3
    endpoints:
      - address: 10.0.0.1           # multiple endpoints should be distinct hosts
        port: 80
        weight: 3                   # relative, default 1, 0 = parked
    # hash_on:                      # key for ip_hash / maglev
    #   type: client_ip             #   | {type: cookie, cookie: name}
    #                               #   | {type: header, header: name}
    #                               # (header/cookie fall back to client IP)
    connection_cap: 100
    max_pending: 50
    slow_start_ms: 10000            # ramp window for newly added endpoints
```

Balancer guidance: `round_robin` default; `least_requests` when request
costs vary; `peak_ewma` for latency-aware picking (tune `peak_ewma.decay_ms`
/ `default_rtt_ms`); `ip_hash`/`maglev` for affinity without sticky
sessions (maglev = consistent hashing, minimal reshuffle when the pool
changes).

## Passive health (outlier detection)

```yaml
    health:
      consecutive_failures: 5      # eject after N consecutive failures
      eject_ms: 30000              # ejection duration
      failure_ratio: 0.5           # ...or error ratio over the window
      failure_min_volume: 20       # (with this many requests)
      half_open_probes: 1          # probes before full re-admission
      window_ms: 60000
```

## Active health (synthetic probes)

```yaml
    active_health:
      kind: http
      path: /healthz
      interval_ms: 5000
      timeout_ms: 2000
      jitter_ms: 500               # de-synchronize probes
      failure_threshold: 3
      success_threshold: 2
```

Active health feeds **load balancing** (eject unhealthy endpoints). The
separate `synthetic` probes (see dwara-operations skill) exercise **routes
end-to-end** and feed alerting/analytics - different jobs.

## Dynamic discovery

```yaml
    dns_discovery:
      hostname: my-service.example.com
      port: 80
      record_type: A
      refresh_interval_s: 300
      min_endpoints: 1
      fail_open: true              # keep last answers if DNS fails
```

Static `endpoints` act as the seed set.

## Timeouts

```yaml
    timeouts:
      connect_ms: 2000
      read_ms: 30000
      write_ms: 30000
      happy_eyeballs_ms: 250       # RFC 8305 dual-stack
```

Also settable as reusable `policies[].timeouts` (most specific attachment
wins).

## Upstream TLS and auth

```yaml
    # protocol: https + client certs toward the upstream
    mtls:
      client_cert_file: /certs/client.crt
      client_key_file: /certs/client.key
    # cert_pinning: ...            # NOTE: pinning takes precedence and
    #                               # suppresses the client cert (known
    #                               # limitation) - don't combine them
    oauth2_client_credentials:      # gateway obtains + caches a token and
      token_endpoint: https://idp/oauth2/token   # forwards it as Bearer
      client_id: ${OAUTH2_CLIENT_ID}
      client_secret: ${OAUTH2_CLIENT_SECRET}
      scopes: [api]
      token_cache_ttl_s: 3600       # effective TTL = min(expires_in-60s, this)
```

Token fetch failures -> `502 oauth2_token_unavailable`; the gateway never
forwards tokenless. Supports `mtls: {client_cert, client_key}`
(RFC 8705 `tls_client_auth`) at the token endpoint.

## Services: where splits and stickiness live

```yaml
services:
  - name: simple
    upstream: api-upstream
    base_path: /v1
    version: v1

  - name: split-service
    split:
      targets:                      # pick = hash % total_weight (request-id
        - upstream: stable-upstream # keyed; keep TOTAL constant on ramp)
          weight: 90
        - upstream: canary-upstream
          weight: 10                # weight 0 = blue-green parking
      canary_analysis:              # EXACTLY 2 targets (baseline + canary)
        window_seconds: 300
        step: 5
        min_requests: 100
        cooldown_seconds: 60
        promote:  { metric: error_rate, threshold: 0.01 }
        rollback: { metric: error_rate, threshold: 0.05 }
        # metrics: error_rate | latency_p99 | latency_p95 | latency_p50

  - name: sticky-service
    upstream: api-upstream
    sticky:
      cookie: dwara-affinity        # set once with Max-Age; opaque branch handle
      ttl_s: 3600                   # branch affinity only - for endpoint
                                    # affinity run ip_hash/maglev on the branch
                                    # upstream (the cookie becomes the ring key)
```

Auto-canary notes: >2x rollback threshold = immediate rollback to weight 0;
weight moves are transient (revert on reload); observability via
`dwara_canary_promotions_total`, `dwara_canary_rollbacks_total`,
`dwara_canary_weight{group}` and `canary_promoted`/`canary_rolled_back`
events (webhook-deliverable).
