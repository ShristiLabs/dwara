# Dynamic Upstream Discovery (DNS)

DW-042 adds DNS-based dynamic upstream discovery to dwara. When an
upstream configures `dns_discovery`, a background task resolves the
hostname via DNS, watches the record TTL, and re-resolves when the TTL
expires (or at `refresh_interval_s`, whichever comes first), updating
the upstream's endpoint set live -- without a restart.

## When to use it

Use DNS discovery when your upstream service registers its instances in
DNS and the set changes dynamically (autoscaling, rolling deploys,
service discovery via DNS). The gateway picks up new endpoints and drops
removed ones without a config reload.

For static upstreams (fixed IP:port list), keep using the `endpoints`
field alone -- no `dns_discovery` block is needed.

## Configuration

Add a `dns_discovery` block to any upstream:

```yaml
upstreams:
  - name: my-service
    load_balancer: round_robin
    protocol: http1
    # `endpoints` is the INITIAL/fallback set. When dns_discovery is
    # present, endpoints may be empty (the gateway resolves them from
    # DNS). Non-empty endpoints serve until the first resolution
    # completes and as a fallback when DNS fails (if fail_open is true).
    endpoints: []
    dns_discovery:
      hostname: my-service.example.com
      port: 8080
      refresh_interval_s: 30
      record_type: A
      fail_open: true
      min_endpoints: 1
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `hostname` | string | (required) | The DNS hostname to resolve. |
| `port` | u16 | (required) | The port to pair with each resolved A-record address. Ignored for SRV records (they carry their own port). |
| `refresh_interval_s` | u64 | `30` | How often to re-resolve, in seconds (1..=3600). The actual refresh interval is `min(refresh_interval_s, record_ttl)` so a short-TTL record is refreshed sooner. |
| `record_type` | string | `"A"` | DNS record type: `"A"` or `"SRV"`. |
| `fail_open` | bool | `true` | If true, keep the last resolved endpoint set when DNS fails. If false, clear endpoints on failure (the upstream answers 503 until DNS recovers). |
| `min_endpoints` | u32 | `1` | Minimum endpoints to keep serving. If a resolution yields fewer than this, the previous set is kept (the upstream does not shrink below the floor). |

### A records

A records are the simplest: the gateway resolves the hostname to one or
more IPv4 addresses and pairs each with the configured `port`. Use this
when all instances share a single port.

### SRV records

SRV records carry their own port, so the `port` field is ignored. The
gateway resolves each SRV target to an IPv4 address via a separate A
lookup. Use SRV when instances may listen on different ports.

## Behavior

### Refresh cycle

Each cycle: resolve, update the endpoint set, sleep
`refresh_interval_s`, repeat. The resolver cache is disabled so every
lookup hits the name server; the sleep is purely the cadence.

### Endpoint-set swap

The discovery task updates the balancer's endpoint set atomically (the
same hot-swap path config reloads use). Unchanged addresses keep their
in-flight counters and health trackers; new addresses start fresh.

### DNS failure

On DNS failure:
- `fail_open: true` (default): the last resolved endpoint set is kept.
  Traffic continues to flow to the known endpoints.
- `fail_open: false`: the endpoint set is cleared. The upstream answers
  503 until DNS recovers.

### min_endpoints floor

If a resolution yields fewer than `min_endpoints`, the previous set is
kept. This prevents the upstream from shrinking below a configured
minimum (e.g., a DNS hiccup that returns a partial set).

### Reload

Discovery tasks are per-generation: a config reload cancels the old
tasks and spawns fresh ones for the new generation's upstreams,
mirroring active health probes. Upstreams without `dns_discovery` spawn
nothing.

## Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `dwara_dns_discovery_endpoints` | gauge | `upstream` | Current resolved endpoint count. |
| `dwara_dns_discovery_refresh_total` | counter | `upstream` | DNS discovery refresh attempts. |
| `dwara_dns_discovery_refresh_failures_total` | counter | `upstream` | DNS discovery refresh failures. |

The `upstream` label is config-bounded; cardinality is never per
resolved address.

## Limitations

- **IPv4 only**: A and SRV resolution resolves IPv4 addresses. IPv6
  (AAAA) support is a follow-up.
- **No system resolver**: the resolver uses explicit name servers
  (defaults to public Google resolvers). Reading `/etc/resolv.conf` is a
  follow-up (`system-config` feature).
- **Consul watch and Kubernetes EndpointSlice watch**: deferred to a
  future milestone. DNS is the first discovery source.
