# Dynamic Upstream Discovery (DW-042)

## Overview

DNS-based dynamic upstream discovery: a background task per upstream
resolves a hostname via DNS (A or SRV records), watches the record TTL,
and re-resolves when the TTL expires (or at `refresh_interval_s`,
whichever comes first), updating the upstream's endpoint set live --
without a restart.

Consul watch and Kubernetes EndpointSlice watch are deferred to a future
milestone. DNS is the first discovery source.

## Architecture

```
Config (dns_discovery) -----> DiscoveryTasks::respawn
                                   |
                                   v
                              JoinSet<()>
                                   |
                          spawn discovery_loop per upstream
                                   |
                          +--------+--------+
                          |                 |
                          v                 v
                     DnsResolver      UpstreamLb.rebuild
                   (hickory-resolver)  (atomic endpoint swap)
                          |
                          v
                     DNS server
                   (A/SRV records)
```

### DnsResolver

`dataplane/discovery.rs::DnsResolver` wraps
`hickory_resolver::TokioAsyncResolver`. The resolver is configured with
explicit name servers (the system resolver is NOT used by default;
`system-config` is off). The resolver's own cache is disabled
(`cache_size = 0`) so every lookup hits the name server and the
discovery task's sleep governs the cadence.

- `resolve_a(hostname)` -> `Vec<(IpAddr, ttl)>`: resolves A records,
  returns IPv4 addresses with the minimum TTL across all records.
- `resolve_srv(hostname)` -> `Vec<(IpAddr, port, ttl)>`: resolves SRV
  records, recursively resolves each SRV target to IPv4 via a separate
  A lookup, returns `(IP, port, TTL)` triples.

### DiscoveryTask

`dataplane/discovery.rs::DiscoveryTasks` owns one
`tokio::task::JoinSet` for every discovery task. The operator
(dwara-bin) calls `respawn` after every snapshot swap (startup and each
reload): all previous tasks are aborted and new ones spawned for the new
generation's upstreams. Dropping `DiscoveryTasks` (or calling
`abort_all`) aborts every task -- the graceful-shutdown path. This
mirrors `ActiveProbes` (DW-013), the closest precedent for a
long-running dataplane task.

### Refresh cycle

Each cycle:
1. Resolve the hostname (A or SRV).
2. If successful and the endpoint count >= `min_endpoints`: update the
   balancer's endpoint set atomically via
   `UpstreamLb::rebuild_with_resolved_health_and_events`. Unchanged
   addresses keep their in-flight counters and health trackers; new
   addresses start fresh.
3. If successful but below `min_endpoints`: keep the previous set (do
   not shrink below the floor).
4. If failed and `fail_open: true`: keep the previous set.
5. If failed and `fail_open: false`: clear the endpoint set (the
   upstream answers 503 until DNS recovers).
6. Sleep `refresh_interval_s` seconds. Repeat.

### Live endpoint-set swap

The discovery task calls `UpstreamLb::rebuild_with_resolved_health_and_events`,
a variant of `rebuild_with_health_and_events` that takes resolved
`HealthParams` (read from the current `LbState` via `health_config()`)
instead of the config form. This ensures a live endpoint-set swap uses
the same health parameters as the initial build without re-resolving
the config form.

The algorithm, slow-start, and events are also read from the current
`LbState` so the live swap matches the initial build. A reload that
changes these respawns the task, so a running loop's parameters cannot
change mid-flight.

## Integration

### dwara-bin

`main.rs` creates a `DnsResolver` (shared across all tasks) and a
`DiscoveryTasks` alongside `ActiveProbes` in the reload task. On
startup and after every successful reload, `respawn` is called with the
new registry and snapshot. The `reload` function in `reload.rs` takes
`&mut DiscoveryTasks`, `&Arc<DnsResolver>`, and `&Arc<Observability>`
parameters.

### Config schema

`config::DnsDiscovery` is an optional field on `config::Upstream`:
`dns_discovery: Option<DnsDiscovery>`. When present, `endpoints` may be
empty (validation allows it). When absent, `endpoints` must be
non-empty (the existing behavior).

Validation (`snapshot::validate`):
- `hostname` must be non-empty.
- `record_type` must be `"A"` or `"SRV"`.
- `refresh_interval_s` must be in `1..=3600`.

### Metrics

Three metric families in `observability.rs`:
- `dwara_dns_discovery_endpoints{upstream}` gauge: current resolved
  endpoint count.
- `dwara_dns_discovery_refresh_total{upstream}` counter: refresh
  attempts.
- `dwara_dns_discovery_refresh_failures_total{upstream}` counter:
  refresh failures.

The `upstream` label is config-bounded; cardinality is never per
resolved address.

## Testing

Integration tests in `tests/dns_discovery.rs` use `hickory-server` to
run an in-process DNS authority/server. The mock server serves A
records for `svc.test.` with a configurable TTL. Tests cover:

1. A-record resolution (IPs and TTL).
2. DiscoveryTasks lifecycle (respawn, abort, task_count).
3. Live endpoint-set swap (poll until the balancer's endpoint set
   changes).
4. Config validation (empty endpoints with/without dns_discovery,
   invalid record_type, out-of-bounds refresh_interval_s, empty
   hostname).

## Future work

- **IPv6 (AAAA)**: resolve AAAA records in addition to A.
- **System resolver**: enable `system-config` to read
  `/etc/resolv.conf`.
- **TTL-driven refresh**: use the record TTL to schedule the next
  refresh sooner for short-TTL records (currently uses
  `refresh_interval_s` as the cadence).
- **Consul watch**: defer to a future milestone.
- **Kubernetes EndpointSlice watch**: defer to a future milestone.
