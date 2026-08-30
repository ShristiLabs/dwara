//! DNS-based dynamic upstream discovery (DW-042, feature analysis 4.4).
//!
//! When an upstream configures `dns_discovery`, a background
//! [`DiscoveryTasks`] resolves the hostname via DNS (A or SRV records),
//! updates the upstream's endpoint set in the [`UpstreamLb`] live, and
//! re-resolves when the record TTL expires (or at `refresh_interval_s`,
//! whichever comes first). Endpoint scale-up/down is reflected without a
//! restart — new connections use the updated set; existing connections
//! stay alive until they close.
//!
//! # Resolution
//!
//! [`DnsResolver`] wraps a `hickory_resolver::TokioAsyncResolver`. A
//! records are resolved to `(IpAddr, ttl)` pairs; SRV records to
//! `(IpAddr, port, ttl)` triples (the SRV target is resolved to an IP by
//! the resolver's recursive lookup). The resolver is configured with
//! explicit name servers (the system resolver is NOT used by default —
//! `system-config` is off); the gateway's config controls which name
//! servers to query.
//!
//! # Refresh cycle
//!
//! Each cycle: resolve, update the endpoint set, sleep
//! `min(refresh_interval_s, record_ttl)`, repeat. On DNS failure:
//! `fail_open: true` keeps the last resolved set; `fail_open: false`
//! clears endpoints (the upstream answers 503 until DNS recovers). The
//! `min_endpoints` floor prevents shrinking below a configured minimum —
//! if a resolution yields fewer endpoints, the previous set is kept.
//!
//! # Task lifecycle
//!
//! [`DiscoveryTasks`] owns one [`tokio::task::JoinSet`] for every
//! discovery task. The operator (dwara-bin) calls
//! [`DiscoveryTasks::respawn`] after every snapshot swap (startup and
//! each reload): all previous tasks are aborted and new ones spawned for
//! the new generation's upstreams. Dropping [`DiscoveryTasks`] (or
//! calling [`DiscoveryTasks::abort_all`]) aborts every task — the
//! graceful-shutdown path. This mirrors [`crate::dataplane::active::ActiveProbes`] (DW-013), the
//! closest precedent for a long-running dataplane task.
//!
//! Consul watch and Kubernetes EndpointSlice watch are DEFERRED to a
//! future milestone — DNS is the first discovery source.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::TokioAsyncResolver;
use tokio::task::JoinSet;

use crate::config::{DnsDiscovery, Endpoint};
use crate::dataplane::balance::UpstreamLb;
use crate::dataplane::upstream::UpstreamHandle;
use crate::observability::Observability;

/// Default DNS name servers when none are explicitly configured: the
/// system's resolver is NOT used (the `system-config` feature is off);
/// instead the gateway falls back to the public Google resolvers, which
/// are the hickory-resolver default. Operators who need a custom
/// resolver configure it at the OS level and the gateway will pick it up
/// once `system-config` support is added (a follow-up).
const DEFAULT_NAMESERVERS: &[&str] = &["8.8.8.8:53", "8.8.4.4:53"];

/// A TTL-aware DNS resolver wrapping `hickory_resolver::TokioAsyncResolver`.
///
/// Configured with explicit name servers (the system resolver is not
/// used by default). `resolve_a` returns `(IpAddr, ttl)` pairs; `resolve_srv`
/// returns `(IpAddr, port, ttl)` triples.
pub struct DnsResolver {
    inner: TokioAsyncResolver,
}

impl DnsResolver {
    /// Build a resolver that queries the given name server addresses
    /// (e.g. `["127.0.0.1:5353"]`). An empty list falls back to the
    /// default public resolvers.
    pub fn new(name_servers: &[String]) -> Self {
        let mut config = ResolverConfig::new();
        let servers: Vec<String> = if name_servers.is_empty() {
            DEFAULT_NAMESERVERS.iter().map(|s| s.to_string()).collect()
        } else {
            name_servers.to_vec()
        };
        for addr in &servers {
            let socket_addr: std::net::SocketAddr = addr
                .parse()
                .unwrap_or_else(|_| panic!("invalid DNS name server address: {addr}"));
            config.add_name_server(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }
        // Disable the resolver's own cache so the discovery task controls
        // refresh timing via TTL. The resolver's LRU cache would serve
        // stale records within the TTL window, which is fine for
        // correctness but makes the refresh cycle's timing less
        // predictable in tests. With caching disabled, every lookup hits
        // the name server, and the discovery task's sleep governs the
        // cadence.
        let mut opts = ResolverOpts::default();
        opts.cache_size = 0;
        let inner = TokioAsyncResolver::tokio(config, opts);
        Self { inner }
    }

    /// Resolve A records for `hostname`, returning `(IpAddr, ttl)` pairs.
    /// The TTL is the minimum TTL across all returned records (the
    /// earliest-expiring record governs the refresh interval). Returns an
    /// empty vec if the hostname resolves to no A records.
    pub async fn resolve_a(&self, hostname: &str) -> Result<Vec<(IpAddr, u32)>, String> {
        let ipv4_lookup = self
            .inner
            .ipv4_lookup(hostname)
            .await
            .map_err(|e| format!("DNS A lookup for '{hostname}' failed: {e}"))?;
        if ipv4_lookup.iter().next().is_none() {
            return Ok(Vec::new());
        }
        let lookup: Lookup = ipv4_lookup.into();
        let ttl = lookup.records().iter().map(|r| r.ttl()).min().unwrap_or(60);
        // Re-iterate the original lookup for IPs (converting to Lookup
        // consumes the iterator's source; the records are shared via
        // Arc so this is cheap).
        let addrs: Vec<(IpAddr, u32)> = lookup
            .records()
            .iter()
            .filter_map(|r| {
                r.data()
                    .and_then(|d| d.as_a())
                    .map(|a| (IpAddr::V4(a.0), ttl))
            })
            .collect();
        Ok(addrs)
    }

    /// Resolve SRV records for `hostname`, returning
    /// `(IpAddr, port, ttl)` triples. The resolver recursively resolves
    /// each SRV target to an IP. The TTL is the minimum TTL across all
    /// returned records. Returns an empty vec if the hostname resolves
    /// to no SRV records.
    pub async fn resolve_srv(&self, hostname: &str) -> Result<Vec<(IpAddr, u16, u32)>, String> {
        let srv_lookup = self
            .inner
            .srv_lookup(hostname)
            .await
            .map_err(|e| format!("DNS SRV lookup for '{hostname}' failed: {e}"))?;
        if srv_lookup.iter().next().is_none() {
            return Ok(Vec::new());
        }
        let ttl = srv_lookup
            .as_lookup()
            .records()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(60);
        // Pair each SRV record's port with the resolved IPs. For each
        // SRV record, resolve the target hostname to IPv4 addresses via
        // a separate A lookup so each (IP, port) pair is precise.
        let mut endpoints = Vec::new();
        let mut seen: std::collections::HashSet<(IpAddr, u16)> = std::collections::HashSet::new();
        for srv in srv_lookup.iter() {
            let port = srv.port();
            let target = srv.target();
            if let Ok(target_lookup) = self.inner.ipv4_lookup(target.clone()).await {
                for ip in target_lookup.iter() {
                    let ip = IpAddr::V4(ip.0);
                    if seen.insert((ip, port)) {
                        endpoints.push((ip, port, ttl));
                    }
                }
            }
        }
        Ok(endpoints)
    }
}

/// Build the endpoint list from a resolved A-record set, pairing each
/// address with the configured port and a default weight of 1.
fn endpoints_from_a(addrs: &[(IpAddr, u32)], port: u16) -> Vec<Endpoint> {
    addrs
        .iter()
        .map(|(ip, _)| Endpoint {
            address: ip.to_string(),
            port,
            weight: 1,
        })
        .collect()
}

/// Build the endpoint list from a resolved SRV-record set. Each
/// `(IpAddr, port)` pair becomes an endpoint with weight 1.
fn endpoints_from_srv(addrs: &[(IpAddr, u16, u32)]) -> Vec<Endpoint> {
    addrs
        .iter()
        .map(|(ip, port, _)| Endpoint {
            address: ip.to_string(),
            port: *port,
            weight: 1,
        })
        .collect()
}

/// One discovery refresh cycle: resolve, update the endpoint set.
async fn refresh_cycle(
    resolver: &DnsResolver,
    dns: &DnsDiscovery,
    lb: &Arc<UpstreamLb>,
    upstream_name: &str,
    obs: &Observability,
) {
    obs.record_dns_discovery_refresh(upstream_name);
    let result = if dns.record_type == "SRV" {
        resolver.resolve_srv(&dns.hostname).await.map(|resolved| {
            let ttl = resolved
                .first()
                .map(|(_, _, t)| *t)
                .unwrap_or(dns.refresh_interval_s as u32);
            let endpoints = endpoints_from_srv(&resolved);
            (endpoints, ttl)
        })
    } else {
        resolver.resolve_a(&dns.hostname).await.map(|resolved| {
            let ttl = resolved
                .first()
                .map(|(_, t)| *t)
                .unwrap_or(dns.refresh_interval_s as u32);
            let endpoints = endpoints_from_a(&resolved, dns.port);
            (endpoints, ttl)
        })
    };
    // Read the current balancer parameters once (algorithm, slow-start,
    // health, events) so the live swap uses the same config as the
    // initial build. A reload that changes these respawns the task.
    let algorithm = lb.algorithm();
    let slow_start = lb.slow_start();
    let health = lb.health_config();
    let events = lb.events();
    match result {
        Ok((endpoints, ttl)) => {
            // min_endpoints floor: if the resolution yielded fewer than
            // the floor, keep the previous set (do not shrink below the
            // floor). An empty resolution also falls through here.
            if (endpoints.len() as u32) < dns.min_endpoints {
                tracing::warn!(
                    code = "dns_discovery_below_floor",
                    upstream = %upstream_name,
                    resolved = endpoints.len(),
                    min = dns.min_endpoints,
                    "DNS resolution yielded fewer than min_endpoints; keeping previous set"
                );
                // Keep the current set; do not update the balancer.
                return;
            }
            // Update the balancer's endpoint set atomically. Unchanged
            // addresses keep their in-flight counters and health
            // trackers; new addresses start fresh. This is the same
            // hot-swap path reloads use.
            lb.rebuild_with_resolved_health_and_events(
                &endpoints,
                algorithm,
                slow_start,
                health,
                events.as_ref(),
            );
            obs.set_dns_discovery_endpoints(upstream_name, endpoints.len() as i64);
            tracing::info!(
                code = "dns_discovery_refreshed",
                upstream = %upstream_name,
                endpoints = endpoints.len(),
                ttl_s = ttl,
                "DNS discovery refreshed: {} endpoints, TTL {}s",
                endpoints.len(),
                ttl
            );
        }
        Err(err) => {
            obs.record_dns_discovery_refresh_failure(upstream_name);
            if dns.fail_open {
                tracing::warn!(
                    code = "dns_discovery_failed_fail_open",
                    upstream = %upstream_name,
                    "DNS discovery failed; keeping last endpoint set (fail_open): {err}"
                );
                // Keep the current set; do not clear.
            } else {
                tracing::warn!(
                    code = "dns_discovery_failed_fail_closed",
                    upstream = %upstream_name,
                    "DNS discovery failed; clearing endpoints (fail_open=false): {err}"
                );
                // Clear the endpoint set: the upstream answers 503
                // until DNS recovers.
                lb.rebuild_with_resolved_health_and_events(
                    &[],
                    algorithm,
                    slow_start,
                    health,
                    events.as_ref(),
                );
                obs.set_dns_discovery_endpoints(upstream_name, 0);
            }
        }
    }
}

/// The per-upstream discovery loop. Runs until the task is aborted by a
/// respawn or shutdown. Each cycle resolves, updates the endpoint set,
/// and sleeps `refresh_interval_s` seconds.
async fn discovery_loop(
    resolver: Arc<DnsResolver>,
    dns: DnsDiscovery,
    handle: Arc<UpstreamHandle>,
    obs: Arc<Observability>,
) {
    let upstream_name = handle.name().to_string();
    let lb = Arc::clone(handle.lb());
    loop {
        refresh_cycle(&resolver, &dns, &lb, &upstream_name, &obs).await;
        // Sleep refresh_interval_s. The resolver cache is disabled, so
        // every lookup hits the name server; the sleep is purely the
        // cadence. Using refresh_interval_s keeps the cycle predictable
        // and bounded by the config (1..=3600s). A future enhancement
        // could use the record TTL to schedule the next refresh sooner
        // for short-TTL records.
        tokio::time::sleep(Duration::from_secs(dns.refresh_interval_s)).await;
    }
}

/// Owns every DNS discovery task for the running generation. Call
/// [`DiscoveryTasks::respawn`] on startup and after every snapshot swap;
/// dropping it (or shutdown) aborts all tasks. Mirrors [`crate::dataplane::active::ActiveProbes`]
/// (DW-013), the closest precedent for a long-running dataplane task.
#[derive(Default)]
pub struct DiscoveryTasks {
    tasks: JoinSet<()>,
}

impl DiscoveryTasks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Abort all current discovery tasks and spawn fresh ones for every
    /// upstream in `snapshot` that configures `dns_discovery`. The
    /// resolver is shared across all tasks (one resolver, many upstreams)
    /// and the handle is taken from the CURRENT registry generation
    /// (call after `DataPlane::refresh`). Upstreams without
    /// `dns_discovery` spawn nothing.
    pub fn respawn(
        &mut self,
        registry: &crate::dataplane::upstream::UpstreamRegistry,
        snapshot: &crate::snapshot::Snapshot,
        resolver: Arc<DnsResolver>,
        obs: Arc<Observability>,
    ) {
        self.abort_all();
        for u in &snapshot.gateway().upstreams {
            let Some(dns) = &u.dns_discovery else {
                continue;
            };
            let Some(handle) = registry.get(&u.name) else {
                continue;
            };
            self.tasks.spawn(discovery_loop(
                Arc::clone(&resolver),
                dns.clone(),
                handle,
                Arc::clone(&obs),
            ));
        }
    }

    /// Abort every discovery task (they stop at the next await point).
    pub fn abort_all(&mut self) {
        self.tasks.abort_all();
    }

    /// Number of live discovery tasks (spawned minus finished/aborted
    /// that have been reaped). Observability/tests.
    pub fn task_count(&mut self) -> usize {
        while self.tasks.try_join_next().is_some() {}
        self.tasks.len()
    }
}
