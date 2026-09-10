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
//! the resolver's recursive lookup). The resolver is configured with the
//! SYSTEM resolver's name servers when `/etc/resolv.conf` is readable
//! (so container-internal names resolve), and the public Google
//! resolvers otherwise.
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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::config::{DnsDiscovery, Endpoint};
use crate::dataplane::balance::UpstreamLb;
use crate::dataplane::upstream::UpstreamHandle;
use crate::observability::Observability;

/// Default DNS name servers when none are explicitly configured AND the
/// system resolver config is unreadable: the public Google resolvers.
/// When `/etc/resolv.conf` is present and parses (the container case —
/// Docker and Kubernetes write their embedded resolver there), its name
/// servers are PREFERRED (see [`system_nameservers`]) so cluster-local
/// names (`my-svc`, `my-svc.ns.svc.cluster.local`) resolve: public
/// resolvers cannot answer those names, and an explicit-public-only
/// default would make every service-name endpoint unresolvable in a
/// container deployment.
const DEFAULT_NAMESERVERS: &[&str] = &["8.8.8.8:53", "8.8.4.4:53"];

/// Name servers from the system resolver configuration: the
/// `nameserver` lines of `/etc/resolv.conf` (the file Docker and
/// Kubernetes write their embedded resolver into). Returns None when
/// the file is absent, unreadable, or carries no `nameserver` lines —
/// the caller then falls back to [`DEFAULT_NAMESERVERS`]. Only the
/// server addresses are taken (port 53; DNS options and search domains
/// are ignored — cluster-local names resolve as-is against the embedded
/// resolver, which sets `ndots:0`). Hand-parsed rather than via
/// hickory's `system-config` feature: that feature drags in
/// platform-specific dependencies (ipconfig, jni, system-configuration)
/// for what is, on every container platform, a three-line file.
fn system_nameservers() -> Option<Vec<String>> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let servers: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("nameserver"))
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        // `ip:port` socket-addr form: IPv6 literals need brackets.
        .map(|ip| {
            if ip.contains(':') {
                format!("[{ip}]:53")
            } else {
                format!("{ip}:53")
            }
        })
        // Only well-formed addresses survive; a malformed line must not
        // panic the resolver constructor downstream.
        .filter(|addr| addr.parse::<SocketAddr>().is_ok())
        .collect();
    (!servers.is_empty()).then_some(servers)
}

/// A TTL-aware DNS resolver wrapping `hickory_resolver::TokioResolver`.
///
/// Configured with explicit name servers (the system resolver is not
/// used by default). `resolve_a` returns `(IpAddr, ttl)` pairs; `resolve_srv`
/// returns `(IpAddr, port, ttl)` triples.
pub struct DnsResolver {
    inner: TokioResolver,
}

impl DnsResolver {
    /// Build a resolver that queries the given name server addresses
    /// (e.g. `["127.0.0.1:5353"]`). An empty list falls back to the
    /// SYSTEM resolver configuration when one is readable (container
    /// deployments: Docker/Kubernetes embedded DNS), and to the default
    /// public resolvers otherwise (see [`system_nameservers`]).
    pub fn new(name_servers: &[String]) -> Self {
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        let servers: Vec<String> = if name_servers.is_empty() {
            system_nameservers()
                .unwrap_or_else(|| DEFAULT_NAMESERVERS.iter().map(|s| s.to_string()).collect())
        } else {
            name_servers.to_vec()
        };
        for addr in &servers {
            let socket_addr: std::net::SocketAddr = addr
                .parse()
                .unwrap_or_else(|_| panic!("invalid DNS name server address: {addr}"));
            // hickory 0.26: NameServerConfig takes an IpAddr and a vec of
            // ConnectionConfig. The port is on ConnectionConfig, not on
            // NameServerConfig (it defaulted to 53 in ::udp()). Set it
            // explicitly so non-53 ports (e.g. mock DNS servers in tests)
            // work. UDP-only is sufficient for discovery; the resolver
            // falls back to TCP for truncated responses automatically.
            let mut conn = hickory_resolver::config::ConnectionConfig::udp();
            conn.port = socket_addr.port();
            config.add_name_server(NameServerConfig::new(socket_addr.ip(), false, vec![conn]));
        }
        // Disable the resolver's own cache so the discovery task controls
        // refresh timing via TTL. The resolver's LRU cache would serve
        // stale records within the TTL window, which is fine for
        // correctness but makes the refresh cycle's timing less
        // predictable in tests. With caching disabled, every lookup hits
        // the name server, and the discovery task's sleep governs the
        // cadence.
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().cache_size = 0;
        let inner = builder
            .build()
            .expect("failed to build TokioResolver (invalid name server config)");
        Self { inner }
    }

    /// Resolve A records for `hostname`, returning `(IpAddr, ttl)` pairs.
    /// The TTL is the minimum TTL across all returned records (the
    /// earliest-expiring record governs the refresh interval). Returns an
    /// empty vec if the hostname resolves to no A records.
    pub async fn resolve_a(&self, hostname: &str) -> Result<Vec<(IpAddr, u32)>, String> {
        let lookup: Lookup = self
            .inner
            .ipv4_lookup(hostname)
            .await
            .map_err(|e| format!("DNS A lookup for '{hostname}' failed: {e}"))?;
        if lookup.answers().is_empty() {
            return Ok(Vec::new());
        }
        let ttl = lookup.answers().iter().map(|r| r.ttl).min().unwrap_or(60);
        let addrs: Vec<(IpAddr, u32)> = lookup
            .answers()
            .iter()
            .filter_map(|r| match r.data {
                hickory_resolver::proto::rr::RData::A(a) => Some((IpAddr::V4(a.0), ttl)),
                _ => None,
            })
            .collect();
        Ok(addrs)
    }

    /// Resolve both A and AAAA records for `hostname` (dual-stack), returning
    /// `(IpAddr, ttl)` pairs. This is the dial-path resolution primitive:
    /// `lookup_ip` short-circuits IP-literal inputs (no DNS), consults the
    /// system hosts file (so `localhost` and any `/etc/hosts` entry resolves
    /// without a network round-trip), and falls back to the configured name
    /// servers for real hostnames. The TTL is the minimum across all
    /// returned records (the earliest-expiring record governs caching).
    /// Returns an empty vec if the hostname resolves to no addresses.
    pub async fn resolve_ip(&self, hostname: &str) -> Result<Vec<(IpAddr, u32)>, String> {
        let lookup = self
            .inner
            .lookup_ip(hostname)
            .await
            .map_err(|e| format!("DNS lookup for '{hostname}' failed: {e}"))?;
        let answers = lookup.as_lookup().answers();
        if answers.is_empty() {
            return Ok(Vec::new());
        }
        let ttl = answers.iter().map(|r| r.ttl).min().unwrap_or(60);
        let addrs: Vec<(IpAddr, u32)> = lookup.iter().map(|ip| (ip, ttl)).collect();
        Ok(addrs)
    }

    /// Resolve SRV records for `hostname`, returning
    /// `(IpAddr, port, ttl)` triples. The resolver recursively resolves
    /// each SRV target to an IP. The TTL is the minimum TTL across all
    /// returned records. Returns an empty vec if the hostname resolves
    /// to no SRV records.
    pub async fn resolve_srv(&self, hostname: &str) -> Result<Vec<(IpAddr, u16, u32)>, String> {
        let lookup: Lookup = self
            .inner
            .srv_lookup(hostname)
            .await
            .map_err(|e| format!("DNS SRV lookup for '{hostname}' failed: {e}"))?;
        if lookup.answers().is_empty() {
            return Ok(Vec::new());
        }
        let ttl = lookup.answers().iter().map(|r| r.ttl).min().unwrap_or(60);
        // Pair each SRV record's port with the resolved IPs. For each
        // SRV record, resolve the target hostname to IPv4 addresses via
        // a separate A lookup so each (IP, port) pair is precise.
        let mut endpoints = Vec::new();
        let mut seen: std::collections::HashSet<(IpAddr, u16)> = std::collections::HashSet::new();
        for record in lookup.answers() {
            let srv = match &record.data {
                hickory_resolver::proto::rr::RData::SRV(srv) => srv,
                _ => continue,
            };
            let port = srv.port;
            let target = srv.target.clone();
            if let Ok(target_lookup) = self.inner.ipv4_lookup(target).await {
                for record in target_lookup.answers() {
                    if let hickory_resolver::proto::rr::RData::A(a) = record.data {
                        let ip = IpAddr::V4(a.0);
                        if seen.insert((ip, port)) {
                            endpoints.push((ip, port, ttl));
                        }
                    }
                }
            }
        }
        Ok(endpoints)
    }
}

/// Default cap on a cached positive lookup's effective TTL. Records carry
/// their own TTL (and `/etc/hosts` entries carry a very large TTL); this
/// caps the cache lifetime so a stale-but-cached address set does not
/// linger past operator expectations on the hot dial path.
const DEFAULT_POSITIVE_TTL_CAP: Duration = Duration::from_secs(300);
/// Default TTL for cached negative (failed) lookups. Short, to suppress
/// retry storms against a failing resolver while letting a flapping name
/// server recover quickly.
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(5);
/// Default max cached hostnames. Bounds memory; the dial path's working
/// set is the set of distinct upstream hostnames, which is small, but the
/// bound prevents unbounded growth under adversarial Host headers.
const DEFAULT_MAX_ENTRIES: usize = 4096;
/// Floor for a cached positive TTL so a zero-TTL record is still cached
/// briefly (avoids re-querying a name server that hands out TTL 0).
const POSITIVE_TTL_FLOOR: Duration = Duration::from_secs(1);

/// One cached DNS entry: either a positive resolution (address set +
/// expiry) or a negative one (failure + expiry). Negative entries cache
/// the FACT of failure, not the error text, so the cached miss returns a
/// stable `AddrNotAvailable` kind.
enum CacheEntry {
    Positive {
        addrs: Vec<IpAddr>,
        expires_at: Instant,
    },
    Negative {
        expires_at: Instant,
    },
}

/// A TTL-cached async DNS resolver for the pooled dial path (PERF-05,
/// #170).
///
/// Wraps [`DnsResolver`] (a hickory `TokioResolver`) with two caches
/// shared across every upstream in a registry:
///
/// - **Positive cache**: a successful lookup is reused until the record
///   TTL expires (capped at `positive_ttl_cap`), so repeated dials to the
///   same host skip both the blocking `getaddrinfo` path and the network
///   round-trip. The cap bounds `/etc/hosts` entries (which carry a
///   near-infinite TTL) and operator-facing staleness.
/// - **Negative cache**: a failed lookup is cached for `negative_ttl`
///   (default 5 s) so a transient resolver failure or NXDOMAIN does not
///   trigger a retry storm on the hottest code path; the cached miss
///   returns `AddrNotAvailable` until it expires, then re-resolves.
///
/// IP-literal hosts skip DNS and the cache entirely (the same
/// short-circuit `getaddrinfo` takes). The cache is `Send + Sync` (one
/// `tokio::sync::Mutex` over a `HashMap`); the critical section holds
/// only the map read/insert, never the resolver future.
pub struct DnsCache {
    resolver: DnsResolver,
    positive_ttl_cap: Duration,
    negative_ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl Default for DnsCache {
    /// Default cache: the system resolver's name servers when readable
    /// (else the public resolvers) + the system hosts file, default
    /// TTLs (positive cap 300 s, negative 5 s), 4096-entry bound.
    fn default() -> Self {
        Self::new(&[])
    }
}

impl DnsCache {
    /// Build a cache backed by the given name servers (empty = the
    /// resolver default: system config when readable, else the public
    /// resolvers; see [`DnsResolver::new`]) with the
    /// default TTLs and entry cap.
    pub fn new(name_servers: &[String]) -> Self {
        Self::with_ttls(
            name_servers,
            DEFAULT_POSITIVE_TTL_CAP,
            DEFAULT_NEGATIVE_TTL,
            DEFAULT_MAX_ENTRIES,
        )
    }

    /// Build a cache with explicit TTL/size knobs. Public so the
    /// dial-path cache contract (TTL expiry, negative caching, memory
    /// bound) can be pinned deterministically in tests without waiting
    /// out the default 5 s negative TTL.
    pub fn with_ttls(
        name_servers: &[String],
        positive_ttl_cap: Duration,
        negative_ttl: Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            resolver: DnsResolver::new(name_servers),
            positive_ttl_cap,
            negative_ttl,
            max_entries,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `host` to a list of `SocketAddr`s paired with `port`,
    /// consulting the cache first. IP-literal hosts skip DNS and the
    /// cache. Hostname hits return the cached address set (positive) or
    /// a cached `AddrNotAvailable` (negative, within `negative_ttl`);
    /// misses resolve via hickory and populate the cache.
    pub async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        // IP-literal short-circuit: no DNS, no cache entry. This is the
        // same path `getaddrinfo`/`lookup_host` took for literals, so
        // IP-endpoint configs (the common case, and every test fixture)
        // are unchanged.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        // Cache read. An expired entry is treated as a miss and replaced
        // after the fresh lookup (below); we do not evict here to keep
        // the critical section to a map read.
        {
            let map = self.entries.lock().await;
            if let Some(entry) = map.get(host) {
                match entry {
                    CacheEntry::Positive { addrs, expires_at } if *expires_at > Instant::now() => {
                        return Ok(addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
                    }
                    CacheEntry::Negative { expires_at } if *expires_at > Instant::now() => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            format!("cached DNS failure for '{host}'"),
                        ));
                    }
                    _ => {} // expired: fall through to a fresh lookup
                }
            }
        }
        // Resolve via hickory (async, no blocking-pool getaddrinfo).
        match self.resolver.resolve_ip(host).await {
            Ok(addrs) if !addrs.is_empty() => {
                let ttl = addrs
                    .iter()
                    .map(|(_, t)| {
                        Duration::from_secs(u64::from(*t))
                            .min(self.positive_ttl_cap)
                            .max(POSITIVE_TTL_FLOOR)
                    })
                    .min()
                    .unwrap_or(self.positive_ttl_cap);
                let ips: Vec<IpAddr> = addrs.iter().map(|(ip, _)| *ip).collect();
                let expires_at = Instant::now() + ttl;
                self.insert(
                    host.to_string(),
                    CacheEntry::Positive {
                        addrs: ips.clone(),
                        expires_at,
                    },
                )
                .await;
                Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
            }
            Ok(_) => {
                // No addresses (NXDOMAIN-ish): cache the miss briefly so
                // a misconfigured hostname does not hammer the resolver.
                let expires_at = Instant::now() + self.negative_ttl;
                self.insert(host.to_string(), CacheEntry::Negative { expires_at })
                    .await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("'{host}' resolved to no addresses"),
                ))
            }
            Err(e) => {
                let expires_at = Instant::now() + self.negative_ttl;
                self.insert(host.to_string(), CacheEntry::Negative { expires_at })
                    .await;
                Err(std::io::Error::other(format!(
                    "DNS lookup for '{host}' failed: {e}"
                )))
            }
        }
    }

    /// Insert an entry, evicting expired entries first when the cache is
    /// at capacity. The eviction pass is O(n) but only runs at the cap;
    /// the working set is small so this is bounded. If expired eviction
    /// does not free a slot (every entry still live), the new entry
    /// replaces the one with the nearest expiry (the next to expire
    /// anyway), keeping the cache at `max_entries` without dropping a
    /// long-lived entry.
    async fn insert(&self, host: String, entry: CacheEntry) {
        let mut map = self.entries.lock().await;
        let now = Instant::now();
        if map.len() >= self.max_entries {
            // Evict every expired entry first.
            map.retain(|_, e| match e {
                CacheEntry::Positive { expires_at, .. } => *expires_at > now,
                CacheEntry::Negative { expires_at } => *expires_at > now,
            });
        }
        if map.len() >= self.max_entries {
            // Still full: drop the entry nearest to expiry (the next
            // natural eviction). A fresh insert always wins over the
            // soonest-expiring resident.
            if let Some(victim) = map
                .iter()
                .min_by_key(|(_, e)| match e {
                    CacheEntry::Positive { expires_at, .. } => *expires_at,
                    CacheEntry::Negative { expires_at } => *expires_at,
                })
                .map(|(k, _)| k.clone())
            {
                map.remove(&victim);
            }
        }
        map.insert(host, entry);
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
            region: None,
            zone: None,
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
            region: None,
            zone: None,
        })
        .collect()
}

/// One discovery refresh cycle: resolve, update the endpoint set.
/// Returns `true` if the resolution succeeded, `false` on failure
/// (used by the caller to apply backoff).
async fn refresh_cycle(
    resolver: &DnsResolver,
    dns: &DnsDiscovery,
    lb: &Arc<UpstreamLb>,
    upstream_name: &str,
    obs: &Observability,
) -> bool {
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
    let peak_ewma = lb.peak_ewma_config();
    let locality = lb.locality_config();
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
                return true;
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
                peak_ewma.as_deref(),
                locality.as_deref(),
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
            true
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
                    peak_ewma.as_deref(),
                    locality.as_deref(),
                );
                obs.set_dns_discovery_endpoints(upstream_name, 0);
            }
            false
        }
    }
}

/// REL-12 (#223): maximum backoff cap (5 minutes). After this cap is
/// reached, the loop continues at the cap until a successful resolution
/// resets it.
const DNS_BACKOFF_MAX_S: u64 = 300;

/// The per-upstream discovery loop. Runs until the task is aborted by a
/// respawn or shutdown. Each cycle resolves, updates the endpoint set,
/// and sleeps `refresh_interval_s` seconds. REL-12 (#223): on failure,
/// applies exponential backoff (doubled each failure, capped at
/// `DNS_BACKOFF_MAX_S`) to avoid hammering the DNS server during an
/// outage. A successful resolution resets the backoff to
/// `refresh_interval_s`.
async fn discovery_loop(
    resolver: Arc<DnsResolver>,
    dns: DnsDiscovery,
    handle: Arc<UpstreamHandle>,
    obs: Arc<Observability>,
) {
    let upstream_name = handle.name().to_string();
    let lb = Arc::clone(handle.lb());
    // REL-12 (#223): current backoff interval. Starts at
    // refresh_interval_s; doubled on each failure, capped at
    // DNS_BACKOFF_MAX_S. Reset to refresh_interval_s on success.
    let mut backoff_s = dns.refresh_interval_s;
    loop {
        let ok = refresh_cycle(&resolver, &dns, &lb, &upstream_name, &obs).await;
        let sleep_s = if ok {
            // Success: reset backoff to the configured refresh interval.
            backoff_s = dns.refresh_interval_s;
            dns.refresh_interval_s
        } else {
            // Failure: sleep the current backoff, then double it for
            // the next failure (capped at DNS_BACKOFF_MAX_S).
            let current = backoff_s;
            backoff_s = (backoff_s * 2).min(DNS_BACKOFF_MAX_S);
            current
        };
        tokio::time::sleep(Duration::from_secs(sleep_s)).await;
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
