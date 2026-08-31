//! Integration tests for DNS-based dynamic upstream discovery (DW-042).
//!
//! These tests spin up an in-process DNS authority/server using
//! `hickory-server`, point a `DnsResolver` at it, and verify:
//!
//! 1. A-record resolution returns the expected IPs and TTL.
//! 2. The `DiscoveryTasks` lifecycle: respawn spawns tasks, abort_all
//!    cancels them, and task_count reflects the live set.
//! 3. A live endpoint-set swap: the balancer's endpoint set changes
//!    after a discovery refresh resolves new IPs.
//! 4. Config validation: `dns_discovery` allows empty `endpoints`;
//!    invalid `record_type` and out-of-bounds `refresh_interval_s` are
//!    rejected.
//!
//! The mock DNS server binds to `127.0.0.1:0` (OS-assigned port) and
//! serves A records for `svc.test.` with a short TTL. Each test creates
//! its own server instance on a unique port (no cross-test contention).

mod support;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dwara_core::config::parse_gateway;
use dwara_core::dataplane::discovery::{DiscoveryTasks, DnsResolver};
use dwara_core::observability::Observability;
use dwara_core::snapshot::{self, ConfigState};
use hickory_resolver::proto::rr::{
    rdata::SOA, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
};
use hickory_server::server::Server;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{Catalog, ZoneType};
use tokio::net::UdpSocket;

/// A mock DNS server serving A records for `svc.test.` at the given IPs
/// with the given TTL. Binds to `127.0.0.1:0` (OS-assigned port); the
/// port is available via `addr()`. Dropping it cancels the background
/// tasks (Server's Drop cancels the shutdown token).
struct MockDnsServer {
    _server: Option<Server<Catalog>>,
    addr: std::net::SocketAddr,
}

impl MockDnsServer {
    /// Start a mock DNS server serving A records for `svc.test.` at the
    /// given IPs with the given TTL.
    async fn start(ips: &[&str], ttl: u32) -> Self {
        let zone_name: Name = Name::parse("svc.test.", None).unwrap();
        let mut records: BTreeMap<RrKey, RecordSet> = BTreeMap::new();

        // SOA record (required by InMemoryZoneHandler).
        let soa_key = RrKey::new(zone_name.clone().into(), RecordType::SOA);
        let mut soa_rset = RecordSet::new(zone_name.clone(), RecordType::SOA, 0);
        let soa = SOA::new(
            Name::parse("ns.svc.test.", None).unwrap(),    // mname
            Name::parse("admin.svc.test.", None).unwrap(), // rname
            0,                                             // serial
            ttl as i32,                                    // refresh
            ttl as i32,                                    // retry
            ttl as i32,                                    // expire
            ttl,                                           // minimum
        );
        soa_rset.insert(
            Record::from_rdata(zone_name.clone(), ttl, RData::SOA(soa)),
            0,
        );
        records.insert(soa_key, soa_rset);

        // Build the A record set for `svc.test.`
        let a_key = RrKey::new(zone_name.clone().into(), RecordType::A);
        let mut a_rset = RecordSet::new(zone_name.clone(), RecordType::A, 0);
        for ip in ips {
            let ip_addr: IpAddr = ip.parse().unwrap();
            let rdata = match ip_addr {
                IpAddr::V4(v4) => RData::A(v4.into()),
                IpAddr::V6(_) => panic!("mock server only serves A records"),
            };
            let record = Record::from_rdata(zone_name.clone(), ttl, rdata);
            a_rset.insert(record, 0);
        }
        records.insert(a_key, a_rset);

        // hickory-server 0.26: InMemoryAuthority -> InMemoryZoneHandler.
        // The constructor takes (origin, records, zone_type, axfr_policy).
        // The default TokioRuntimeProvider is used.
        let authority =
            InMemoryZoneHandler::<hickory_server::net::runtime::TokioRuntimeProvider>::new(
                zone_name.clone(),
                records,
                ZoneType::Primary,
                hickory_server::zone_handler::AxfrPolicy::Deny,
            )
            .unwrap();

        let mut catalog = Catalog::new();
        // hickory-server 0.26: upsert takes Vec<Arc<dyn ZoneHandler>>.
        catalog.upsert(LowerName::from(&zone_name), vec![Arc::new(authority)]);

        // Use tokio::net::UdpSocket (register_socket expects it).
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp_socket.local_addr().unwrap();

        let mut server = Server::new(catalog);
        server.register_socket(udp_socket);

        Self {
            _server: Some(server),
            addr,
        }
    }

    /// The address the DNS server is listening on.
    fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }
}

/// Build a minimal gateway YAML with one DNS-discovered upstream and
/// `allow_empty_routes: true` (no routes needed for discovery tests).
fn gateway_yaml_with_dns(dns_yaml: &str) -> String {
    format!(
        "allow_empty_routes: true
listeners: []
routes: []
upstreams:
- name: dns-pool
{dns_yaml}
"
    )
}

/// Build a minimal gateway YAML with one static upstream (no DNS
/// discovery) and `allow_empty_routes: true`.
fn gateway_yaml_static() -> String {
    "allow_empty_routes: true
listeners: []
routes: []
upstreams:
- name: static-pool
  endpoints:
  - address: 127.0.0.1
    port: 9001
"
    .to_string()
}

/// Parse a gateway YAML and publish it to a new ConfigState.
fn make_state(yaml: &str) -> Arc<ConfigState> {
    let gateway = parse_gateway(yaml).unwrap_or_else(|e| panic!("invalid config: {e}"));
    let state = Arc::new(ConfigState::new());
    state.compile_and_publish(&gateway).unwrap();
    state
}

// ---------------------------------------------------------------------------
// 1. DnsResolver: A-record resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolver_resolves_a_records() {
    let dns_server = MockDnsServer::start(&["127.0.0.10", "127.0.0.11"], 60).await;
    let resolver = DnsResolver::new(&[dns_server.addr().to_string()]);
    let result = resolver.resolve_a("svc.test.").await.unwrap();
    assert_eq!(result.len(), 2);
    let ips: Vec<IpAddr> = result.iter().map(|(ip, _)| *ip).collect();
    assert!(ips.contains(&"127.0.0.10".parse::<IpAddr>().unwrap()));
    assert!(ips.contains(&"127.0.0.11".parse::<IpAddr>().unwrap()));
    // TTL should be 60 (the TTL we set on the records).
    let ttl = result.first().map(|(_, t)| *t).unwrap();
    assert_eq!(ttl, 60);
}

#[tokio::test]
async fn resolver_returns_error_for_nonexistent_hostname() {
    let dns_server = MockDnsServer::start(&["127.0.0.10"], 60).await;
    let resolver = DnsResolver::new(&[dns_server.addr().to_string()]);
    // The mock server only serves svc.test.; a different hostname
    // should return an error (NXDOMAIN).
    let result = resolver.resolve_a("nonexistent.test.").await;
    assert!(result.is_err(), "expected error for nonexistent hostname");
}

#[tokio::test]
async fn resolver_falls_back_to_default_nameservers() {
    // No name servers provided: should fall back to defaults without
    // panicking (the resolver is constructed, but we don't query it —
    // the default public resolvers may not be reachable in CI).
    let _resolver = DnsResolver::new(&[]);
}

// ---------------------------------------------------------------------------
// 2. DiscoveryTasks lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_tasks_respawn_and_abort() {
    let dns_server = MockDnsServer::start(&["127.0.0.10", "127.0.0.11"], 60).await;
    let resolver = Arc::new(DnsResolver::new(&[dns_server.addr().to_string()]));
    let obs = Arc::new(Observability::from_env());

    let yaml = gateway_yaml_with_dns(
        "  dns_discovery:\n\
         \x20   hostname: svc.test.\n\
         \x20   port: 8080\n\
         \x20   refresh_interval_s: 1",
    );
    let state = make_state(&yaml);
    let dp = dwara_core::proxy::DataPlane::new(Arc::clone(&state));

    let mut discovery = DiscoveryTasks::new();
    discovery.respawn(
        &dp.registry(),
        &state.snapshot(),
        Arc::clone(&resolver),
        Arc::clone(&obs),
    );

    // One upstream with dns_discovery -> one task.
    assert_eq!(discovery.task_count(), 1);

    // Abort all tasks. The abort is async — yield to let the runtime
    // process the abort signals before checking task_count.
    discovery.abort_all();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(discovery.task_count(), 0);
}

#[tokio::test]
async fn discovery_tasks_no_tasks_for_static_upstreams() {
    let dns_server = MockDnsServer::start(&["127.0.0.10"], 60).await;
    let resolver = Arc::new(DnsResolver::new(&[dns_server.addr().to_string()]));
    let obs = Arc::new(Observability::from_env());

    let yaml = gateway_yaml_static();
    let state = make_state(&yaml);
    let dp = dwara_core::proxy::DataPlane::new(Arc::clone(&state));

    let mut discovery = DiscoveryTasks::new();
    discovery.respawn(
        &dp.registry(),
        &state.snapshot(),
        Arc::clone(&resolver),
        Arc::clone(&obs),
    );

    // No upstream with dns_discovery -> zero tasks.
    assert_eq!(discovery.task_count(), 0);
}

// ---------------------------------------------------------------------------
// 3. Live endpoint-set swap via discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_updates_endpoint_set_live() {
    let dns_server = MockDnsServer::start(&["127.0.0.10", "127.0.0.11"], 60).await;
    let resolver = Arc::new(DnsResolver::new(&[dns_server.addr().to_string()]));
    let obs = Arc::new(Observability::from_env());

    let yaml = gateway_yaml_with_dns(
        "  dns_discovery:\n\
         \x20   hostname: svc.test.\n\
         \x20   port: 8080\n\
         \x20   refresh_interval_s: 1",
    );
    let state = make_state(&yaml);
    let dp = dwara_core::proxy::DataPlane::new(Arc::clone(&state));

    // The upstream starts with 0 endpoints (dns_discovery, no static
    // endpoints). The discovery task will resolve and update the set.
    let handle = dp.registry().get("dns-pool").unwrap();
    assert_eq!(handle.lb().len(), 0);

    // Spawn discovery tasks.
    let mut discovery = DiscoveryTasks::new();
    discovery.respawn(
        &dp.registry(),
        &state.snapshot(),
        Arc::clone(&resolver),
        Arc::clone(&obs),
    );

    // Poll until the balancer's endpoint set is updated (the discovery
    // task resolves on the first cycle). Bounded polls with a generous
    // margin — the resolver hits the mock server directly (no cache).
    let mut updated = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if handle.lb().len() == 2 {
            updated = true;
            break;
        }
    }
    assert!(
        updated,
        "discovery task did not update the endpoint set within 5s"
    );

    // Verify the endpoints are at port 8080.
    let ep0 = handle.lb().endpoint(0).unwrap();
    assert_eq!(ep0.1, 8080);
    let ep1 = handle.lb().endpoint(1).unwrap();
    assert_eq!(ep1.1, 8080);

    discovery.abort_all();
}

// ---------------------------------------------------------------------------
// 4. Config validation
// ---------------------------------------------------------------------------

#[test]
fn validation_allows_empty_endpoints_with_dns_discovery() {
    let yaml = gateway_yaml_with_dns(
        "  dns_discovery:\n\
         \x20   hostname: svc.test.\n\
         \x20   port: 8080\n\
         \x20   refresh_interval_s: 30",
    );
    let gateway = parse_gateway(&yaml).unwrap();
    let issues = snapshot::validate(&gateway);
    // No "upstream has no endpoints" issue (dns_discovery is present).
    assert!(
        !issues
            .iter()
            .any(|i| i.field == "endpoints" && i.message.contains("no endpoints")),
        "expected no 'no endpoints' issue when dns_discovery is present; got: {:?}",
        issues
    );
}

#[test]
fn validation_rejects_empty_endpoints_without_dns_discovery() {
    let yaml = "allow_empty_routes: true\n\
                listeners: []\n\
                routes: []\n\
                upstreams:\n\
                - name: static-pool\n";
    let gateway = parse_gateway(yaml).unwrap();
    let issues = snapshot::validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "endpoints" && i.message.contains("no endpoints")),
        "expected 'no endpoints' issue when dns_discovery is absent"
    );
}

#[test]
fn validation_rejects_invalid_record_type() {
    let yaml = gateway_yaml_with_dns(
        "  dns_discovery:\n\
         \x20   hostname: svc.test.\n\
         \x20   port: 8080\n\
         \x20   refresh_interval_s: 30\n\
         \x20   record_type: CNAME",
    );
    let gateway = parse_gateway(&yaml).unwrap();
    let issues = snapshot::validate(&gateway);
    assert!(
        issues.iter().any(|i| i.field == "dns_discovery.record_type"
            && i.message.contains("A")
            && i.message.contains("SRV")),
        "expected record_type validation issue; got: {:?}",
        issues
    );
}

#[test]
fn validation_rejects_out_of_bounds_refresh_interval() {
    let yaml = gateway_yaml_with_dns(
        "  dns_discovery:\n\
         \x20   hostname: svc.test.\n\
         \x20   port: 8080\n\
         \x20   refresh_interval_s: 0",
    );
    let gateway = parse_gateway(&yaml).unwrap();
    let issues = snapshot::validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "dns_discovery.refresh_interval_s"),
        "expected refresh_interval_s validation issue; got: {:?}",
        issues
    );
}

#[test]
fn validation_rejects_empty_hostname() {
    let yaml = gateway_yaml_with_dns(
        "  dns_discovery:\n\
         \x20   hostname: ''\n\
         \x20   port: 8080\n\
         \x20   refresh_interval_s: 30",
    );
    let gateway = parse_gateway(&yaml).unwrap();
    let issues = snapshot::validate(&gateway);
    assert!(
        issues
            .iter()
            .any(|i| i.field == "dns_discovery.hostname" && i.message.contains("empty")),
        "expected hostname validation issue; got: {:?}",
        issues
    );
}
