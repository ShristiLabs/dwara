//! Integration tests for the async cached DNS dial path (PERF-05, #170).
//!
//! The developer's `tests/dns_discovery.rs` pins the `DnsCache` caching
//! contract (positive hit, TTL expiry, negative caching, IP-literal
//! short-circuit) through the public `DnsCache::resolve` API in isolation.
//! These suites exercise the SAME cache through the actual dial path that
//! the pooled connector uses — `happy_dial_via` (the RFC 8305 resolve+dial
//! the connector calls) and the full reverse proxy — so the integration of
//! the cache with the connect/racing machinery and the gateway is covered:
//!
//! 1. End-to-end through the proxy: an upstream whose endpoint is a
//!    hostname (`localhost`, resolved via the system hosts file hickory
//!    consults) reaches a real backend — the cached DNS dial path works
//!    under the full proxy action.
//! 2. IP-literal short-circuit through the proxy: an `127.0.0.1` endpoint
//!    bypasses DNS on the new `happy_dial_via` dial path.
//! 3. Positive cache hit on the dial path: `happy_dial_via` + a `DnsCache`
//!    backed by a mock DNS server + a real TCP backend. After the first
//!    dial resolves and populates the cache, the DNS server is killed; a
//!    second dial still connects (the cache served the address set without
//!    a network round-trip). Killing the server is the deterministic
//!    "no-query" proof — a non-cached dial would fail to reach the dead
//!    server.
//! 4. Negative cache on the dial path: `happy_dial_via` against a name the
//!    mock does not serve fails; after the server is killed a second dial
//!    returns the cached `AddrNotAvailable` (not a network error), proving
//!    the miss was served from the cache without re-querying.
//! 5. End-to-end DNS failure through the proxy: an unresolvable hostname
//!    (a >63-octet label that hickory rejects at name-parse time, so the
//!    failure is deterministic and network-independent) yields 502 on
//!    every attempt; a second request fails consistently (the cached
//!    negative miss is served, not a hang or panic).
//!
//! The mock DNS server binds to `127.0.0.1:0` (OS-assigned port); each
//! test uses its own instance on a unique port. The dial-path tests use
//! `happy_dial_via` directly (the same function the pooled connector
//! calls) so the cache+race integration is exercised without the full
//! proxy, which cannot inject a custom `DnsCache` (the registry builds
//! `DnsCache::default()` with the public resolvers + system hosts file).

mod support;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use dwara_core::dataplane::discovery::DnsCache;
use dwara_core::dataplane::upstream::happy_dial_via;
use hickory_resolver::proto::rr::{
    rdata::SOA, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
};
use hickory_server::server::Server;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{Catalog, ZoneType};
use hyper::StatusCode;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

use support::{body_text, dataplane_from, h1_client, spawn_backend_full, spawn_gateway, uri};

/// A mock DNS server serving A records for `svc.test.` at the given IPs
/// with the given TTL. Binds to `127.0.0.1:0` (OS-assigned port); the port
/// is available via `addr()`. Dropping it cancels the background tasks.
/// (Mirrors the fixture in `tests/dns_discovery.rs`; kept local because it
/// is suite-specific and not in the shared support module.)
struct MockDnsServer {
    _server: Option<Server<Catalog>>,
    addr: std::net::SocketAddr,
}

impl MockDnsServer {
    async fn start(ips: &[&str], ttl: u32) -> Self {
        let zone_name: Name = Name::parse("svc.test.", None).unwrap();
        let mut records: BTreeMap<RrKey, RecordSet> = BTreeMap::new();

        let soa_key = RrKey::new(zone_name.clone().into(), RecordType::SOA);
        let mut soa_rset = RecordSet::new(zone_name.clone(), RecordType::SOA, 0);
        let soa = SOA::new(
            Name::parse("ns.svc.test.", None).unwrap(),
            Name::parse("admin.svc.test.", None).unwrap(),
            0,
            ttl as i32,
            ttl as i32,
            ttl as i32,
            ttl,
        );
        soa_rset.insert(
            Record::from_rdata(zone_name.clone(), ttl, RData::SOA(soa)),
            0,
        );
        records.insert(soa_key, soa_rset);

        let a_key = RrKey::new(zone_name.clone().into(), RecordType::A);
        let mut a_rset = RecordSet::new(zone_name.clone(), RecordType::A, 0);
        for ip in ips {
            let ip_addr: IpAddr = ip.parse().unwrap();
            let rdata = match ip_addr {
                IpAddr::V4(v4) => RData::A(v4.into()),
                IpAddr::V6(_) => panic!("mock server only serves A records"),
            };
            a_rset.insert(Record::from_rdata(zone_name.clone(), ttl, rdata), 0);
        }
        records.insert(a_key, a_rset);

        let authority =
            InMemoryZoneHandler::<hickory_server::net::runtime::TokioRuntimeProvider>::new(
                zone_name.clone(),
                records,
                ZoneType::Primary,
                hickory_server::zone_handler::AxfrPolicy::Deny,
            )
            .unwrap();

        let mut catalog = Catalog::new();
        catalog.upsert(LowerName::from(&zone_name), vec![Arc::new(authority)]);

        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp_socket.local_addr().unwrap();

        let mut server = Server::new(catalog);
        server.register_socket(udp_socket);

        Self {
            _server: Some(server),
            addr,
        }
    }

    fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }
}

/// A minimal TCP "backend" that accepts connections on 127.0.0.1 and
/// immediately drops them. Enough for `happy_dial_via` to succeed a
/// connect (the dial-path cache test only needs the connect to win, not a
/// full HTTP exchange). Returns the port the listener is on.
async fn echo_listener_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((_stream, _)) => {
                    // Drop the stream immediately; the dial only needs the
                    // accept to succeed.
                }
                Err(_) => continue,
            }
        }
    });
    port
}

/// One `/api` route to one upstream whose endpoint `address` is the given
/// host (a hostname or IP literal) and `port` is the backend port.
fn proxy_yaml_host(host: &str, backend_port: u16) -> String {
    format!(
        "routes:\n\
         - name: all\n\
         \x20 service: svc\n\
         \x20 match:\n\
         \x20   path:\n\
         \x20     type: prefix\n\
         \x20     value: /api\n\
         \x20 action:\n\
         \x20   type: proxy\n\
         services:\n\
         - name: svc\n\
         \x20 upstream: up\n\
         upstreams:\n\
         - name: up\n\
         \x20 endpoints:\n\
         \x20   - address: {host}\n\
         \x20     port: {backend_port}\n"
    )
}

// ---------------------------------------------------------------------------
// 1. End-to-end through the proxy: hostname endpoint reaches the backend
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_dials_hostname_endpoint_through_cached_dns() {
    // `localhost` resolves via the system hosts file hickory consults
    // (use_hosts_file = Auto by default) to 127.0.0.1 (+ ::1); the
    // happy-eyeballs race connects to 127.0.0.1 where the backend lives.
    // This proves the full proxy -> happy_dial_via -> DnsCache -> lookup_ip
    // -> /etc/hosts -> connect path works end-to-end.
    let backend = spawn_backend_full(Arc::new(|_req| {
        hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from_static(
            b"host-ok",
        )))
    }))
    .await;
    let dp = dataplane_from(&proxy_yaml_host("localhost", backend));
    let port = spawn_gateway(dp).await;

    let resp = h1_client().get(uri(port, "/api/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "host-ok");
}

// ---------------------------------------------------------------------------
// 2. IP-literal short-circuit through the proxy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_dials_ip_literal_endpoint_skipping_dns() {
    // An IP-literal endpoint never hits the cache's resolver branch (the
    // short-circuit in DnsCache::resolve). This pins that the new
    // happy_dial_via dial path preserves the IP-literal fast path that
    // every IP-endpoint test fixture relies on.
    let backend = spawn_backend_full(Arc::new(|_req| {
        hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from_static(
            b"ip-ok",
        )))
    }))
    .await;
    let dp = dataplane_from(&proxy_yaml_host("127.0.0.1", backend));
    let port = spawn_gateway(dp).await;

    let resp = h1_client().get(uri(port, "/api/x")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp.into_body()).await, "ip-ok");
}

// ---------------------------------------------------------------------------
// 3. Positive cache hit on the dial path (happy_dial_via + DnsCache)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dial_path_reuses_cached_resolution_after_dns_server_dies() {
    // The mock serves svc.test. -> 127.0.0.1 (the echo listener's IP) at a
    // 60s TTL. Dial 1 resolves via the mock and connects to the listener.
    // Dial 2 hits the positive cache (still within TTL) and connects.
    // Then the DNS server is killed; Dial 3 MUST still connect — the
    // cached address set is served without a network round-trip. A
    // non-cached dial against the dead server would fail to resolve.
    let backend_port = echo_listener_port().await;
    let dns_server = MockDnsServer::start(&["127.0.0.1"], 60).await;
    let cache = DnsCache::new(&[dns_server.addr().to_string()]);

    // Dial 1: cache miss -> query the mock -> connect to 127.0.0.1.
    let s1 = happy_dial_via(&cache, "svc.test.", backend_port, None)
        .await
        .expect("first dial resolves and connects");
    assert_eq!(
        s1.peer_addr().unwrap().ip(),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
    drop(s1);

    // Dial 2: cache hit (within TTL) -> connect, no query.
    let s2 = happy_dial_via(&cache, "svc.test.", backend_port, None)
        .await
        .expect("second dial reuses the cached address");
    assert_eq!(
        s2.peer_addr().unwrap().ip(),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
    drop(s2);

    // Kill the DNS server. A fresh (non-cached) resolution would now fail
    // (server unreachable); the cached entry must still serve the address.
    drop(dns_server);
    let s3 = happy_dial_via(&cache, "svc.test.", backend_port, None)
        .await
        .expect("third dial served from the cache with the DNS server dead");
    assert_eq!(
        s3.peer_addr().unwrap().ip(),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
}

// ---------------------------------------------------------------------------
// 4. Negative cache on the dial path (happy_dial_via + DnsCache)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dial_path_serves_cached_negative_miss_without_requery() {
    // A name the mock does not serve -> NXDOMAIN -> cached negative. Kill
    // the server; a second dial must return the cached AddrNotAvailable
    // (NOT a network error), proving the miss was served from the cache
    // without re-querying the dead server.
    let backend_port = echo_listener_port().await;
    let dns_server = MockDnsServer::start(&["127.0.0.1"], 60).await;
    let cache = DnsCache::with_ttls(
        &[dns_server.addr().to_string()],
        std::time::Duration::from_secs(300),
        std::time::Duration::from_secs(60),
        4096,
    );

    // First dial: the mock does not serve nope.test. -> failure (cached).
    let first = happy_dial_via(&cache, "nope.test.", backend_port, None).await;
    assert!(first.is_err(), "expected failure for unserved name");

    // Kill the server. A non-cached negative would now be a network error
    // (server unreachable); the cached miss is served as AddrNotAvailable.
    drop(dns_server);
    let second = happy_dial_via(&cache, "nope.test.", backend_port, None).await;
    assert!(second.is_err(), "expected cached negative");
    assert_eq!(
        second.unwrap_err().kind(),
        std::io::ErrorKind::AddrNotAvailable,
        "negative cache must return AddrNotAvailable, not a network error"
    );
}

// ---------------------------------------------------------------------------
// 5. End-to-end DNS failure through the proxy: unresolvable hostname -> 502
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_dial_path_returns_502_for_unresolvable_hostname() {
    // A single label longer than 63 octets is rejected by hickory at
    // name-parse time (into_name), so the lookup fails immediately without
    // any network round-trip — deterministic and CI-sandbox-safe. The
    // DnsCache caches the negative miss; both requests surface 502
    // (UpstreamError::Io -> BAD_GATEWAY) consistently, proving the dial
    // path handles DNS failure end-to-end without hanging or panicking.
    let long_label = "a".repeat(70); // > 63-octet label limit
    let host = format!("{long_label}.test");
    // No backend is needed (the dial never connects).
    let dp = dataplane_from(&proxy_yaml_host(&host, 1));
    let port = spawn_gateway(dp).await;

    let resp1 = h1_client().get(uri(port, "/api/x")).await.unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::BAD_GATEWAY,
        "unresolvable hostname must surface 502"
    );
    // Drain the error body so the connection is released back to the pool.
    let _ = body_text(resp1.into_body()).await;

    // Second request: the cached negative miss is served consistently.
    let resp2 = h1_client().get(uri(port, "/api/x")).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_GATEWAY,
        "second request must also surface 502 (cached negative miss)"
    );
}
