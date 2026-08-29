//! Unit tests for `dataplane::proxy_proto` (DW-030): header reading,
//! the effective-address policy (PROXY source vs the spec's LOCAL /
//! UNKNOWN / AF_UNSPEC fallbacks to the real peer), the fail-closed
//! malformed path with its 400 envelope, and the pipelined-bytes replay
//! prefix. Driven over `tokio::io::duplex` streams — the framing read
//! is the unit under test, not the sockets.

use std::net::SocketAddr;
use std::time::Duration;

use ppp::v2::{Addresses, Command, IPv4, IPv6, Protocol, Unix, Version};
use tokio::io::AsyncReadExt as _;

use dwara_core::dataplane::proxy_proto::{read_client_addr, reject_malformed, ProxyProtoError};

fn real_peer() -> SocketAddr {
    "127.0.0.9:4242".parse().unwrap()
}

/// Drive one header read over a duplex pair; returns the outcome.
async fn read_written(
    bytes: &[u8],
) -> Result<dwara_core::dataplane::proxy_proto::ProxyHeader, ProxyProtoError> {
    let (mut client, mut server) = tokio::io::duplex(4096);
    client.write_all_and_flush(bytes).await;
    read_client_addr(&mut server, real_peer(), Duration::from_secs(5)).await
}

/// Small helper: write then flush (duplex buffers need the flush to be
/// observable on the other side deterministically).
trait WriteFlush: tokio::io::AsyncWrite + Unpin {
    async fn write_all_and_flush(&mut self, bytes: &[u8]) {
        tokio::io::AsyncWriteExt::write_all(self, bytes)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(self).await.unwrap();
    }
}
impl<T: tokio::io::AsyncWrite + Unpin> WriteFlush for T {}

#[tokio::test]
async fn v1_tcp4_header_yields_source_and_replays_pipelined_bytes() {
    let mut line = b"PROXY TCP4 203.0.113.7 10.0.0.1 55555 8080\r\n".to_vec();
    line.extend_from_slice(b"GET /api HTTP/1.1\r\nHost: x\r\n\r\n");
    let h = read_written(&line).await.expect("v1 header parses");
    assert_eq!(h.client, "203.0.113.7:55555".parse::<SocketAddr>().unwrap());
    // "PROXY TCP4 203.0.113.7 10.0.0.1 55555 8080\r\n" is 44 bytes.
    assert_eq!(h.consumed, 44);
    assert_eq!(h.prefix, b"GET /api HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
}

#[tokio::test]
async fn v1_tcp6_header_yields_ipv6_source() {
    let h = read_written(b"PROXY TCP6 2001:db8::1 2001:db8::2 4444 80\r\n")
        .await
        .expect("v1 tcp6 header parses");
    assert_eq!(
        h.client,
        "[2001:db8::1]:4444".parse::<SocketAddr>().unwrap()
    );
    assert!(h.prefix.is_empty());
}

#[tokio::test]
async fn v1_unknown_keeps_the_real_peer() {
    let h = read_written(b"PROXY UNKNOWN\r\n")
        .await
        .expect("UNKNOWN parses");
    assert_eq!(h.client, real_peer());
}

#[tokio::test]
async fn v2_proxy_ipv4_yields_source_and_replays_pipelined_bytes() {
    let vc = Version::Two as u8 | Command::Proxy as u8;
    let mut header = ppp::v2::Builder::with_addresses(
        vc,
        Protocol::Stream,
        IPv4::new([203, 0, 113, 9], [10, 0, 0, 1], 55555, 8080),
    )
    .build()
    .unwrap();
    let consumed = header.len();
    header.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
    let h = read_written(&header).await.expect("v2 header parses");
    assert_eq!(h.client, "203.0.113.9:55555".parse::<SocketAddr>().unwrap());
    assert_eq!(h.consumed, consumed);
    assert_eq!(h.prefix, b"GET / HTTP/1.1\r\n\r\n".to_vec());
}

#[tokio::test]
async fn v2_proxy_ipv6_yields_source() {
    let vc = Version::Two as u8 | Command::Proxy as u8;
    let header = ppp::v2::Builder::with_addresses(
        vc,
        Protocol::Stream,
        IPv6::new(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            4444,
            80,
        ),
    )
    .build()
    .unwrap();
    let h = read_written(&header).await.expect("v2 ipv6 header parses");
    assert_eq!(
        h.client,
        "[2001:db8::1]:4444".parse::<SocketAddr>().unwrap()
    );
}

#[tokio::test]
async fn v2_local_command_keeps_the_real_peer_whatever_the_addresses() {
    // LOCAL is the LB's own connection (health checks); the spec's
    // fallback is the real peer even when address fields are populated
    // or claim a datagram protocol.
    let vc = Version::Two as u8 | Command::Local as u8;
    let header = ppp::v2::Builder::with_addresses(
        vc,
        Protocol::Datagram,
        IPv4::new([203, 0, 113, 9], [10, 0, 0, 1], 55555, 8080),
    )
    .build()
    .unwrap();
    let h = read_written(&header).await.expect("LOCAL header parses");
    assert_eq!(h.client, real_peer());
}

#[tokio::test]
async fn v2_af_unspec_with_proxy_keeps_the_real_peer() {
    // Hand-built all-zero address section after the fixed 16 bytes:
    // command PROXY, family UNSPEC, protocol UNSPEC, length 0.
    let mut header = ppp::v2::PROTOCOL_PREFIX.to_vec();
    header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
    let h = read_written(&header)
        .await
        .expect("AF_UNSPEC header parses");
    assert_eq!(h.client, real_peer());
}

#[tokio::test]
async fn v2_datagram_protocol_with_proxy_command_is_malformed() {
    let vc = Version::Two as u8 | Command::Proxy as u8;
    let header = ppp::v2::Builder::with_addresses(
        vc,
        Protocol::Datagram,
        IPv4::new([203, 0, 113, 9], [10, 0, 0, 1], 55555, 8080),
    )
    .build()
    .unwrap();
    match read_written(&header).await {
        Err(ProxyProtoError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[tokio::test]
async fn v2_unix_family_with_proxy_command_is_malformed() {
    let vc = Version::Two as u8 | Command::Proxy as u8;
    let header = ppp::v2::Builder::with_addresses(
        vc,
        Protocol::Stream,
        Addresses::Unix(Unix {
            source: [0; 108],
            destination: [0; 108],
        }),
    )
    .build()
    .unwrap();
    match read_written(&header).await {
        Err(ProxyProtoError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[tokio::test]
async fn garbage_first_bytes_are_malformed_and_answered_with_a_400_envelope() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    client.write_all_and_flush(b"HELO nonsense\r\n\r\n").await;
    match read_client_addr(&mut server, real_peer(), Duration::from_secs(5)).await {
        Err(ProxyProtoError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
    // The fail-closed answer: an HTTP/1.1 400 carrying the JSON envelope
    // with the stable code and a request id. The reject write goes to
    // the server side, so the CLIENT side is where it is observable.
    reject_malformed(&mut server).await.expect("reject writes");
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("read completes")
        .expect("read ok");
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
    assert!(text.contains("content-type: application/json"), "{text}");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    let parsed: serde_json::Value = serde_json::from_str(body.trim()).expect("envelope is JSON");
    assert_eq!(parsed["error"]["code"], "proxy_protocol_malformed");
    assert!(parsed["error"]["request_id"]
        .as_str()
        .is_some_and(|r| r.starts_with("req-")));
}

#[tokio::test]
async fn truncated_v2_length_claim_is_malformed_not_hung() {
    // A v2 fixed header whose length field claims 200 bytes of address
    // payload that never arrive must be bounded: the signature shapes
    // are consistent, so the deadline governs. With a generous deadline
    // and a CLOSED peer the read ends as an IO error, not a hang.
    let (mut client, mut server) = tokio::io::duplex(4096);
    let mut header = ppp::v2::PROTOCOL_PREFIX.to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0x00, 200]); // claims 200, sends none
    client.write_all_and_flush(&header).await;
    drop(client); // peer closes: the incomplete read must terminate
    match tokio::time::timeout(
        Duration::from_secs(2),
        read_client_addr(&mut server, real_peer(), Duration::from_secs(1)),
    )
    .await
    .expect("read terminates")
    {
        Err(ProxyProtoError::Io(_)) => {}
        other => panic!("expected Io after EOF mid-header, got {other:?}"),
    }
}

#[tokio::test]
async fn stalled_header_hits_the_whole_header_deadline() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    client.write_all_and_flush(b"PROXY TCP4 203.0.113.7").await;
    let started = std::time::Instant::now();
    match read_client_addr(&mut server, real_peer(), Duration::from_millis(80)).await {
        Err(ProxyProtoError::Incomplete) => {}
        other => panic!("expected Incomplete, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(70));
}

#[tokio::test]
async fn v1_line_over_the_protocol_ceiling_is_malformed() {
    // 107 bytes is v1's hard ceiling; a line that cannot terminate
    // within it is refused outright (not buffered forever, not parsed).
    let mut line = b"PROXY TCP4 ".to_vec();
    while line.len() < 130 {
        line.push(b'x');
    }
    match read_written(&line).await {
        Err(ProxyProtoError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[tokio::test]
async fn eof_before_any_bytes_is_an_io_close() {
    let (_client, mut server) = tokio::io::duplex(4096);
    drop(_client);
    match read_client_addr(&mut server, real_peer(), Duration::from_secs(1)).await {
        Err(ProxyProtoError::Io(_)) => {}
        other => panic!("expected Io, got {other:?}"),
    }
}
