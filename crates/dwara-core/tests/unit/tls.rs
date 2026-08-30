//! Unit tests for `security::tls` (relocated from src).

use std::path::PathBuf;

use dwara_core::config::{
    Endpoint, Gateway, Listener, ListenerProtocol, ListenerTls, LoadBalancer, SniRoute,
    TlsCertificate, TlsMode, Upstream, UpstreamProtocol,
};
use dwara_core::security::tls::*;

// --- SNI parser -------------------------------------------------------

/// Build a minimal ClientHello carrying the given SNI (test helper:
/// constructs exactly the fields the parser walks).
fn client_hello(sni: Option<&str>) -> Vec<u8> {
    wrap_record(&client_hello_message(sni))
}

/// The handshake message (4-byte header + body) of a ClientHello,
/// unframed: the fragmentation tests re-cut this into records.
fn client_hello_message(sni: Option<&str>) -> Vec<u8> {
    let mut ext = Vec::new();
    if let Some(name) = sni {
        let mut entry = vec![0x00u8];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        ext.extend_from_slice(&0u16.to_be_bytes()); // ext type: server_name
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
    }
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // empty session id
    body.extend_from_slice(&2u16.to_be_bytes()); // one cipher suite
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1); // one compression method
    body.push(0);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01u8]; // ClientHello
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);
    hs
}

/// Frame `payload` as one TLS handshake record.
fn wrap_record(payload: &[u8]) -> Vec<u8> {
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    rec
}

#[test]
fn sni_parser_extracts_host_name() {
    assert_eq!(
        sni_from_client_hello(&client_hello(Some("api.example.com"))),
        Some("api.example.com".to_string())
    );
}

#[test]
fn sni_parser_handles_absent_sni_and_garbage() {
    assert_eq!(sni_from_client_hello(&client_hello(None)), None);
    assert_eq!(sni_from_client_hello(b"GET / HTTP/1.1\r\n"), None);
    assert_eq!(sni_from_client_hello(&[]), None);
    assert_eq!(sni_from_client_hello(&[0x16, 0x03, 0x01]), None);
}

#[test]
fn sni_parser_reassembles_client_hello_fragmented_across_records() {
    // #120: a ClientHello split across TLS records (record payloads cap
    // at 16384 bytes, so larger hellos MUST fragment) must reassemble
    // before parsing. Split inside the fixed prefix, mid-body, and just
    // before the end: every cut point yields the same SNI.
    let hs = client_hello_message(Some("frag.example.com"));
    for split in [20usize, hs.len() / 2, hs.len() - 10] {
        let mut buf = wrap_record(&hs[..split]);
        buf.extend_from_slice(&wrap_record(&hs[split..]));
        assert_eq!(
            sni_from_client_hello(&buf),
            Some("frag.example.com".to_string()),
            "split at {split} must reassemble and parse"
        );
    }
}

#[test]
fn sni_parser_reassembles_three_record_fragment() {
    let hs = client_hello_message(Some("three.example.com"));
    let a = hs.len() / 3;
    let mut buf = wrap_record(&hs[..a]);
    buf.extend_from_slice(&wrap_record(&hs[a..2 * a]));
    buf.extend_from_slice(&wrap_record(&hs[2 * a..]));
    assert_eq!(
        sni_from_client_hello(&buf),
        Some("three.example.com".to_string())
    );
}

#[test]
fn sni_parser_missing_tail_of_fragmented_hello_returns_none() {
    // The last byte of the final fragment has not arrived: the message
    // is incomplete, so no SNI yet (the peek loop keeps waiting).
    let hs = client_hello_message(Some("frag.example.com"));
    let split = hs.len() / 2;
    let mut second = wrap_record(&hs[split..]);
    second.truncate(second.len() - 1);
    let mut buf = wrap_record(&hs[..split]);
    buf.extend_from_slice(&second);
    assert_eq!(sni_from_client_hello(&buf), None);
}

#[test]
fn sni_parser_non_handshake_record_cannot_complete_fragment() {
    // An application-data record where handshake bytes are still needed:
    // structurally not a fragmented hello we can wait on.
    let hs = client_hello_message(Some("frag.example.com"));
    let split = hs.len() / 2;
    let mut buf = wrap_record(&hs[..split]);
    buf.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]);
    assert_eq!(sni_from_client_hello(&buf), None);
}

#[test]
fn sni_parser_ignores_records_after_a_complete_hello() {
    // A complete single-record hello followed by a coalesced trailing
    // record (e.g. the next message): the parse uses the first only.
    let mut buf = client_hello(Some("tail.example.com"));
    buf.extend_from_slice(&wrap_record(&[0xde, 0xad]));
    assert_eq!(
        sni_from_client_hello(&buf),
        Some("tail.example.com".to_string())
    );
}

#[test]
fn sni_parser_refuses_hello_over_reassembly_budget() {
    // The passthrough reassembly budget is 64 KiB of handshake message
    // (4-byte header + body). 65533 body bytes is the smallest size over
    // it (4 + 65533 > 65536); 65532 is the largest under it. All bytes
    // present in both cases, framed across two records (one record cannot
    // carry >65535 bytes of payload).
    for (body_len, expect_sni) in [(65533usize, false), (65532, true)] {
        let name = "big.example.com";
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        // server_name extension, then a padding extension sized so the
        // body is exactly body_len bytes.
        let mut entry = vec![0x00u8];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        let sni_ext_len = ext.len();
        let pad_payload = body_len - 41 - 2 - sni_ext_len - 4;
        ext.extend_from_slice(&0x00ffu16.to_be_bytes());
        ext.extend_from_slice(&(pad_payload as u16).to_be_bytes());
        ext.extend_from_slice(&vec![0x42u8; pad_payload]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        assert_eq!(body.len(), body_len, "body sizing arithmetic");

        let mut hs = vec![0x01u8];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);
        let mut buf = wrap_record(&hs[..60000]);
        buf.extend_from_slice(&wrap_record(&hs[60000..]));
        let got = sni_from_client_hello(&buf);
        if expect_sni {
            assert_eq!(got, Some(name.to_string()), "body_len={body_len}");
        } else {
            assert_eq!(got, None, "body_len={body_len} must be refused");
        }
    }
}

#[test]
fn sni_parser_corrupt_second_fragment_yields_no_sni() {
    // The second record is handshake-typed and completes the declared
    // message length, but its payload is garbage: the reassembled body
    // is structurally invalid, so the parse is None (no panic, no SNI).
    // Distinct from the non-handshake-record case: this exercises the
    // reassembly copy path with a corrupt tail.
    let hs = client_hello_message(Some("frag.example.com"));
    let split = hs.len() / 2;
    let mut buf = wrap_record(&hs[..split]);
    let garbage = vec![0xaau8; hs.len() - split];
    buf.extend_from_slice(&wrap_record(&garbage));
    assert_eq!(sni_from_client_hello(&buf), None);
}

#[test]
fn sni_parser_fragment_inside_handshake_header_is_not_reassembled() {
    // Boundary decision: a hello fragmented INSIDE its 4-byte handshake
    // header (first record payload shorter than 4 bytes) is not
    // reassembled — the first record must carry the whole header so the
    // message length is readable. Even though the remaining bytes would
    // complete a parseable message, the answer is None.
    let hs = client_hello_message(Some("hdrfrag.example.com"));
    let mut buf = wrap_record(&hs[..2]);
    buf.extend_from_slice(&wrap_record(&hs[2..]));
    assert_eq!(sni_from_client_hello(&buf), None);
    // Same for a 3-byte first fragment (header minus its last byte).
    let mut buf = wrap_record(&hs[..3]);
    buf.extend_from_slice(&wrap_record(&hs[3..]));
    assert_eq!(sni_from_client_hello(&buf), None);
}

#[test]
fn sni_parser_ignores_other_extensions_before_sni() {
    // Build a hello with a padded unknown extension first.
    let mut ext = Vec::new();
    ext.extend_from_slice(&0x00ffu16.to_be_bytes());
    ext.extend_from_slice(&4u16.to_be_bytes());
    ext.extend_from_slice(&[9, 9, 9, 9]);
    let name = "x.test";
    let mut entry = vec![0x00];
    entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
    entry.extend_from_slice(name.as_bytes());
    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entry);
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&list);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let l = body.len();
    let mut hs = vec![0x01, (l >> 16) as u8, (l >> 8) as u8, l as u8];
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    assert_eq!(sni_from_client_hello(&rec), Some("x.test".to_string()));
}

/// Prefix of a valid ClientHello of `keep` bytes with the record and
/// handshake length fields rewritten to describe the truncated
/// message, so the parser walks INTO the truncated body (and its
/// short length fields) instead of bailing at the record boundary.
/// DW-025 regression helper: every u16be call site must tolerate a
/// 0- or 1-byte remainder without panicking.
fn truncated_client_hello(keep: usize) -> Vec<u8> {
    let mut buf = client_hello(Some("api.example.com"));
    assert!(keep >= 9 && keep <= buf.len(), "keep={keep} out of range");
    buf.truncate(keep);
    buf[3..5].copy_from_slice(&((keep - 5) as u16).to_be_bytes());
    let hs_len = keep - 9;
    buf[6] = (hs_len >> 16) as u8;
    buf[7] = (hs_len >> 8) as u8;
    buf[8] = hs_len as u8;
    buf
}

#[test]
fn sni_record_length_larger_than_buffer_returns_none() {
    let mut buf = client_hello(Some("api.example.com"));
    buf[3..5].copy_from_slice(&0xffffu16.to_be_bytes());
    assert_eq!(sni_from_client_hello(&buf), None);
    // One byte short of the claimed record (no retag): over-claim by 1.
    let mut short = client_hello(Some("api.example.com"));
    short.truncate(short.len() - 1);
    assert_eq!(sni_from_client_hello(&short), None);
}

#[test]
fn sni_cipher_suites_length_field_truncated_returns_none() {
    // Record/handshake headers are 9 bytes; the cipher-suite length
    // u16be reads body[35..37] i.e. buf[44..46]. One byte remains at
    // keep=45 (the exact pre-fix panic: `b[1]` on a 1-byte slice),
    // zero bytes at keep=44, and the field present but its suites
    // truncated at keep=46.
    for keep in [44, 45, 46] {
        assert_eq!(
            sni_from_client_hello(&truncated_client_hello(keep)),
            None,
            "keep={keep} must be no-SNI, not a panic"
        );
    }
    // Just-short-by-one boundary in the other direction: with the
    // full cipher-suite bytes present the walk proceeds past them.
    assert_eq!(sni_from_client_hello(&truncated_client_hello(48)), None);
    assert_eq!(
        sni_from_client_hello(&client_hello(Some("api.example.com"))),
        Some("api.example.com".to_string())
    );
}

#[test]
fn sni_extensions_total_length_field_truncated_returns_none() {
    // ext_total u16be reads body[41..43] i.e. buf[50..52].
    for keep in [50, 51] {
        assert_eq!(
            sni_from_client_hello(&truncated_client_hello(keep)),
            None,
            "keep={keep} must be no-SNI, not a panic"
        );
    }
    // Boundary: field exactly present, no extension bytes after it.
    assert_eq!(sni_from_client_hello(&truncated_client_hello(52)), None);
}

#[test]
fn sni_extension_length_overrun_returns_none() {
    // Extension header (type+len) present but the claimed extension
    // payload is cut short: ext_len says 9+n bytes, body ends inside.
    for keep in [56, 58, 60] {
        assert_eq!(
            sni_from_client_hello(&truncated_client_hello(keep)),
            None,
            "keep={keep} must be no-SNI, not a panic"
        );
    }
}

#[test]
fn sni_list_and_name_length_overruns_return_none() {
    let full = client_hello(Some("api.example.com"));
    let n = "api.example.com".len();
    // SNI list length claims far more than the extension carries.
    let mut over_list = full.clone();
    over_list[full.len() - n - 5..full.len() - n - 3].copy_from_slice(&0xffffu16.to_be_bytes());
    assert_eq!(sni_from_client_hello(&over_list), None);
    // Host-name length claims far more than the list carries.
    let mut over_name = full.clone();
    over_name[full.len() - n - 2..full.len() - n].copy_from_slice(&0xffffu16.to_be_bytes());
    assert_eq!(sni_from_client_hello(&over_name), None);
    // Boundary (control): the same fields at their exact values parse.
    assert_eq!(
        sni_from_client_hello(&full),
        Some("api.example.com".to_string())
    );
    // Name cut one byte short (all framing intact above it).
    assert_eq!(
        sni_from_client_hello(&truncated_client_hello(full.len() - 1)),
        None
    );
}

// --- passthrough routing ----------------------------------------------

fn passthrough_gateway() -> (Gateway, ListenerTls) {
    let tls = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Passthrough,
        cert_file: None,
        key_file: None,
        certificates: vec![],
        sni_routes: vec![SniRoute {
            server_names: vec!["a.example.com".into()],
            upstream: "backend-a".into(),
        }],
    };
    let gateway = Gateway {
        trusted_proxies: vec![],
        listeners: vec![Listener {
            name: "edge".into(),
            address: "0.0.0.0".into(),
            port: 443,
            protocol: ListenerProtocol::Https,
            tls: Some(tls.clone()),
            policies: vec![],
            authorization: None,
            proxy_protocol: false,
        }],
        routes: vec![],
        services: vec![],
        upstreams: vec![Upstream {
            name: "backend-a".into(),
            load_balancer: LoadBalancer::RoundRobin,
            protocol: UpstreamProtocol::Http1,
            endpoints: vec![Endpoint {
                address: "10.0.0.5".into(),
                port: 8443,
                weight: 1,
            }],
            connection_cap: None,
            slow_start_ms: None,
            health: None,
            active_health: None,
            retries: None,
            timeouts: None,
            breaker: None,
            max_pending: None,
            trusted_ca_file: None,
            oauth2_client_credentials: None,
            dns_discovery: None,
        }],
        consumers: vec![],
        policies: vec![],
        global_policies: Vec::new(),
        authorization: None,
        max_concurrent_requests: None,
        load_shed_dry_run: false,
        jwt_providers: Vec::new(),
        admin: None,
        // Genuinely zero-route: SNI passthrough resolves on the LISTENER's
        // sni_routes, ahead of the route table (#129 opt-in).
        allow_empty_routes: true,
        hmac_auth: None,
        webhooks: Vec::new(),
        analytics: None,
        analytics_stream: None,
        geoip: None,
        admission_queue: None,
        mtls_consumer_mapping: None,
        mtls_forward_headers: None,
        license: None,
        oidc_providers: Vec::new(),
        redis_rate_limiter: None,
    };
    (gateway, tls)
}

#[test]
fn passthrough_routes_sni_to_first_endpoint() {
    let (gw, tls) = passthrough_gateway();
    assert_eq!(
        resolve_passthrough(Some("a.example.com"), &tls.sni_routes, &gw, None),
        PassthroughAction::Forward {
            host: "10.0.0.5".into(),
            port: 8443
        }
    );
    // Case-insensitive server-name match.
    assert_eq!(
        resolve_passthrough(Some("A.EXAMPLE.COM"), &tls.sni_routes, &gw, None),
        PassthroughAction::Forward {
            host: "10.0.0.5".into(),
            port: 8443
        }
    );
}

#[test]
fn passthrough_closes_unmatched_sni_or_missing() {
    let (gw, tls) = passthrough_gateway();
    assert_eq!(
        resolve_passthrough(None, &tls.sni_routes, &gw, None),
        PassthroughAction::Close
    );
    assert_eq!(
        resolve_passthrough(Some("other.example.com"), &tls.sni_routes, &gw, None),
        PassthroughAction::Close
    );
}

// --- certificate resolver (real rustls objects, rcgen certs) ----------

fn write_test_cert(dir: &std::path::Path, cn: &str) -> (PathBuf, PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec![cn.to_string()]).expect("rcgen cert");
    let cpath = dir.join(format!("{cn}.crt.pem"));
    let kpath = dir.join(format!("{cn}.key.pem"));
    std::fs::write(&cpath, cert.cert.pem()).unwrap();
    std::fs::write(&kpath, cert.key_pair.serialize_pem()).unwrap();
    (cpath, kpath)
}

/// #128: a `tempfile::TempDir` per test. The previous helper named dirs
/// `dwara-tls-{pid}-{nanos}` from the system clock, and the nanosecond
/// stamps collide across parallel test threads (measured 31.5k/32k
/// duplicates in a 16-thread sampler on one host) — one test's
/// remove_dir_all then deleted a sibling's certificates. TempDir is
/// collision-free by construction and cleans up on drop, so the manual
/// remove_dir_all calls disappear with the helper change.
fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("unique temp dir")
}

#[test]
fn resolver_selects_by_sni_and_falls_back() {
    let dir = temp_dir();
    let (fc, fk) = write_test_cert(dir.path(), "fallback.example.com");
    let (ac, ak) = write_test_cert(dir.path(), "a.example.com");
    let tls = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Terminate,
        cert_file: Some(fc.display().to_string()),
        key_file: Some(fk.display().to_string()),
        certificates: vec![TlsCertificate {
            server_names: vec!["a.example.com".into()],
            cert_file: ac.display().to_string(),
            key_file: ak.display().to_string(),
        }],
        sni_routes: vec![],
    };
    let term = TlsTermination::build(&tls).expect("builds");
    assert_eq!(term.watched_paths.len(), 4);

    // Hot reload keeps working and does not disturb the live config.
    term.reload(&tls).expect("reload");
}

#[test]
fn build_rejects_mismatched_cert_key_pair() {
    let dir = temp_dir();
    let (ac, ak) = write_test_cert(dir.path(), "a.example.com");
    let (_bc, bk) = write_test_cert(dir.path(), "b.example.com");
    // Wrong key for the leaf certificate: rejected at build time.
    let tls = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Terminate,
        cert_file: Some(ac.display().to_string()),
        key_file: Some(bk.display().to_string()),
        certificates: vec![],
        sni_routes: vec![],
    };
    assert!(matches!(
        TlsTermination::build(&tls),
        Err(TlsError::KeyMismatch { .. })
    ));
    // Same mismatch inside a per-certificate entry is rejected too.
    let tls = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Terminate,
        certificates: vec![TlsCertificate {
            server_names: vec!["a.example.com".into()],
            cert_file: ac.display().to_string(),
            key_file: bk.display().to_string(),
        }],
        ..tls
    };
    assert!(matches!(
        TlsTermination::build(&tls),
        Err(TlsError::KeyMismatch { .. })
    ));

    // Matching pair: builds, and a reload with a torn pair is
    // rejected while the live config keeps serving.
    let good = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Terminate,
        cert_file: Some(ac.display().to_string()),
        key_file: Some(ak.display().to_string()),
        certificates: vec![],
        sni_routes: vec![],
    };
    let term = TlsTermination::build(&good).expect("matching pair builds");
    let torn = ListenerTls {
        client_ca_file: None,
        cert_file: Some(ac.display().to_string()),
        key_file: Some(bk.display().to_string()),
        ..good.clone()
    };
    assert!(matches!(
        term.reload(&torn),
        Err(TlsError::KeyMismatch { .. })
    ));
    // Reload of the good config still succeeds afterwards.
    term.reload(&good).expect("reload with matching pair");
}

#[test]
fn build_fails_on_missing_files() {
    let tls = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Terminate,
        cert_file: Some("/nonexistent/cert.pem".into()),
        key_file: Some("/nonexistent/key.pem".into()),
        certificates: vec![],
        sni_routes: vec![],
    };
    assert!(matches!(TlsTermination::build(&tls), Err(TlsError::Io(_))));
    assert!(matches!(
        TlsTermination::build(&ListenerTls {
            client_ca_file: None,
            mode: TlsMode::Terminate,
            cert_file: None,
            key_file: None,
            certificates: vec![],
            sni_routes: vec![],
        }),
        Err(TlsError::NoCertificates)
    ));
}

// --- key-material loading (#120 zeroize rewrite, exercised through the
// public TlsTermination::build path; load_signing_key is private) ------

#[test]
fn build_fails_when_key_file_carries_no_private_key_material() {
    let dir = temp_dir();
    let dir = dir.path();
    let (cc, ck) = write_test_cert(dir, "nokey.example.com");

    // A key file that is a valid PEM of the WRONG kind (certificates
    // only): the private-key iterator finds nothing usable.
    let cert_only = dir.join("cert-only.key.pem");
    std::fs::write(&cert_only, std::fs::read_to_string(&cc).unwrap()).unwrap();
    let tls = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Terminate,
        cert_file: Some(cc.display().to_string()),
        key_file: Some(cert_only.display().to_string()),
        certificates: vec![],
        sni_routes: vec![],
    };
    match TlsTermination::build(&tls) {
        Err(TlsError::EmptyPem { what, .. }) => assert_eq!(what, "private keys"),
        Ok(_) => panic!("expected EmptyPem(private keys), but the build succeeded"),
        Err(other) => panic!("expected EmptyPem(private keys), got {other}"),
    }

    // An empty key file is the same failure.
    let empty = dir.join("empty.key.pem");
    std::fs::write(&empty, b"").unwrap();
    let tls = ListenerTls {
        client_ca_file: None,
        key_file: Some(empty.display().to_string()),
        ..tls
    };
    assert!(matches!(
        TlsTermination::build(&tls),
        Err(TlsError::EmptyPem {
            what: "private keys",
            ..
        })
    ));

    // Semantics preserved from the pre-#120 pem_file_iter path: a key
    // file whose CERTIFICATE blocks precede the private key still loads
    // (non-private-key PEM sections are skipped, not fatal).
    let mixed = dir.join("mixed.key.pem");
    let mut body = std::fs::read_to_string(&cc).unwrap();
    body.push_str(&std::fs::read_to_string(&ck).unwrap());
    std::fs::write(&mixed, body).unwrap();
    let tls = ListenerTls {
        client_ca_file: None,
        key_file: Some(mixed.display().to_string()),
        ..tls
    };
    assert!(TlsTermination::build(&tls).is_ok());
}

#[test]
fn build_fails_on_corrupt_private_key_pem_without_leaking_material() {
    let dir = temp_dir();
    let dir = dir.path();
    let (cc, _ck) = write_test_cert(dir, "corrupt.example.com");
    // A recognized PRIVATE KEY section whose body is not base64: the
    // PEM decode fails. The marker string is what a leaking error path
    // would carry back out; it must appear in no reachable output.
    let marker = "s3cr3t!m@rker";
    let corrupt = dir.join("corrupt.key.pem");
    std::fs::write(
        &corrupt,
        format!("-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----\n"),
    )
    .unwrap();
    let tls = ListenerTls {
        client_ca_file: None,
        mode: TlsMode::Terminate,
        cert_file: Some(cc.display().to_string()),
        key_file: Some(corrupt.display().to_string()),
        certificates: vec![],
        sni_routes: vec![],
    };
    // TlsTermination is not Debug, so expect_err is unavailable here;
    // the match keeps the error and rejects the success branch.
    let err = match TlsTermination::build(&tls) {
        Err(e) => e,
        Ok(_) => panic!("corrupt key must fail, but the build succeeded"),
    };
    let text = format!("{err}");
    let debug = format!("{err:?}");
    assert!(
        !text.contains(marker) && !debug.contains(marker),
        "error output must not echo key-file material: display={text:?} debug={debug:?}"
    );
    // Sanity: the error is a decoding failure, not a silent success or
    // a panic out of the zeroized load path.
    assert!(matches!(err, TlsError::Io(_) | TlsError::Rustls(_)));
}

// --- trusted-CA bundle loading (#121: root_store_from_pem_file) ---------

/// One self-signed CA (the same shape as the integration fixture): a
/// bundle of these is what a trusted_ca_file carries.
fn bundle_ca(cn: &str) -> String {
    let key = rcgen::KeyPair::generate().expect("ca key");
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.self_signed(&key).expect("ca cert").pem()
}

#[test]
fn root_store_loads_every_certificate_in_a_multi_cert_bundle() {
    let dir = temp_dir();
    let dir = dir.path();
    // Real bundles list several anchors with comment filler between the
    // blocks; every certificate must become a trust anchor, in any order.
    let bundle = dir.join("two-anchors.pem");
    std::fs::write(
        &bundle,
        format!(
            "{}# several anchors follow\n{}",
            bundle_ca("unit-ca-a"),
            bundle_ca("unit-ca-b")
        ),
    )
    .unwrap();
    let store = root_store_from_pem_file(bundle.to_str().unwrap()).expect("bundle loads");
    assert_eq!(store.len(), 2, "both anchors are in the store");

    // A single-anchor file is the degenerate bundle.
    let single = dir.join("one-anchor.pem");
    std::fs::write(&single, bundle_ca("unit-ca-single")).unwrap();
    let store = root_store_from_pem_file(single.to_str().unwrap()).expect("single loads");
    assert_eq!(store.len(), 1);
}

#[test]
fn root_store_rejects_unusable_bundle_files() {
    let owned = temp_dir();
    let dir = owned.path();

    // Missing path: io error.
    assert!(matches!(
        root_store_from_pem_file("/nonexistent/dwara-test-ca.pem"),
        Err(TlsError::Io(_))
    ));

    // A directory opens for read but yields no certificates: io error
    // here (snapshot validation also rejects it now — its PEM parse
    // dies on the same EISDIR read — but the io-error MAPPING is owned
    // by this layer).
    let subdir = dir.join("is-a-directory.pem");
    std::fs::create_dir(&subdir).unwrap();
    assert!(matches!(
        root_store_from_pem_file(subdir.to_str().unwrap()),
        Err(TlsError::Io(_))
    ));

    // Empty file: parses to zero anchors — never a valid "trust nothing".
    let empty = dir.join("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    assert!(matches!(
        root_store_from_pem_file(empty.to_str().unwrap()),
        Err(TlsError::EmptyPem {
            what: "CA certificates",
            ..
        })
    ));

    // Non-PEM garbage: no certificate sections at all, so the iterator
    // yields zero certificates — the same EmptyPem failure (non-PEM
    // text is skipped, not fatal, matching the key-file semantics).
    let garbage = dir.join("garbage.pem");
    std::fs::write(&garbage, "definitely not a pem file\n").unwrap();
    assert!(matches!(
        root_store_from_pem_file(garbage.to_str().unwrap()),
        Err(TlsError::EmptyPem {
            what: "CA certificates",
            ..
        })
    ));

    // A CERTIFICATE section whose base64 body is not a certificate at
    // all: the PEM layer hands back the decoded bytes (validation's
    // parse check accepts them — it parses PEM, not anchors), and the
    // root store is what rejects them — the unusable-anchor dimension
    // mapped to RootUnusable. This is the fail-closed backstop's error
    // surface for a bundle that breaks between validate and build.
    let bogus = dir.join("bogus-anchor.pem");
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    std::fs::write(
        &bogus,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(b"definitely not a der certificate")
        ),
    )
    .unwrap();
    assert!(matches!(
        root_store_from_pem_file(bogus.to_str().unwrap()),
        Err(TlsError::RootUnusable(_))
    ));
}

#[test]
fn webpki_root_store_matches_the_public_root_set() {
    // The DEFAULT outbound trust (entities without trusted_ca_file) is
    // the Mozilla set, built once here for connectors, probes, and the
    // JWKS fetcher.
    assert!(!webpki_root_store().is_empty());
}
