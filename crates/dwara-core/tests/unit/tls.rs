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

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
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
        }],
        consumers: vec![],
        policies: vec![],
        max_concurrent_requests: None,
        jwt_providers: Vec::new(),
        admin: None,
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

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dwara-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn resolver_selects_by_sni_and_falls_back() {
    let dir = temp_dir();
    let (fc, fk) = write_test_cert(&dir, "fallback.example.com");
    let (ac, ak) = write_test_cert(&dir, "a.example.com");
    let tls = ListenerTls {
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn build_rejects_mismatched_cert_key_pair() {
    let dir = temp_dir();
    let (ac, ak) = write_test_cert(&dir, "a.example.com");
    let (_bc, bk) = write_test_cert(&dir, "b.example.com");
    // Wrong key for the leaf certificate: rejected at build time.
    let tls = ListenerTls {
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
        mode: TlsMode::Terminate,
        cert_file: Some(ac.display().to_string()),
        key_file: Some(ak.display().to_string()),
        certificates: vec![],
        sni_routes: vec![],
    };
    let term = TlsTermination::build(&good).expect("matching pair builds");
    let torn = ListenerTls {
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn build_fails_on_missing_files() {
    let tls = ListenerTls {
        mode: TlsMode::Terminate,
        cert_file: Some("/nonexistent/cert.pem".into()),
        key_file: Some("/nonexistent/key.pem".into()),
        certificates: vec![],
        sni_routes: vec![],
    };
    assert!(matches!(TlsTermination::build(&tls), Err(TlsError::Io(_))));
    assert!(matches!(
        TlsTermination::build(&ListenerTls {
            mode: TlsMode::Terminate,
            cert_file: None,
            key_file: None,
            certificates: vec![],
            sni_routes: vec![],
        }),
        Err(TlsError::NoCertificates)
    ));
}
