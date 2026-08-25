//! TLS machinery for listeners (DW-007, feature analysis 4.10 / 4.13).
//!
//! Responsibilities:
//!
//! - process-global crypto provider installation (aws-lc-rs; must happen
//!   before the first rustls object is created),
//! - building a hot-reloadable `rustls::ServerConfig` from a
//!   [`ListenerTls`] terminate block, with SNI-based certificate selection
//!   (the single `cert_file`/`key_file` pair is the fallback certificate,
//!   `certificates` entries are matched by SNI),
//! - a minimal TLS ClientHello SNI parser used by passthrough routing,
//!   and the passthrough byte-splice itself.
//!
//! Hot reload model: [`TlsTermination`] keeps the current
//! `Arc<rustls::ServerConfig>` behind an `ArcSwap`. Each accepted
//! connection clones the current `Arc` into a fresh `TlsAcceptor`, so a
//! swap only affects handshakes that start after it: in-flight TLS
//! sessions keep their negotiated configuration and existing connections
//! are never dropped by a reload.
//!
//! Documented v1 limitation: TLS 1.3 and 1.2 are both enabled with
//! rustls's default (modern) cipher-suite policy; no cipher/version
//! overrides are configurable yet.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::{Gateway, ListenerTls, SniRoute};

/// Error loading or building TLS material.
#[derive(Debug)]
pub enum TlsError {
    Io(std::io::Error),
    /// A PEM file parsed to zero usable items.
    EmptyPem {
        path: PathBuf,
        what: &'static str,
    },
    Rustls(rustls::Error),
    /// No certificate material at all in a terminate block.
    NoCertificates,
    /// The private key does not match the leaf certificate (public keys
    /// differ). Detected at build AND reload time so a torn cert/key pair
    /// on disk can never be swapped into the live configuration.
    KeyMismatch {
        cert_file: PathBuf,
        key_file: PathBuf,
    },
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Io(e) => write!(f, "tls file error: {e}"),
            TlsError::EmptyPem { path, what } => {
                write!(f, "no {what} found in PEM file {}", path.display())
            }
            TlsError::Rustls(e) => write!(f, "tls error: {e}"),
            TlsError::NoCertificates => {
                write!(f, "tls terminate block has no certificate material")
            }
            TlsError::KeyMismatch {
                cert_file,
                key_file,
            } => write!(
                f,
                "private key {} does not match leaf certificate {}",
                key_file.display(),
                cert_file.display()
            ),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> Self {
        TlsError::Io(e)
    }
}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> Self {
        TlsError::Rustls(e)
    }
}

/// Install the aws-lc-rs crypto provider as the process-global rustls
/// default. Idempotent: installing twice (e.g. binary + tests in one
/// process) returns Ok the first time and an ignorable error afterwards.
pub fn install_aws_lc_rs_provider() {
    // install_default returns Err(previous provider) when one is already
    // installed; that is the idempotent success case for us.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let path = PathBuf::from(path);
    let certs = CertificateDer::pem_file_iter(&path)
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?;
    if certs.is_empty() {
        return Err(TlsError::EmptyPem {
            path,
            what: "certificates",
        });
    }
    Ok(certs)
}

fn load_signing_key(path: &str) -> Result<Arc<dyn rustls::sign::SigningKey>, TlsError> {
    let ppath = PathBuf::from(path);
    let keys = PrivateKeyDer::pem_file_iter(&ppath)
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?;
    let key = keys.into_iter().next().ok_or(TlsError::EmptyPem {
        path: ppath,
        what: "private keys",
    })?;
    // Loading a signing key requires an installed provider; the binary
    // installs aws-lc-rs at startup, tests call the installer too.
    rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(TlsError::Rustls)
}

/// Read one DER TLV: returns (tag, content, remainder after the element).
/// Used by [`spki_of_leaf`] to walk the certificate structure without a
/// full X.509 parser dependency.
fn der_elem(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *buf.first()?;
    let mut i = 1usize;
    let first = *buf.get(i)?;
    let len = if first < 0x80 {
        i += 1;
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 8 {
            return None;
        }
        i += 1;
        let mut l = 0usize;
        for &b in buf.get(i..i + n)? {
            l = (l << 8) | b as usize;
        }
        i += n;
        l
    };
    let content = buf.get(i..i + len)?;
    Some((tag, content, &buf[i + len..]))
}

/// Extract the DER-encoded SubjectPublicKeyInfo of a leaf certificate by
/// walking Certificate -> TBSCertificate -> (version?) serial, signature,
/// issuer, validity, subject, SPKI. Returns the SPKI DER including its own
/// SEQUENCE header (the same encoding `SigningKey::public_key` yields) or
/// None on any structural shortcoming (treated as a mismatch by the
/// caller, which rejects).
fn spki_of_leaf(cert: &CertificateDer<'_>) -> Option<Vec<u8>> {
    // Certificate SEQUENCE -> TBSCertificate SEQUENCE.
    let (tag, cert_content, _) = der_elem(cert.as_ref())?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = der_elem(cert_content)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // Optional [0] EXPLICIT version comes before the serial INTEGER.
    if let Some((tag, _, tail)) = der_elem(rest) {
        if tag & 0xc0 == 0x80 {
            rest = tail;
        }
    }
    // serialNumber, signature, issuer, validity, subject, then SPKI.
    for _ in 0..5 {
        let (_, _, tail) = der_elem(rest)?;
        rest = tail;
    }
    let (tag, _, after_spki) = der_elem(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(rest[..rest.len() - after_spki.len()].to_vec())
}

/// Load one cert/key pair as a `CertifiedKey`, rejecting pairs whose
/// private key does not match the leaf certificate (public-key/SPKI
/// comparison via aws-lc-rs, available through the rustls signing key).
fn load_certified_key(cert_file: &str, key_file: &str) -> Result<Arc<CertifiedKey>, TlsError> {
    let certs = load_cert_chain(cert_file)?;
    let key = load_signing_key(key_file)?;
    let spki_ok = key
        .public_key()
        .map(|k| k.as_ref().to_vec())
        .zip(spki_of_leaf(&certs[0]))
        .is_some_and(|(key_spki, cert_spki)| key_spki == cert_spki);
    if !spki_ok {
        return Err(TlsError::KeyMismatch {
            cert_file: PathBuf::from(cert_file),
            key_file: PathBuf::from(key_file),
        });
    }
    Ok(Arc::new(CertifiedKey::new(certs, key)))
}

/// SNI-aware certificate resolver: exact server-name match against the
/// `certificates` entries; falls back to the single pair (or the first
/// entry when no pair is configured). Names are compared lowercase per
/// the SNI specification.
pub struct SniCertResolver {
    // Debug is required by ResolvesServerCert; derived on a snapshot of
    // the key names only, via a manual impl below.
    by_name: BTreeMap<String, Arc<CertifiedKey>>,
    fallback: Arc<CertifiedKey>,
}

impl SniCertResolver {
    /// Build from a terminate-mode [`ListenerTls`]. The fallback order is:
    /// the single `cert_file`/`key_file` pair if present, else the first
    /// `certificates` entry.
    pub fn build(tls: &ListenerTls) -> Result<Self, TlsError> {
        let mut by_name = BTreeMap::new();
        let mut fallback: Option<Arc<CertifiedKey>> = None;
        let mut first: Option<Arc<CertifiedKey>> = None;

        if let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) {
            fallback = Some(load_certified_key(cert_file, key_file)?);
        }
        for c in &tls.certificates {
            let key = load_certified_key(&c.cert_file, &c.key_file)?;
            for n in &c.server_names {
                by_name.insert(n.to_ascii_lowercase(), Arc::clone(&key));
            }
            if first.is_none() {
                first = Some(key);
            }
        }
        let fallback = fallback.or(first).ok_or(TlsError::NoCertificates)?;
        Ok(SniCertResolver { by_name, fallback })
    }
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("names", &self.by_name.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|sni| self.by_name.get(&sni.to_ascii_lowercase()))
            .map(Arc::clone)
            .or_else(|| Some(Arc::clone(&self.fallback)))
    }
}

/// A hot-reloadable TLS termination configuration for one listener.
///
/// The current `ServerConfig` lives behind an `ArcSwap`; every accepted
/// connection snapshots the current `Arc` when its handshake starts.
/// [`TlsTermination::reload`] swaps in a rebuilt config; handshakes that
/// began earlier finish with the configuration they negotiated.
pub struct TlsTermination {
    config: ArcSwap<ServerConfig>,
    /// The cert/key paths this config was built from, so a watcher can
    /// observe exactly the files that matter.
    pub watched_paths: Vec<PathBuf>,
}

impl TlsTermination {
    /// Build from a terminate-mode [`ListenerTls`] block.
    pub fn build(tls: &ListenerTls) -> Result<Self, TlsError> {
        let mut watched = Vec::new();
        if let (Some(c), Some(k)) = (&tls.cert_file, &tls.key_file) {
            watched.push(PathBuf::from(c));
            watched.push(PathBuf::from(k));
        }
        for c in &tls.certificates {
            watched.push(PathBuf::from(&c.cert_file));
            watched.push(PathBuf::from(&c.key_file));
        }
        Ok(TlsTermination {
            config: ArcSwap::from_pointee(Self::server_config(tls)?),
            watched_paths: watched,
        })
    }

    fn server_config(tls: &ListenerTls) -> Result<ServerConfig, TlsError> {
        let resolver = SniCertResolver::build(tls)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        // ALPN advertises both; the client's choice decides HTTP/1.1 vs
        // HTTP/2 (hyper-util's auto builder handles whichever arrives).
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }

    /// The current server config; clone the `Arc` per accepted connection.
    pub fn config(&self) -> Arc<ServerConfig> {
        self.config.load_full()
    }

    /// Rebuild from (possibly changed files on disk) and swap in. On any
    /// error — including a cert/key pair whose key does not match the
    /// leaf certificate (torn reload) — the current config is untouched
    /// and the previous certificates keep serving.
    pub fn reload(&self, tls: &ListenerTls) -> Result<(), TlsError> {
        let built = Self::server_config(tls)?;
        self.config.store(Arc::new(built));
        Ok(())
    }
}

/// Parse the SNI server name out of a TLS ClientHello record.
///
/// Minimal record parser (no new dependency): walks the TLS record and
/// handshake headers, skips session id / cipher suites / compression
/// methods, then scans the extension list for `server_name` (ext 0) and
/// returns the first `host_name` entry. Returns `None` on any structural
/// shortcoming; callers treat that as "no SNI".
pub fn sni_from_client_hello(buf: &[u8]) -> Option<String> {
    fn u16be(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }
    // Record header: type(1) version(2) length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16be(&buf[3..]) as usize;
    let rec = buf.get(5..5 + rec_len)?;
    // Handshake header: type(1) length(3); expect ClientHello (0x01).
    if rec.len() < 4 || rec[0] != 0x01 {
        return None;
    }
    let hs_len = ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | rec[3] as usize;
    let body = rec.get(4..4 + hs_len)?;
    let mut i = 0usize;
    i += 2; // client version
    i += 32; // random
             // session id
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    // cipher suites
    let cs_len = u16be(body.get(i..)?) as usize;
    i += 2 + cs_len;
    // compression methods
    let cm_len = *body.get(i)? as usize;
    i += 1 + cm_len;
    // extensions
    let ext_total = u16be(body.get(i..)?) as usize;
    i += 2;
    let ext_end = i + ext_total;
    while i + 4 <= ext_end && i + 4 <= body.len() {
        let ext_type = u16be(&body[i..]);
        let ext_len = u16be(&body[i + 2..]) as usize;
        let ext = body.get(i + 4..i + 4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name list: total length (2), then entries:
            // type (1, must be 0 host_name), length (2), bytes.
            if ext.len() < 2 {
                return None;
            }
            let list_len = u16be(ext) as usize;
            let list = ext.get(2..2 + list_len)?;
            if list.is_empty() {
                return None;
            }
            let name_type = list[0];
            if name_type != 0x00 || list.len() < 4 {
                return None;
            }
            let name_len = u16be(&list[1..]) as usize;
            let name = list.get(3..3 + name_len)?;
            return std::str::from_utf8(name).ok().map(|s| s.to_string());
        }
        i += 4 + ext_len;
    }
    None
}

/// Passthrough routing outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum PassthroughAction {
    /// Splice to this upstream endpoint.
    Forward { host: String, port: u16 },
    /// Close the connection (non-TLS, no SNI, or no matching route).
    Close,
}

/// Resolve a passthrough SNI route against the gateway config.
///
/// Routing rule (v1, documented): the SNI server name is matched exactly
/// against the `sni_routes` entries of the listener; a hit forwards to
/// the FIRST endpoint of the referenced upstream (load balancing across
/// endpoints is DW-011). No match, no SNI, or a non-TLS client closes
/// the connection.
pub fn resolve_passthrough(
    sni: Option<&str>,
    routes: &[SniRoute],
    gateway: &Gateway,
) -> PassthroughAction {
    let Some(name) = sni else {
        return PassthroughAction::Close;
    };
    for r in routes {
        if r.server_names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            if let Some(up) = gateway
                .upstreams
                .iter()
                .find(|u| u.name == r.upstream)
                .and_then(|u| u.endpoints.first())
            {
                return PassthroughAction::Forward {
                    host: up.address.clone(),
                    port: up.port,
                };
            }
            return PassthroughAction::Close;
        }
    }
    PassthroughAction::Close
}

/// Maximum bytes peeked while looking for a complete ClientHello: one
/// maximal TLS record is 16384 bytes of payload plus a 5-byte header.
const PEEK_LIMIT: usize = 5 + 16 * 1024;
/// How long to wait for a complete ClientHello before giving up.
const PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Peek the ClientHello off a passthrough connection, decide the route,
/// and either splice both directions to the upstream or close.
///
/// Peeking (never reading) keeps the bytes available for the upstream
/// once splicing starts.
pub async fn handle_passthrough(
    stream: &mut TcpStream,
    tls: &ListenerTls,
    gateway: &Gateway,
) -> std::io::Result<PassthroughAction> {
    let mut scratch = vec![0u8; PEEK_LIMIT];
    let started = std::time::Instant::now();
    let sni = loop {
        let n = stream.peek(&mut scratch).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before ClientHello",
            ));
        }
        let seen = &scratch[..n];
        // Early reject (documented): a TLS record always starts with the
        // handshake content type 0x16, so anything else is a non-TLS
        // client (e.g. plain HTTP) — close immediately instead of
        // spinning until the peek timeout.
        if seen[0] != 0x16 {
            break None;
        }
        if let Some(sni) = sni_from_client_hello(seen) {
            break Some(sni);
        }
        // Not usable yet: either the record is still arriving (wait for
        // more bytes) or it is complete and carries no SNI / is not TLS.
        let complete = seen.len() >= 5 && {
            let rec_len = u16::from_be_bytes([seen[3], seen[4]]) as usize;
            seen.len() >= 5 + rec_len
        };
        if complete || started.elapsed() >= PEEK_TIMEOUT {
            break None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    };

    match resolve_passthrough(sni.as_deref(), &tls.sni_routes, gateway) {
        PassthroughAction::Forward { host, port } => {
            let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
            let _ = stream.set_nodelay(true);
            let _ = upstream.set_nodelay(true);
            tokio::io::copy_bidirectional(stream, &mut upstream).await?;
            let _ = stream.shutdown().await;
            let _ = upstream.shutdown().await;
            Ok(PassthroughAction::Forward { host, port })
        }
        PassthroughAction::Close => {
            let _ = stream.shutdown().await;
            Ok(PassthroughAction::Close)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Listener, ListenerProtocol, TlsCertificate, TlsMode};

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
            listeners: vec![Listener {
                name: "edge".into(),
                address: "0.0.0.0".into(),
                port: 443,
                protocol: ListenerProtocol::Https,
                tls: Some(tls.clone()),
            }],
            routes: vec![],
            services: vec![],
            upstreams: vec![crate::config::Upstream {
                name: "backend-a".into(),
                load_balancer: crate::config::LoadBalancer::RoundRobin,
                protocol: crate::config::UpstreamProtocol::Http1,
                endpoints: vec![crate::config::Endpoint {
                    address: "10.0.0.5".into(),
                    port: 8443,
                    weight: 1,
                }],
                connection_cap: None,
                timeouts: None,
            }],
            consumers: vec![],
            policies: vec![],
        };
        (gateway, tls)
    }

    #[test]
    fn passthrough_routes_sni_to_first_endpoint() {
        let (gw, tls) = passthrough_gateway();
        assert_eq!(
            resolve_passthrough(Some("a.example.com"), &tls.sni_routes, &gw),
            PassthroughAction::Forward {
                host: "10.0.0.5".into(),
                port: 8443
            }
        );
        // Case-insensitive server-name match.
        assert_eq!(
            resolve_passthrough(Some("A.EXAMPLE.COM"), &tls.sni_routes, &gw),
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
            resolve_passthrough(None, &tls.sni_routes, &gw),
            PassthroughAction::Close
        );
        assert_eq!(
            resolve_passthrough(Some("other.example.com"), &tls.sni_routes, &gw),
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
}
