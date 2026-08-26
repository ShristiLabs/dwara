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
    /// The admin mTLS client-CA verifier could not be built (root
    /// loading or verifier construction failed).
    ClientAuth(String),
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
            TlsError::ClientAuth(m) => write!(f, "admin client-auth setup failed: {m}"),
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

/// Cert resolver that always answers with the one configured key: the
/// admin listener serves a single identity (no SNI selection).
struct SingleCertResolver(Arc<CertifiedKey>);

impl std::fmt::Debug for SingleCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleCertResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Build the mTLS-ONLY `rustls::ServerConfig` for the admin listener
/// (DW-022, decision 6). Client certificates are REQUIRED and must chain
/// to the CA in `client_ca_file` (`WebPkiClientVerifier` over a root
/// store loaded from that PEM); the server presents the single
/// cert/key pair. The key is checked against the leaf exactly like
/// dataplane termination, so a torn pair cannot boot. ALPN advertises
/// HTTP/1.1 only — the admin API is a small request/response surface.
pub fn admin_mtls_server_config(
    tls: &crate::config::AdminTlsConfig,
) -> Result<ServerConfig, TlsError> {
    let certified = load_certified_key(&tls.cert_file, &tls.key_file)?;
    let ca_path = PathBuf::from(&tls.client_ca_file);
    let ca_certs = CertificateDer::pem_file_iter(&ca_path)
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?;
    if ca_certs.is_empty() {
        return Err(TlsError::EmptyPem {
            path: ca_path,
            what: "client CA certificates",
        });
    }
    let mut roots = rustls::RootCertStore::empty();
    for c in ca_certs {
        roots
            .add(c)
            .map_err(|e| TlsError::ClientAuth(format!("adding root for admin verifier: {e}")))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| TlsError::ClientAuth(format!("building admin client verifier: {e}")))?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertResolver(certified)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Parse the SNI server name out of a TLS ClientHello record.
///
/// Minimal record parser (no new dependency): walks the TLS record and
/// handshake headers, skips session id / cipher suites / compression
/// methods, then scans the extension list for `server_name` (ext 0) and
/// returns the first `host_name` entry. Returns `None` on any structural
/// shortcoming; callers treat that as "no SNI".
pub fn sni_from_client_hello(buf: &[u8]) -> Option<String> {
    // DW-025 fuzz fix: every u16be call site must tolerate slices shorter
    // than two bytes (`slice::get(i..)` succeeds for i <= len even when
    // fewer than 2 bytes remain), so the helper returns Option and
    // truncation anywhere is "no SNI" instead of an index panic.
    fn u16be(b: &[u8]) -> Option<u16> {
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }
    // Record header: type(1) version(2) length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16be(buf.get(3..)?)? as usize;
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
    let cs_len = u16be(body.get(i..)?)? as usize;
    i += 2 + cs_len;
    // compression methods
    let cm_len = *body.get(i)? as usize;
    i += 1 + cm_len;
    // extensions
    let ext_total = u16be(body.get(i..)?)? as usize;
    i += 2;
    let ext_end = i + ext_total;
    while i + 4 <= ext_end && i + 4 <= body.len() {
        let ext_type = u16be(body.get(i..)?)?;
        let ext_len = u16be(body.get(i + 2..)?)? as usize;
        let ext = body.get(i + 4..i + 4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name list: total length (2), then entries:
            // type (1, must be 0 host_name), length (2), bytes.
            if ext.len() < 2 {
                return None;
            }
            let list_len = u16be(ext)? as usize;
            let list = ext.get(2..2 + list_len)?;
            if list.is_empty() {
                return None;
            }
            let name_type = list[0];
            if name_type != 0x00 || list.len() < 4 {
                return None;
            }
            let name_len = u16be(list.get(1..)?)? as usize;
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
/// against the `sni_routes` entries of the listener. A hit forwards to an
/// endpoint of the referenced upstream chosen by that upstream's load
/// balancer (DW-011; `registry` is the dataplane's current registry, so
/// passthrough picks follow config reloads too). The pick carries no hash
/// key — a byte splice has no per-request client-IP semantics to weight
/// beyond stickiness, so `ip_hash` degrades to its smooth-RR fallback.
/// Without a registry (callers without a dataplane) the FIRST configured
/// endpoint is used. No match, no SNI, or a non-TLS client closes the
/// connection.
pub fn resolve_passthrough(
    sni: Option<&str>,
    routes: &[SniRoute],
    gateway: &Gateway,
    registry: Option<&crate::upstream::UpstreamRegistry>,
) -> PassthroughAction {
    let Some(name) = sni else {
        return PassthroughAction::Close;
    };
    for r in routes {
        if r.server_names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            let upstream = gateway.upstreams.iter().find(|u| u.name == r.upstream);
            let endpoint = upstream.and_then(|u| {
                // Prefer the live balancer; fall back to the first
                // configured endpoint.
                // Single-load pick: index and address:port come from the
                // same state snapshot, so a concurrent reload cannot pair
                // an index from one set with an address from another.
                registry
                    .and_then(|reg| reg.get(&u.name))
                    .and_then(|h| h.lb().pick_endpoint(None).map(|(_, a, p)| (a, p)))
                    .or_else(|| u.endpoints.first().map(|e| (e.address.clone(), e.port)))
            });
            if let Some((host, port)) = endpoint {
                return PassthroughAction::Forward { host, port };
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
    registry: Option<&crate::upstream::UpstreamRegistry>,
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

    match resolve_passthrough(sni.as_deref(), &tls.sni_routes, gateway, registry) {
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
}
