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
use zeroize::Zeroizing;

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
    // #120 key-material hygiene: the PEM file body is plaintext secret
    // material. Reading it into a Zeroizing buffer wipes the raw bytes on
    // drop (the old pem_file_iter path left the decoded text in heap
    // memory after the iterator finished).
    let pem = Zeroizing::new(std::fs::read(&ppath)?);
    // PrivateKeyDer implements Zeroize (rustls-pki-types), so the parsed
    // DER secret is wiped when this wrapper drops — including the
    // error paths below. The clone_key() copy handed to the provider is
    // the one residue: aws-lc copies what it needs into its own
    // structures, but that DER buffer itself is freed unwiped
    // (PrivateKeyDer implements Zeroize with no Drop). The provider's
    // own key material is wiped by aws-lc on free.
    let key = Zeroizing::new(
        PrivateKeyDer::pem_slice_iter(&pem)
            .next()
            .ok_or(TlsError::EmptyPem {
                path: ppath,
                what: "private keys",
            })?
            .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?,
    );
    // Loading a signing key requires an installed provider; the binary
    // installs aws-lc-rs at startup, tests call the installer too.
    rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key.clone_key())
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

/// DW-025 fuzz fix: every u16be call site must tolerate slices shorter
/// than two bytes (`slice::get(i..)` succeeds for i <= len even when
/// fewer than 2 bytes remain), so the helper returns Option and
/// truncation anywhere is "no SNI" instead of an index panic.
fn u16be(b: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

/// Handshake-message length out of a ClientHello handshake header
/// (the type byte is checked by the caller): 3-byte big-endian.
fn hs_len_of(header: &[u8]) -> usize {
    ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize
}

/// Reassemble the first handshake message body (the ClientHello body)
/// out of a connection prefix that may carry the message FRAGMENTED
/// across several TLS records (#120: TLS records cap their payload at
/// 16384 bytes, so larger ClientHellos arrive as multiple records and
/// must be reassembled before parsing).
///
/// Single-record hellos borrow from `buf`; fragmented hellos copy the
/// record-payload tails into one buffer. Returns `None` while the
/// message is incomplete, over the reassembly budget, or structurally
/// unusable.
fn client_hello_body(buf: &[u8]) -> Option<std::borrow::Cow<'_, [u8]>> {
    // Record header: type(1) version(2) length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16be(buf.get(3..)?)? as usize;
    let first = buf.get(5..5 + rec_len)?;
    // Handshake header: type(1) length(3); expect ClientHello (0x01).
    if first.len() < 4 || first[0] != 0x01 {
        return None;
    }
    let hs_len = hs_len_of(first);
    // Refuse hellos whose handshake message alone exceeds the
    // reassembly budget: a bounded close, never an unbounded buffer.
    if 4 + hs_len > MAX_HELLO_BYTES {
        return None;
    }
    if first.len() >= 4 + hs_len {
        return Some(std::borrow::Cow::Borrowed(&first[4..4 + hs_len]));
    }
    // Fragmented: the first record holds a prefix of the message;
    // append the tails carried by subsequent complete handshake records
    // until the message is whole.
    let mut body = Vec::with_capacity(hs_len);
    body.extend_from_slice(&first[4..]);
    let mut pos = 5 + rec_len;
    while body.len() < hs_len {
        let hdr = buf.get(pos..pos + 5)?;
        if hdr[0] != 0x16 {
            // Handshake bytes travel in handshake records only; a record
            // of another type cannot complete the message.
            return None;
        }
        let rl = u16be(hdr.get(3..)?)? as usize;
        let payload = buf.get(pos + 5..pos + 5 + rl)?;
        let take = (hs_len - body.len()).min(payload.len());
        body.extend_from_slice(&payload[..take]);
        pos += 5 + rl;
    }
    Some(std::borrow::Cow::Owned(body))
}

/// Parse the SNI server name out of a TLS ClientHello, reassembling
/// handshake fragments across records when the hello does not fit in
/// one (#120).
///
/// Minimal record parser (no new dependency): walks the TLS record and
/// handshake headers, skips session id / cipher suites / compression
/// methods, then scans the extension list for `server_name` (ext 0) and
/// returns the first `host_name` entry. Returns `None` on any structural
/// shortcoming; callers treat that as "no SNI".
pub fn sni_from_client_hello(buf: &[u8]) -> Option<String> {
    let body = client_hello_body(buf)?;
    let body = body.as_ref();
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

/// Endpoint resolver for passthrough routing: maps an upstream NAME to a
/// load-balanced `(address, port)`. The dataplane caller builds it from
/// the CURRENT registry (see dwara-bin's listener), so passthrough picks
/// follow config reloads; `Send + Sync` because the passthrough path runs
/// on spawned tasks. `None` means "no dataplane" — the first configured
/// endpoint is used.
pub type EndpointPicker<'a> = &'a (dyn Fn(&str) -> Option<(String, u16)> + Send + Sync);

/// Resolve a passthrough SNI route against the gateway config.
///
/// Routing rule (v1, documented): the SNI server name is matched exactly
/// against the `sni_routes` entries of the listener. A hit forwards to an
/// endpoint of the referenced upstream. Endpoint selection is delegated to
/// `pick`: the caller supplies a resolver that maps an upstream NAME to a
/// load-balanced `(address, port)` (DW-011; the dataplane caller builds it
/// from the CURRENT registry, so passthrough picks follow config reloads
/// too — see dwara-bin's listener). The pick carries no hash key — a byte
/// splice has no per-request client-IP semantics to weight beyond
/// stickiness, so `ip_hash` degrades to its smooth-RR fallback. Without a
/// resolver (callers without a dataplane) the FIRST configured endpoint is
/// used. No match, no SNI, or a non-TLS client closes the connection.
pub fn resolve_passthrough(
    sni: Option<&str>,
    routes: &[SniRoute],
    gateway: &Gateway,
    pick: Option<EndpointPicker<'_>>,
) -> PassthroughAction {
    let Some(name) = sni else {
        return PassthroughAction::Close;
    };
    for r in routes {
        if r.server_names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            let upstream = gateway.upstreams.iter().find(|u| u.name == r.upstream);
            let endpoint = upstream.and_then(|u| {
                // Prefer the caller's (balancer-backed) pick; fall back to
                // the first configured endpoint. Single-load pick: index
                // and address:port come from the same state snapshot, so a
                // concurrent reload cannot pair an index from one set with
                // an address from another.
                pick.and_then(|pick| pick(&u.name))
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

/// Total reassembly budget for one passthrough ClientHello (#120): a
/// hello fragmented across records is accumulated up to this size, and
/// anything whose handshake message alone is larger is refused (the
/// connection is closed). Real ClientHellos are a few KB; 64 KiB covers
/// four maximal TLS records.
const MAX_HELLO_BYTES: usize = 64 * 1024;
/// Maximum bytes peeked while looking for a complete ClientHello: the
/// reassembly budget plus per-record header overhead and slack for
/// coalesced trailing records. The decision fires as soon as the hello
/// is complete, so a FULL window without one means the hello exceeds
/// the budget and the connection is refused instead of spinning until
/// the peek timeout.
const PEEK_LIMIT: usize = MAX_HELLO_BYTES + 5 + 1024;
/// How long to wait for a complete ClientHello before giving up.
const PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What the peek loop should do after examining the buffered prefix of
/// a passthrough connection.
enum HelloPeek {
    /// A complete ClientHello carrying SNI.
    Sni(String),
    /// Nothing that can still arrive would change the answer (non-TLS
    /// bytes, a structurally complete hello without SNI, a handshake
    /// message that is not a ClientHello, or a hello over the
    /// reassembly budget): decide now.
    Settled,
    /// The ClientHello is fragmented across records (or bytes are still
    /// arriving) and the message is not complete yet: keep waiting,
    /// bounded by [`PEEK_TIMEOUT`] and [`PEEK_LIMIT`].
    Pending,
}

/// Examine a peeked connection prefix: is the ClientHello complete (and
/// what SNI does it carry), definitively undecidable-as-no-SNI, or still
/// missing bytes that may yet arrive? A hello split across records keeps
/// the answer [`HelloPeek::Pending`] until its last fragment lands (#120).
fn examine_peeked(seen: &[u8]) -> HelloPeek {
    // Early reject (documented): a TLS record always starts with the
    // handshake content type 0x16, so anything else is a non-TLS client
    // (e.g. plain HTTP) — decide immediately instead of waiting.
    if seen.first() != Some(&0x16) {
        return HelloPeek::Settled;
    }
    // Walk complete handshake records, counting the bytes of the first
    // handshake message they carry.
    let mut pos = 0usize;
    // Total bytes the message needs (4-byte header + body), once read.
    let mut needed: Option<usize> = None;
    // Message bytes present so far (header + body fragments).
    let mut have = 0usize;
    loop {
        let Some(hdr) = seen.get(pos..pos + 5) else {
            // A further record header is absent or truncated: if the
            // message is still short, more records may complete it.
            return HelloPeek::Pending;
        };
        if hdr[0] != 0x16 {
            // Handshake bytes travel in handshake records only; a record
            // of another type while the message is short cannot complete
            // it, so there is nothing left to wait for.
            return HelloPeek::Settled;
        }
        let Some(rec_len) = u16be(hdr.get(3..).unwrap_or(&[])) else {
            // Unreachable for a 5-byte header slice; kept as a guarded
            // fallback per the DW-025 no-index-panic style.
            return HelloPeek::Pending;
        };
        let rec_len = rec_len as usize;
        let Some(payload) = seen.get(pos + 5..pos + 5 + rec_len) else {
            // Record payload still arriving.
            return HelloPeek::Pending;
        };
        if needed.is_none() {
            if payload.len() < 4 {
                // Boundary decision: a hello fragmented INSIDE its 4-byte
                // handshake header (no real TLS stack does this) is not
                // reassembled — the first record must carry the whole
                // header so the message length is readable.
                return HelloPeek::Settled;
            }
            if payload[0] != 0x01 {
                return HelloPeek::Settled;
            }
            let hs_len = hs_len_of(payload);
            if 4 + hs_len > MAX_HELLO_BYTES {
                return HelloPeek::Settled;
            }
            needed = Some(4 + hs_len);
        }
        // Every payload byte of these records belongs to the message
        // stream (the 4-byte handshake header included): the message
        // occupies a contiguous byte range starting at the first
        // record's payload.
        have += payload.len();
        if have >= needed.unwrap_or(0) {
            // The whole message is buffered: parse it for SNI.
            return match sni_from_client_hello(seen) {
                Some(name) => HelloPeek::Sni(name),
                None => HelloPeek::Settled,
            };
        }
        pos += 5 + rec_len;
    }
}

/// Peek the ClientHello off a passthrough connection, decide the route,
/// and either splice both directions to the upstream or close.
///
/// `pick` is the endpoint resolver handed to [`resolve_passthrough`]
/// (upstream name -> load-balanced `(address, port)`; None falls back to
/// the first configured endpoint). Peeking (never reading) keeps the
/// bytes available for the upstream once splicing starts: the entire
/// hello — including fragments that had to be reassembled for the SNI
/// decision (#120) — is still in the socket buffer and is replayed to
/// the upstream by the splice. A ClientHello fragmented across records
/// is waited for (bounded) rather than closed as no-SNI.
pub async fn handle_passthrough(
    stream: &mut TcpStream,
    tls: &ListenerTls,
    gateway: &Gateway,
    pick: Option<EndpointPicker<'_>>,
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
        match examine_peeked(seen) {
            HelloPeek::Sni(name) => break Some(name),
            HelloPeek::Settled => break None,
            HelloPeek::Pending => {
                // A full window without a decision means the handshake
                // message exceeds the reassembly budget: refuse now
                // rather than spinning until the peek timeout.
                if n >= PEEK_LIMIT || started.elapsed() >= PEEK_TIMEOUT {
                    break None;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    };

    match resolve_passthrough(sni.as_deref(), &tls.sni_routes, gateway, pick) {
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
