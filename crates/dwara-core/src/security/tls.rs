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
//! - outbound TRUST for https dials (#121): the default webpki public
//!   root set, PEM-bundle root stores for the `trusted_ca_file` config
//!   field (private CAs), and the shared HTTP/1.1 client-config shape
//!   used by upstream connectors, active health probes, and the JWKS
//!   fetcher,
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
    /// A certificate from a trusted-CA PEM file was rejected by the
    /// root store (not usable as a trust anchor).
    RootUnusable(String),
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
            TlsError::RootUnusable(m) => {
                write!(f, "certificate not usable as a trust anchor: {m}")
            }
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
///
/// When the `fips` cargo feature is ON (DW-111), the binary calls
/// [`crate::security::fips::install_fips_provider`] instead, which
/// installs the same aws-lc-rs provider (the FIPS-validated code path)
/// and then runs the self-test to confirm. This function remains the
/// default install path for non-FIPS builds.
pub fn install_aws_lc_rs_provider() {
    // install_default returns Err(previous provider) when one is already
    // installed; that is the idempotent success case for us.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// DW-111: build a FIPS-restricted `CryptoProvider` from the aws-lc-rs
/// default provider, filtering the cipher suite list to the FIPS-approved
/// allowlist in [`crate::security::fips::FIPS_ALLOWED_CIPHERS`]. The
/// returned provider is identical to the aws-lc-rs default except its
/// `cipher_suites` vector contains only the FIPS-approved suites. A suite
/// in the allowlist that the provider does not support is silently
/// skipped (the provider's support is the ground truth; the allowlist is
/// the restriction).
#[cfg(feature = "fips")]
fn fips_provider() -> rustls::crypto::CryptoProvider {
    use crate::security::fips::FIPS_ALLOWED_CIPHERS;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let suites: Vec<rustls::SupportedCipherSuite> = provider
        .cipher_suites
        .iter()
        .filter(|suite| {
            let name = format!("{:?}", suite.suite()).to_ascii_lowercase();
            FIPS_ALLOWED_CIPHERS
                .iter()
                .any(|allowed| *allowed == name.as_str())
        })
        .copied()
        .collect();
    rustls::crypto::CryptoProvider {
        cipher_suites: suites,
        ..provider
    }
}

/// The Mozilla (webpki) public root set as a rustls `RootCertStore`: the
/// DEFAULT trust for every outbound https dial — upstream connectors,
/// active health probes, and the JWKS fetcher (#121 made the per-entity
/// override configurable; this remains what an entity without a
/// `trusted_ca_file` verifies against). Lives here, next to the other
/// root-store machinery, so all outbound callers share one definition
/// instead of each rebuilding it inline.
pub fn webpki_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Build a rustls `RootCertStore` from a PEM file of CA certificates
/// (#121). The file may carry SEVERAL certificates — a typical CA bundle
/// lists an anchor plus intermediates — and every certificate in it
/// becomes a trust anchor. Fails with [`TlsError::Io`] when the file
/// cannot be read or parsed, and with [`TlsError::EmptyPem`] when it
/// parses to zero certificates (an empty trust set is always a
/// configuration mistake, never a valid "trust nothing" — that would
/// silently fail every TLS handshake).
pub fn root_store_from_pem_file(path: &str) -> Result<rustls::RootCertStore, TlsError> {
    let ppath = PathBuf::from(path);
    let certs = CertificateDer::pem_file_iter(&ppath)
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Io(std::io::Error::other(e.to_string())))?;
    if certs.is_empty() {
        return Err(TlsError::EmptyPem {
            path: ppath,
            what: "CA certificates",
        });
    }
    let mut roots = rustls::RootCertStore::empty();
    for c in certs {
        roots
            .add(c)
            .map_err(|e| TlsError::RootUnusable(e.to_string()))?;
    }
    Ok(roots)
}

/// HTTP/1.1-ALPN rustls client config over the given trust roots: the
/// shared shape for every outbound https dial that speaks HTTP/1.1 —
/// `https`-protocol upstream connectors, active health probes, and the
/// JWKS fetcher (#121). Keeping one constructor here means a config
/// generation applies IDENTICAL trust and handshake policy across the
/// pooled client, the probes, and the fetcher; `http2` upstreams build
/// their own config (same roots, `h2` ALPN).
pub fn https_h1_client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

/// DW-105: HTTP/1.1-ALPN rustls client config with post-quantum hybrid
/// key exchange opt-in. When `pq` is `true` AND the `pq` cargo feature
/// is ON, [`crate::security::pq::install_pq_kx_group`] is called to
/// prepend the X25519+ML-KEM hybrid kx group to the provider's kx group
/// list before building the config. The rustls PQ API is experimental;
/// the call is a documented no-op when the API is not reachable (the
/// config builds with the classical kx group list — no regression).
/// When `pq` is `false` or the feature is off, this is identical to
/// [`https_h1_client_config`].
pub fn https_h1_client_config_pq(roots: rustls::RootCertStore, pq: bool) -> rustls::ClientConfig {
    if pq {
        let _ = crate::security::pq::install_pq_kx_group();
    }
    https_h1_client_config(roots)
}

/// HTTP/3-ALPN rustls client config over the given trust roots (DW-108):
/// the shared shape for every outbound H3/QUIC dial — the H3 upstream
/// connector and the QUIC active health probe. QUIC mandates TLS 1.3,
/// so this always negotiates `h3` over the same root store the pooled
/// https connector would use (#121: webpki by default, the upstream's
/// `trusted_ca_file` bundle when configured). Keeping the constructor
/// here means one trust/handshake policy across the pooled H3 client and
/// its probes, mirroring [`https_h1_client_config`].
pub fn https_h3_client_config(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    // DW-108: no 0-RTT upstream dialing (replay risk footgun). rustls
    // does not expose early-data knobs on ClientConfig directly; the
    // default is no early data, which is the safe choice.
    cfg
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
    // An 8-byte length field can encode a value near usize::MAX, which
    // would overflow the `i + len` addition: bound the element end
    // BEFORE slicing (checked add + length filter, then the slice is
    // always in range).
    let end = len.checked_add(i).filter(|end| *end <= buf.len())?;
    Some((tag, &buf[i..end], &buf[end..]))
}

/// Walk the TBS of a leaf certificate to the SUBJECT RDNSequence content
/// (the bytes INSIDE the subject SEQUENCE header — unlike
/// [`spki_of_leaf`], which keeps its header because that is the SPKI
/// encoding the key comparison needs). None on any structural
/// shortcoming.
fn subject_of_leaf<'a>(cert: &'a CertificateDer<'a>) -> Option<&'a [u8]> {
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
    // serialNumber, signature, issuer, validity — then subject (the 5th
    // element after the optional version).
    for _ in 0..4 {
        let (_, _, tail) = der_elem(rest)?;
        rest = tail;
    }
    let (tag, subject_content, _) = der_elem(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(subject_content)
}

/// Walk the TBS of a leaf certificate to the ISSUER RDNSequence content
/// (DW-035): the bytes INSIDE the issuer SEQUENCE header. The issuer is
/// the 4th element of TBSCertificate (after the optional version):
/// serialNumber, signature, issuer. None on any structural shortcoming.
/// Same DER-walk substrate as [`subject_of_leaf`].
fn issuer_of_leaf<'a>(cert: &'a CertificateDer<'a>) -> Option<&'a [u8]> {
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
    // serialNumber, signature, then issuer (the 3rd element after the
    // optional version).
    for _ in 0..2 {
        let (_, _, tail) = der_elem(rest)?;
        rest = tail;
    }
    let (tag, issuer_content, _) = der_elem(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(issuer_content)
}

/// Extract the issuer CommonName of a leaf certificate (DW-035): the
/// value of the FIRST CN attribute (OID 2.5.4.3) in the issuer RDN
/// sequence. Same strict UTF-8 decode as [`subject_cn_of_leaf`]; `None`
/// when the issuer carries no decodable CN. THE CERTIFICATE IS ALREADY
/// VERIFIED at the TLS layer when this runs; extraction only reads the
/// value for the `X-Client-Cert-Issuer-CN` forwarding header.
pub fn issuer_cn_of_leaf(cert: &CertificateDer<'_>) -> Option<String> {
    let issuer = issuer_of_leaf(cert)?;
    cn_of_rdn_sequence(issuer)
}

/// Walk the TBS of a leaf certificate to the VALIDITY SEQUENCE content
/// (DW-035): the bytes INSIDE the validity SEQUENCE. The validity is
/// the 5th element of TBSCertificate (after the optional version):
/// serialNumber, signature, issuer, validity. None on any structural
/// shortcoming.
fn validity_of_leaf<'a>(cert: &'a CertificateDer<'a>) -> Option<&'a [u8]> {
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
    // serialNumber, signature, issuer, validity (the 4th element after
    // the optional version).
    for _ in 0..3 {
        let (_, _, tail) = der_elem(rest)?;
        rest = tail;
    }
    let (tag, validity_content, _) = der_elem(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(validity_content)
}

/// Extract the `notAfter` timestamp of a leaf certificate (DW-035) as
/// Unix epoch seconds. The validity SEQUENCE holds two time values:
/// `notBefore` then `notAfter`, each a UTCTime (tag 0x17, YYMMDDHHMMSSZ)
/// or GeneralizedTime (tag 0x18, YYYYMMDDHHMMSSZ). Returns `None` on
/// any structural shortcoming or an unparseable time. THE CERTIFICATE
/// IS ALREADY VERIFIED at the TLS layer when this runs; extraction only
/// reads the value for the `X-Client-Cert-Not-After` forwarding header.
pub fn not_after_unix_secs(cert: &CertificateDer<'_>) -> Option<i64> {
    let validity = validity_of_leaf(cert)?;
    // Skip notBefore (the first element) to reach notAfter.
    let (_, _, after_not_before) = der_elem(validity)?;
    let (tag, time_bytes, _) = der_elem(after_not_before)?;
    match tag {
        0x17 => parse_utc_time(time_bytes),
        0x18 => parse_generalized_time(time_bytes),
        _ => None,
    }
}

/// Parse a UTCTime value (tag 0x17, `YYMMDDHHMMSSZ`) into Unix epoch
/// seconds. RFC 5280 section 4.1.2.5.1: the year is interpreted as
/// 1950-2049 for YY 00-49 and 1900-1999 for YY 50-99. The trailing `Z`
/// (UTC) is required; no offsets are supported (certificates carry UTC
/// times only).
fn parse_utc_time(bytes: &[u8]) -> Option<i64> {
    // Minimum: YYMMDDHHMMSSZ (13 bytes). Seconds are required in
    // X.509 (RFC 5280); fractional seconds are not allowed in UTCTime.
    if bytes.len() < 13 || *bytes.last()? != b'Z' {
        return None;
    }
    let body = &bytes[..bytes.len() - 1];
    let yy = two_digit_decimal(body, 0)?;
    let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
    let month = two_digit_decimal(body, 2)? as u32;
    let day = two_digit_decimal(body, 4)? as u32;
    let hour = two_digit_decimal(body, 6)? as u32;
    let minute = two_digit_decimal(body, 8)? as u32;
    let second = two_digit_decimal(body, 10)? as u32;
    epoch_secs(year, month, day, hour, minute, second)
}

/// Parse a GeneralizedTime value (tag 0x18, `YYYYMMDDHHMMSSZ`) into
/// Unix epoch seconds. RFC 5280 section 4.1.2.5.2: GeneralizedTime is
/// used for dates after 2049; the trailing `Z` (UTC) is required.
fn parse_generalized_time(bytes: &[u8]) -> Option<i64> {
    if bytes.len() < 15 || *bytes.last()? != b'Z' {
        return None;
    }
    let body = &bytes[..bytes.len() - 1];
    let year = four_digit_decimal(body, 0)?;
    let month = two_digit_decimal(body, 4)? as u32;
    let day = two_digit_decimal(body, 6)? as u32;
    let hour = two_digit_decimal(body, 8)? as u32;
    let minute = two_digit_decimal(body, 10)? as u32;
    let second = two_digit_decimal(body, 12)? as u32;
    epoch_secs(year, month, day, hour, minute, second)
}

/// Read two ASCII decimal digits at `offset` as a u16.
fn two_digit_decimal(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + 2)?;
    let hi = (bytes[0] as char).to_digit(10)?;
    let lo = (bytes[1] as char).to_digit(10)?;
    Some((hi * 10 + lo) as u16)
}

/// Read four ASCII decimal digits at `offset` as a u16 (year).
fn four_digit_decimal(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + 4)?;
    let mut v = 0u16;
    for &b in bytes {
        v = v * 10 + (b as char).to_digit(10)? as u16;
    }
    Some(v)
}

/// Convert a calendar date + time to Unix epoch seconds using a
/// civil-from-days algorithm (Howard Hinnant, no chrono dependency).
/// Returns None for an invalid date (month outside 1..=12, day outside
/// the month's range, or a year outside the u16-representable range).
fn epoch_secs(year: u16, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }
    let y = year as i64;
    let m = month as i64;
    let d = day as i64;
    // Days from the civil epoch (1970-01-01) to (y, m, d). The algorithm
    // is from Howard Hinnant's "date" library (the days_from_civil
    // function), public domain.
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = (y_adj - era * 400) as u64; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64; // [0, 146096]
    let days = era * 146097 + doe as i64 - 719468;
    let secs = days * 86400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64;
    // Validate the day is in range for the month (the algorithm above
    // does not reject e.g. Feb 30; a round-trip check would, but the
    // certificate was already verified by rustls so a structurally
    // invalid date here is a malformed cert, not an attack surface).
    // Accept the computed value: rustls's own validity check already
    // rejected an expired/not-yet-valid cert at the TLS layer when
    // verification ran.
    Some(secs)
}

/// Extract the FIRST CN attribute (OID 2.5.4.3) from an RDN sequence's
/// raw DER content (the bytes INSIDE the SEQUENCE header). Shared by
/// [`subject_cn_of_leaf`] and [`issuer_cn_of_leaf`]; strict UTF-8
/// decode (reject rather than fold, the same rationale).
fn cn_of_rdn_sequence(rdn_sequence: &[u8]) -> Option<String> {
    let mut rdns = rdn_sequence;
    while let Some((set_tag, set_content, tail)) = der_elem(rdns) {
        if set_tag != 0x31 {
            return None;
        }
        let mut attrs = set_content;
        while let Some((seq_tag, attr, attr_tail)) = der_elem(attrs) {
            if seq_tag == 0x30 {
                if let Some((oid_tag, oid, after_oid)) = der_elem(attr) {
                    if oid_tag == 0x06 && oid == [0x55, 0x04, 0x03] {
                        if let Some((val_tag, val, _)) = der_elem(after_oid) {
                            if matches!(val_tag, 0x0c | 0x13 | 0x16) {
                                return Some(std::str::from_utf8(val).ok()?.to_string());
                            }
                        }
                    }
                }
            }
            attrs = attr_tail;
        }
        rdns = tail;
    }
    None
}

/// Extract the subject CommonName of a leaf certificate (#124): the
/// value of the FIRST CN attribute (OID 2.5.4.3) in the subject RDN
/// sequence, decoded from UTF8String / PrintableString / IA5String (the
/// string types CNs carry in practice). The decode is STRICT UTF-8:
/// invalid CN bytes yield `None` rather than being lossy-folded to
/// U+FFFD, which could collide two distinct malformed names into one
/// selector. `None` also when the subject carries no CN at all — either
/// way such a certificate can only match a by-fingerprint mTLS
/// credential (the caller falls back to the fingerprint selector).
/// Hand-rolled DER walk (no X.509 parser dependency), same substrate as
/// the private SPKI extractor in this module. THE CERTIFICATE IS
/// ALREADY VERIFIED at the TLS layer when this runs; extraction only
/// reads the match value.
pub fn subject_cn_of_leaf(cert: &CertificateDer<'_>) -> Option<String> {
    let subject = subject_of_leaf(cert)?;
    cn_of_rdn_sequence(subject)
}

/// Format the SHA-256 fingerprint of a certificate DER as lowercase
/// colon-separated hex (DW-035): the format the
/// `mtls_consumer_mapping.consumers[].fingerprint` config field and the
/// `X-Client-Cert-Fingerprint` forwarding header use. The raw hex
/// (no colons) is the credential SELECTOR the authn registry indexes;
/// this colon-separated form is the OPERATOR-facing display format
/// (config and headers), so the two never collide.
pub fn fingerprint_colon_hex(cert: &CertificateDer<'_>) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(cert.as_ref());
    let hex = crate::config::credentials::sha256_hex(cert.as_ref());
    // Group the 64-char hex into 32 byte pairs joined by ':'.
    let bytes = hex.as_bytes();
    let mut out = String::with_capacity(64 + 31);
    for (i, chunk) in bytes.chunks(2).enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    let _ = digest; // sha256_hex already computed; keep the import used.
    out
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
        // DW-105: when the listener opts in to post-quantum hybrid key
        // exchange (`pq: true`) AND the `pq` cargo feature is ON, prepend
        // the X25519+ML-KEM hybrid kx group to the provider's kx group
        // list. The rustls PQ API is experimental; [`install_pq_kx_group`]
        // is a documented no-op when the API is not reachable in the
        // pinned rustls version (the config builds with the classical kx
        // group list — no regression). When the `pq` feature is OFF, the
        // call is inert (returns [`PqMode::Disabled`]). Validation
        // rejects `pq: true` + FIPS mode (ML-KEM is not FIPS-validated).
        if tls.pq {
            let _ = crate::security::pq::install_pq_kx_group();
        }
        // #124 client-certificate authn: with a `client_ca_file` the
        // listener REQUESTS a client certificate and verifies any
        // presented one against the bundle (the admin mTLS verifier
        // pattern), but — unlike the admin listener — does NOT require
        // one: `allow_unauthenticated` keeps the listener open to API-key
        // / Basic / JWT / anonymous traffic, and authn matches the
        // VERIFIED certificate against consumers' `mtls` credentials. An
        // UNVERIFIED certificate fails the handshake here and never
        // reaches the authenticator (mTLS authn only ever sees
        // certificates rustls has already chained to the configured CA).
        //
        // DW-111: when the `fips` cargo feature is ON, the server config
        // is built with the FIPS-approved cipher suites only (the
        // process-default provider's suite list filtered to the
        // allowlist in `security::fips`). Non-FIPS builds use the
        // default builder (rustls's modern cipher-suite policy).
        #[cfg(feature = "fips")]
        {
            let provider = Arc::new(fips_provider());
            let mut config = match &tls.client_ca_file {
                Some(client_ca) => {
                    let roots = root_store_from_pem_file(client_ca)?;
                    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                        Arc::new(roots),
                        Arc::clone(&provider),
                    )
                    .allow_unauthenticated()
                    .build()
                    .map_err(|e| TlsError::ClientAuth(format!("building client verifier: {e}")))?;
                    ServerConfig::builder_with_provider(Arc::clone(&provider))
                        .with_safe_default_protocol_versions()
                        .map_err(|e| TlsError::Rustls(e))?
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(Arc::new(resolver))
                }
                None => ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| TlsError::Rustls(e))?
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(resolver)),
            };
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Ok(config)
        }
        #[cfg(not(feature = "fips"))]
        {
            let mut config = match &tls.client_ca_file {
                Some(client_ca) => {
                    let roots = root_store_from_pem_file(client_ca)?;
                    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                        .allow_unauthenticated()
                        .build()
                        .map_err(|e| {
                            TlsError::ClientAuth(format!("building client verifier: {e}"))
                        })?;
                    ServerConfig::builder()
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(Arc::new(resolver))
                }
                None => ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(resolver)),
            };
            // ALPN advertises both; the client's choice decides HTTP/1.1 vs
            // HTTP/2 (hyper-util's auto builder handles whichever arrives).
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Ok(config)
        }
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
    // Same PEM-bundle loading as the outbound trusted_ca_file path (#121):
    // one root-store-from-file helper, shared by admin mTLS and outbound
    // connectors, so bundle semantics cannot drift between them.
    let roots = root_store_from_pem_file(&tls.client_ca_file)?;
    // DW-111: when the `fips` cargo feature is ON, the admin mTLS config
    // is also built with the FIPS-approved cipher suites only (the same
    // restriction as dataplane termination). Non-FIPS builds use the
    // default builder.
    #[cfg(feature = "fips")]
    {
        let provider = Arc::new(fips_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|e| TlsError::ClientAuth(format!("building admin client verifier: {e}")))?;
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::Rustls(e))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SingleCertResolver(certified)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
    #[cfg(not(feature = "fips"))]
    {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| TlsError::ClientAuth(format!("building admin client verifier: {e}")))?;
        let mut config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SingleCertResolver(certified)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
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

/// Peek the TLS ClientHello SNI off a TCP stream WITHOUT splicing.
///
/// This is the peek-only half of [`handle_passthrough`], extracted so
/// the DW-103 L4 TCP dispatcher can reuse the EXACT SNI extraction
/// (the same bounded reassembly, the same 64 KiB budget, the same 10s
/// peek timeout) and then own its own splice (with an idle timeout and
/// L4 metrics). Returns `Ok(None)` when the client sends no SNI, a
/// non-TLS hello, or the peek times out. Peeking (never reading) keeps
/// the bytes available for the upstream once splicing starts.
pub async fn peek_client_hello_sni(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut scratch = vec![0u8; PEEK_LIMIT];
    let started = std::time::Instant::now();
    loop {
        let n = stream.peek(&mut scratch).await?;
        if n == 0 {
            return Ok(None);
        }
        let seen = &scratch[..n];
        match examine_peeked(seen) {
            HelloPeek::Sni(name) => return Ok(Some(name)),
            HelloPeek::Settled => return Ok(None),
            HelloPeek::Pending => {
                if n >= PEEK_LIMIT || started.elapsed() >= PEEK_TIMEOUT {
                    return Ok(None);
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
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

// ---------------------------------------------------------------------------
// DW-107: SPIFFE/SPIRE mTLS integration point (service mesh mode).
//
// The functions below are the documented seam between the mesh domain
// (which produces SVID cert/key material and the trust bundle from the
// SPIRE Workload API) and the TLS machinery here (which would consume
// that material to build the mTLS server/client config). They are
// SCAFFOLDED behind the `mesh` cargo feature: the shapes compile so
// the integration contract is fixed, but the actual rustls config
// construction is a documented no-op today (the `spiffe` crate would
// be added when production-ready). The seam is kept here, in
// `security::tls`, rather than in `mesh`, so the dependency direction
// stays downward (`mesh` is a peer of `security`, both above `config`;
// `mesh` does not import `security`).
// ---------------------------------------------------------------------------

/// The mTLS role the SPIFFE-aware TLS config plays for a connection.
/// Inbound sidecar connections act as the mTLS server (terminate the
/// peer's SVID); outbound sidecar connections act as the mTLS client
/// (present the local workload's SVID).
#[cfg(feature = "mesh")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiffeMtlsRole {
    /// The sidecar terminates the peer's mTLS (inbound): the SVID
    /// cert/key is the server certificate, the trust bundle verifies
    /// the peer (client) SVID.
    Server,
    /// The sidecar presents the local workload's SVID (outbound): the
    /// SVID cert/key is the client certificate, the trust bundle
    /// verifies the remote sidecar's (server) SVID.
    Client,
}

/// Build a SPIFFE-aware mTLS rustls config from an X.509 SVID and a
/// trust bundle. This is the integration point between the mesh domain
/// (which fetches SVIDs from the SPIRE Workload API) and the TLS
/// machinery here.
///
/// # Stubbed
///
/// This is a documented no-op today. The actual rustls
/// `ServerConfig`/`ClientConfig` construction -- loading the SVID cert
/// chain + private key as the presented certificate, the trust bundle
/// as the peer-verification root store, and wiring a SPIFFE-ID-aware
/// certificate verifier (one that extracts the URI SAN SPIFFE ID from
/// the verified peer cert and hands it to the auth layer as the
/// identity) -- would land here when the `spiffe` crate is added. Today
/// the function logs that the integration is stubbed and returns an
/// error so callers fail loudly and attributably.
#[cfg(feature = "mesh")]
pub fn build_spiffe_mtls_config(
    role: SpiffeMtlsRole,
    svid: &crate::mesh::SpiffeSvid,
    trust_bundle: &crate::mesh::SpiffeTrustBundle,
) -> Result<(), TlsError> {
    tracing::info!(
        code = "spiffe_mtls_config_stubbed",
        role = ?role,
        cert_chain_len = svid.x509_cert.len(),
        trust_bundle_len = trust_bundle.x509_certs.len(),
        "the SPIFFE-aware mTLS rustls config construction is stubbed (DW-107): the \
         `spiffe` crate would be added when production-ready. The SVID cert/key and \
         trust bundle would be loaded into a rustls ServerConfig/ClientConfig with a \
         SPIFFE-ID-aware certificate verifier (the peer's URI SAN SPIFFE ID is the \
         auth identity). No rustls config is built."
    );
    // The shapes are used so the integration contract compiles and the
    // scaffold is exercised; the real construction lands here when the
    // spiffe crate is wired.
    let _ = (role, svid, trust_bundle);
    Err(TlsError::NoCertificates)
}

/// Extract the SPIFFE ID (the URI SAN) from a verified peer
/// certificate. This is the auth identity the mesh uses for policy
/// decisions: the sidecar terminates mTLS, verifies the peer SVID
/// against the trust bundle, then extracts the SPIFFE ID from the
/// peer cert's URI SAN and hands it to the auth layer as the
/// principal/consumer.
///
/// # Stubbed
///
/// Documented no-op today. The DER walk to the URI SAN extension
/// (the same substrate as `spki_of_leaf`, no X.509 parser dependency)
/// would land here when the mesh mTLS wiring is production-ready. Today
/// the function returns None.
#[cfg(feature = "mesh")]
pub fn extract_spiffe_id_from_peer_cert(
    _cert: &rustls::pki_types::CertificateDer<'_>,
) -> Option<crate::mesh::SpiffeIdentity> {
    // The URI SAN extraction (a DER walk to the SubjectAltName
    // extension, then the URI entry tagged with the SPIFFE scheme)
    // would land here when production-ready, mirroring the
    // `spki_algorithm_of_leaf` DER walk used by FIPS validation. Today
    // the function is a documented no-op.
    tracing::info!(
        code = "spiffe_id_extraction_stubbed",
        "the SPIFFE ID (URI SAN) extraction from a peer certificate is stubbed \
         (DW-107): the DER walk would land here when the mesh mTLS wiring is \
         production-ready."
    );
    None
}
