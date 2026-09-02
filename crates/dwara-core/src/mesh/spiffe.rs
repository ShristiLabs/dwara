//! SPIFFE/SPIRE mTLS identity (DW-107).
//!
//! Identity in the service mesh is provided by SPIFFE (Secure Production
//! Identity Framework for Everyone) via SPIRE (the SPIFFE Runtime
//! Environment). Each workload fetches X.509 SVIDs (SPIFFE Verifiable
//! Identity Documents) from the SPIRE Workload API, exposed over a Unix
//! domain socket. An X.509 SVID is an X.509 certificate whose URI SAN
//! carries the workload's SPIFFE ID (`spiffe://<trust-domain>/<path>`).
//! The SPIFFE ID is the authentication identity used for policy
//! decisions; the trust bundle (the SPIRE signing CAs) is used to
//! verify peer SVIDs.
//!
//! # Integration point
//!
//! The mTLS TLS config in `security::tls` would consume the SVID
//! certificate/key (as the presented client/server cert) and the trust
//! bundle (as the peer-verification root store). The peer's SPIFFE ID
//! is extracted from the verified peer certificate's URI SAN and used
//! as the auth identity (the consumer / principal for policy
//! decisions). This seam is documented here and kept as a hand-off
//! (mesh produces the SVID material; security consumes it) so the
//! dependency direction stays downward.
//!
//! # Stubbed
//!
//! The Workload API connection and SVID fetch are STUBBED. The
//! [`SpiffeClient`] records the configured socket path and refresh
//! interval and exposes the integration point, but does NOT open the
//! Unix socket or fetch real SVIDs. The `spiffe` crate (which speaks
//! the SPIRE Workload API gRPC protocol over the Unix socket and
//! handles SVID rotation) would be added as an optional dependency
//! when production-ready; today the scaffold compiles with no new
//! dependencies and the config schema round-trips.

use crate::config::mesh::MeshSpiffeConfig;
use std::path::PathBuf;
use std::time::Duration;

/// A SPIFFE ID: the trust domain and the path that together form the
/// workload identity (`spiffe://<trust-domain>/<path>`).
///
/// The SPIFFE ID is the URI SAN carried in an X.509 SVID; it is the
/// authentication identity the mesh uses for policy decisions. The
/// trust domain is the trust boundary (e.g. `example.org`); the path
/// identifies the workload within the trust domain (e.g.
/// `/ns/default/sa/my-service`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeIdentity {
    /// The trust domain (the part after `spiffe://` and before the
    /// first `/`). Must be non-empty.
    pub trust_domain: String,
    /// The SPIFFE path (everything after the trust domain, including
    /// the leading `/`). Must start with `/`.
    pub path: String,
}

impl SpiffeIdentity {
    /// Build a SPIFFE ID from a trust domain and path. The path is
    /// normalized to start with `/` (a leading slash is prepended when
    /// missing, mirroring the SPIFFE ID grammar).
    pub fn new(trust_domain: impl Into<String>, path: impl Into<String>) -> Self {
        let trust_domain = trust_domain.into();
        let mut path = path.into();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        SpiffeIdentity { trust_domain, path }
    }

    /// Parse a `spiffe://<trust-domain>/<path>` URI into a
    /// [`SpiffeIdentity`]. Returns None when the scheme is not
    /// `spiffe://` or the trust domain is empty.
    pub fn parse(uri: &str) -> Option<Self> {
        let rest = uri.strip_prefix("spiffe://")?;
        let (trust_domain, path) = rest.split_once('/')?;
        if trust_domain.is_empty() {
            return None;
        }
        Some(SpiffeIdentity {
            trust_domain: trust_domain.to_string(),
            path: format!("/{path}"),
        })
    }

    /// The canonical URI form: `spiffe://<trust-domain><path>`.
    pub fn to_uri(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }

    /// True when the identity is well-formed: non-empty trust domain
    /// and a path starting with `/`.
    pub fn is_valid(&self) -> bool {
        !self.trust_domain.is_empty() && self.path.starts_with('/')
    }
}

impl std::fmt::Display for SpiffeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_uri())
    }
}

/// An X.509 SVID: the certificate chain, the private key, and the
/// expiry the workload presents to prove its SPIFFE identity.
///
/// The certificate's URI SAN carries the [`SpiffeIdentity`]; the
/// private key is the matching key. The SVID is refreshed before
/// expiry by the [`SpiffeClient`].
#[derive(Debug, Clone)]
pub struct SpiffeSvid {
    /// The X.509 certificate chain (DER bytes, leaf first). The leaf
    /// certificate's URI SAN carries the SPIFFE ID.
    pub x509_cert: Vec<Vec<u8>>,
    /// The private key matching the leaf certificate (DER bytes). This
    /// is sensitive material; it is zeroized on drop when the
    /// production wiring lands (today the field holds scaffold bytes).
    pub private_key: Vec<u8>,
    /// The SVID expiry (seconds since the Unix epoch). The client
    /// refreshes the SVID before this time.
    pub expires_at: u64,
}

impl SpiffeSvid {
    /// Seconds until the SVID expires, relative to `now`. Clamped to 0
    /// when already expired (the gauge metric never goes negative).
    pub fn seconds_until_expiry(&self, now: u64) -> i64 {
        let remaining = self.expires_at.saturating_sub(now);
        remaining as i64
    }
}

/// The SPIFFE trust bundle: the X.509 root certificates (the SPIRE
/// signing CAs) used to verify peer SVIDs. The bundle is fetched from
/// the Workload API alongside the SVID and refreshed on the same
/// schedule.
#[derive(Debug, Clone)]
pub struct SpiffeTrustBundle {
    /// The X.509 CA certificates (DER bytes) that sign SVIDs in this
    /// trust domain. The mTLS TLS config uses these as the
    /// peer-verification root store.
    pub x509_certs: Vec<Vec<u8>>,
}

/// The resolved SPIFFE configuration: the trust domain, the Workload
/// API socket path, and the SVID refresh interval. Built from the
/// config schema ([`MeshSpiffeConfig`]) at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeConfig {
    /// The trust domain this workload belongs to (e.g. `example.org`).
    /// Must be non-empty.
    pub trust_domain: String,
    /// The filesystem path of the SPIRE Workload API Unix socket
    /// (e.g. `/tmp/spire-agent/public/api.sock`). Must be non-empty.
    pub workload_api_socket: PathBuf,
    /// The SVID refresh interval. The client refreshes the SVID (and
    /// trust bundle) before expiry, at half the remaining lifetime by
    /// default; this is the upper bound on the refresh cadence.
    pub svid_refresh_interval: Duration,
}

impl SpiffeConfig {
    /// Build a [`SpiffeConfig`] from the config schema.
    pub fn from_config(cfg: &MeshSpiffeConfig) -> Self {
        SpiffeConfig {
            trust_domain: cfg.trust_domain.clone(),
            workload_api_socket: PathBuf::from(&cfg.workload_api_socket),
            svid_refresh_interval: Duration::from_secs(cfg.svid_refresh_interval_secs),
        }
    }
}

/// The SPIFFE Workload API client: connects to the SPIRE agent over a
/// Unix socket, fetches X.509 SVIDs for the workload, and refreshes
/// them before expiry.
///
/// # Stubbed
///
/// The Workload API connection and SVID fetch are STUBBED. The client
/// records the configured socket path and refresh interval and exposes
/// the integration point (the mTLS TLS config would use the SVID
/// cert/key and the trust bundle for peer verification), but does NOT
/// open the Unix socket or fetch real SVIDs. The `spiffe` crate (which
/// speaks the SPIRE Workload API gRPC protocol over the Unix socket
/// and handles SVID rotation) would be added as an optional dependency
/// when production-ready. Today the scaffold compiles with no new
/// dependencies.
#[derive(Debug, Clone)]
pub struct SpiffeClient {
    config: SpiffeConfig,
}

/// The outcome of an SVID refresh attempt, captured for the
/// `dwara_spiffe_svid_refresh_total{result}` metric. The CLOSED
/// two-value label set: `success` when the Workload API returned a
/// fresh SVID, `error` when the fetch failed (the client keeps serving
/// the previous SVID until it expires).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvidRefreshResult {
    /// The Workload API returned a fresh SVID and trust bundle.
    Success,
    /// The fetch failed (socket unreachable, gRPC error, parse
    /// failure). The client keeps serving the previous SVID until it
    /// expires; a refresh failure does not drop the workload's
    /// identity immediately.
    Error,
}

impl SvidRefreshResult {
    /// The lowercase metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            SvidRefreshResult::Success => "success",
            SvidRefreshResult::Error => "error",
        }
    }
}

impl SpiffeClient {
    /// Build a client from the resolved SPIFFE config.
    pub fn new(config: SpiffeConfig) -> Self {
        SpiffeClient { config }
    }

    /// The resolved SPIFFE configuration.
    pub fn config(&self) -> &SpiffeConfig {
        &self.config
    }

    /// The workload's SPIFFE ID for the configured trust domain and a
    /// path. This is the identity the SVID's URI SAN carries and the
    /// auth identity the mesh uses for policy decisions.
    pub fn workload_identity(&self, path: &str) -> SpiffeIdentity {
        SpiffeIdentity::new(&self.config.trust_domain, path)
    }

    /// Fetch the workload's current X.509 SVID from the Workload API.
    ///
    /// # Stubbed
    ///
    /// This is a documented no-op today. The Workload API gRPC call
    /// over the Unix socket (the `spiffe` crate's
    /// `WorkloadApi::fetch_x509_svid`) would land here when
    /// production-ready. Today the function logs that the fetch is
    /// stubbed and returns an error result so the
    /// `dwara_spiffe_svid_refresh_total{result="error"}` metric
    /// records the stubbed state. The SVID material the mTLS TLS
    /// config would consume (cert chain, private key, expiry) is the
    /// integration point documented above.
    pub fn fetch_svid(&self) -> Result<SpiffeSvid, SpiffeError> {
        tracing::info!(
            code = "spiffe_workload_api_stubbed",
            socket = %self.config.workload_api_socket.display(),
            trust_domain = %self.config.trust_domain,
            "the SPIRE Workload API fetch is stubbed (DW-107): the `spiffe` crate would be \
             added when production-ready. No SVID is fetched; the mTLS TLS config integration \
             point is documented in mesh::spiffe."
        );
        Err(SpiffeError::WorkloadApiStubbed)
    }

    /// Fetch the trust bundle (the SPIRE signing CAs) from the Workload
    /// API. Used as the peer-verification root store in the mTLS TLS
    /// config.
    ///
    /// # Stubbed
    ///
    /// Documented no-op today (same as [`Self::fetch_svid`]).
    pub fn fetch_trust_bundle(&self) -> Result<SpiffeTrustBundle, SpiffeError> {
        tracing::info!(
            code = "spiffe_trust_bundle_stubbed",
            "the SPIRE Workload API trust-bundle fetch is stubbed (DW-107)"
        );
        Err(SpiffeError::WorkloadApiStubbed)
    }

    /// Refresh the SVID before expiry. The client refreshes at half the
    /// remaining lifetime by default; the configured
    /// `svid_refresh_interval` is the upper bound on the cadence.
    ///
    /// # Stubbed
    ///
    /// Documented no-op today: the refresh loop would call
    /// [`Self::fetch_svid`] on a timer and swap the live SVID behind an
    /// `ArcSwap` (the same hot-reload shape as `security::tls`). Today
    /// it records the stubbed result for the refresh metric.
    pub fn refresh_svid(&self) -> SvidRefreshResult {
        match self.fetch_svid() {
            Ok(_) => SvidRefreshResult::Success,
            Err(_) => SvidRefreshResult::Error,
        }
    }
}

/// Error returned by the stubbed SPIFFE Workload API calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffeError {
    /// The Workload API fetch is stubbed (DW-107): the `spiffe` crate
    /// is not yet wired. The mTLS TLS config integration point is
    /// documented in `mesh::spiffe`.
    WorkloadApiStubbed,
    /// The Workload API socket could not be reached (the production
    /// wiring would surface the underlying I/O / gRPC error here).
    WorkloadApiUnreachable(String),
}

impl std::fmt::Display for SpiffeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpiffeError::WorkloadApiStubbed => write!(
                f,
                "spiffe workload api fetch is stubbed (DW-107): the `spiffe` crate is not yet \
                 wired"
            ),
            SpiffeError::WorkloadApiUnreachable(m) => {
                write!(f, "spiffe workload api unreachable: {m}")
            }
        }
    }
}

impl std::error::Error for SpiffeError {}
