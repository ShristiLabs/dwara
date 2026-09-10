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
//! # Implementation
//!
//! The Workload API client is implemented behind a transport
//! abstraction ([`WorkloadApiTransport`]) so the fetch logic is
//! testable without a real SPIRE agent. The production transport
//! (`GrpcWorkloadApi`) uses tonic over a Unix domain socket and is
//! gated behind the `ent` cargo feature (which brings in tonic + prost;
//! the mesh feature itself is flag-only). A [`FakeWorkloadApi`] is
//! provided for tests.
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
    /// The workload's SPIFFE ID (parsed from the SVID's URI SAN).
    pub spiffe_id: SpiffeIdentity,
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
    /// The trust domain this bundle covers.
    pub trust_domain: String,
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

/// The transport abstraction for the SPIRE Workload API. The
/// production implementation (`GrpcWorkloadApi`) uses tonic over a
/// Unix domain socket (ent-gated); tests use [`FakeWorkloadApi`].
///
/// The trait is async via `async-trait` (dyn-compatible, the same
/// pattern as the extensions traits). The methods mirror the SPIRE
/// Workload API's `FetchX509SVID` and `FetchX509Bundle` RPCs.
#[async_trait::async_trait]
pub trait WorkloadApiTransport: Send + Sync + 'static {
    /// Fetch the workload's X.509 SVIDs from the Workload API. The
    /// response contains one SVID per SPIFFE ID the workload is
    /// authorized to present (typically one). The SVID's cert chain
    /// and private key are DER bytes; the expiry is seconds since the
    /// Unix epoch.
    async fn fetch_x509_svid(&self) -> Result<Vec<SpiffeSvid>, SpiffeError>;

    /// Fetch the trust bundle (the SPIRE signing CAs) for the
    /// configured trust domain from the Workload API. The bundle's
    /// CA certs are DER bytes; the mTLS TLS config uses them as the
    /// peer-verification root store.
    async fn fetch_x509_bundle(&self) -> Result<SpiffeTrustBundle, SpiffeError>;
}

/// The SPIFFE Workload API client: connects to the SPIRE agent over a
/// Unix socket, fetches X.509 SVIDs for the workload, and refreshes
/// them before expiry.
///
/// The client holds a [`WorkloadApiTransport`] (the production gRPC
/// transport or a test fake) and delegates the actual fetch to it.
/// The refresh logic (when to refresh, what to do on failure) lives
/// here; the transport is the seam for the wire protocol.
#[derive(Clone)]
pub struct SpiffeClient {
    config: SpiffeConfig,
    transport: std::sync::Arc<dyn WorkloadApiTransport>,
}

impl std::fmt::Debug for SpiffeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClient")
            .field("config", &self.config)
            .field("transport", &"<dyn WorkloadApiTransport>")
            .finish()
    }
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
    /// Build a client from the resolved SPIFFE config and a transport.
    /// The transport is the seam for the Workload API wire protocol:
    /// the production gRPC transport (`GrpcWorkloadApi`) or a test
    /// fake ([`FakeWorkloadApi`]).
    pub fn new(config: SpiffeConfig, transport: std::sync::Arc<dyn WorkloadApiTransport>) -> Self {
        SpiffeClient { config, transport }
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

    /// Fetch the workload's current X.509 SVIDs from the Workload API.
    /// The response contains one SVID per SPIFFE ID the workload is
    /// authorized to present (typically one). The first SVID is the
    /// primary; callers that only need one SVID can use
    /// [`Self::fetch_primary_svid`].
    pub async fn fetch_svid(&self) -> Result<Vec<SpiffeSvid>, SpiffeError> {
        self.transport.fetch_x509_svid().await
    }

    /// Fetch the workload's primary (first) X.509 SVID from the
    /// Workload API. Convenience wrapper around [`Self::fetch_svid`]
    /// that returns the first SVID or an error when the response is
    /// empty.
    pub async fn fetch_primary_svid(&self) -> Result<SpiffeSvid, SpiffeError> {
        let mut svids = self.fetch_svid().await?;
        if svids.is_empty() {
            return Err(SpiffeError::EmptyResponse);
        }
        Ok(svids.remove(0))
    }

    /// Fetch the trust bundle (the SPIRE signing CAs) from the Workload
    /// API. Used as the peer-verification root store in the mTLS TLS
    /// config.
    pub async fn fetch_trust_bundle(&self) -> Result<SpiffeTrustBundle, SpiffeError> {
        self.transport.fetch_x509_bundle().await
    }

    /// Refresh the SVID before expiry. The client refreshes at half the
    /// remaining lifetime by default; the configured
    /// `svid_refresh_interval` is the upper bound on the cadence.
    ///
    /// This is the synchronous wrapper used by the refresh loop's
    /// metric recording path. The actual fetch is async (delegated to
    /// the transport); the refresh loop spawns the async fetch and
    /// records the result here.
    pub fn refresh_result_from_fetch(
        &self,
        fetch_result: &Result<SpiffeSvid, SpiffeError>,
    ) -> SvidRefreshResult {
        match fetch_result {
            Ok(_) => SvidRefreshResult::Success,
            Err(_) => SvidRefreshResult::Error,
        }
    }
}

/// Error returned by the SPIFFE Workload API calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffeError {
    /// The Workload API socket could not be reached (the SPIRE agent
    /// is not running, the socket path is wrong, or the connection
    /// was refused).
    WorkloadApiUnreachable(String),
    /// The Workload API returned an empty response (no SVIDs). The
    /// workload is not registered with SPIRE, or the agent's workload
    /// selector does not match this process.
    EmptyResponse,
    /// The Workload API returned a malformed response (the protobuf
    /// could not be parsed, or the SVID's certificate chain is
    /// invalid).
    MalformedResponse(String),
    /// The gRPC call failed (the Workload API returned a non-OK
    /// status). The message is the gRPC status message.
    GrpcStatus(String),
}

impl std::fmt::Display for SpiffeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpiffeError::WorkloadApiUnreachable(m) => {
                write!(f, "spiffe workload api unreachable: {m}")
            }
            SpiffeError::EmptyResponse => {
                write!(f, "spiffe workload api returned no svids")
            }
            SpiffeError::MalformedResponse(m) => {
                write!(f, "spiffe workload api malformed response: {m}")
            }
            SpiffeError::GrpcStatus(m) => {
                write!(f, "spiffe workload api grpc error: {m}")
            }
        }
    }
}

impl std::error::Error for SpiffeError {}

// ---------------------------------------------------------------------------
// Production gRPC transport (ent feature only: tonic + prost)
// ---------------------------------------------------------------------------

/// The production Workload API transport: a gRPC client over a Unix
/// domain socket, using tonic (the same stack as the CP/DP transport).
/// Gated behind the `ent` cargo feature because tonic + prost are
/// ent-gated dependencies.
///
/// The SPIRE Workload API is a simple unary RPC:
///   `FetchX509SVID(X509SVIDRequest) -> (X509SVIDResponse)`
/// The response contains the workload's SVIDs (cert chain + private
/// key + expiry) and the trust bundle (CA certs). The proto is
/// hand-rolled (no protoc/build-script) using prost::Message derives,
/// the same approach as the CP/DP transport.
#[cfg(feature = "ent")]
pub mod grpc {
    use super::{SpiffeError, SpiffeIdentity, SpiffeSvid, SpiffeTrustBundle, WorkloadApiTransport};
    use async_trait::async_trait;
    use bytes::Buf;
    use prost::Message as ProstMessage;
    use std::path::Path;
    use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
    use tonic::transport::Endpoint;
    use tonic::{Request, Status};

    // -----------------------------------------------------------------
    // Wire messages (hand-written prost structs, matching the SPIRE
    // Workload API proto). Field numbers and types match the upstream
    // proto definition (spire-api/workload.proto).
    // -----------------------------------------------------------------

    /// Wire: the FetchX509SVID request (empty body).
    #[derive(Clone, PartialEq, ProstMessage)]
    pub struct PbX509SvidRequest {}

    /// Wire: a single X.509 SVID in the FetchX509SVID response.
    #[derive(Clone, PartialEq, ProstMessage)]
    pub struct PbX509Svid {
        /// The SPIFFE ID (URI form: `spiffe://<trust-domain>/<path>`).
        #[prost(string, tag = "1")]
        pub spiffe_id: String,
        /// The X.509 certificate chain (DER bytes, leaf first).
        #[prost(bytes, tag = "2")]
        pub x509_svid: Vec<u8>,
        /// The private key matching the leaf cert (DER bytes).
        #[prost(bytes, tag = "3")]
        pub x509_svid_key: Vec<u8>,
        /// The SVID expiry (seconds since the Unix epoch).
        #[prost(int64, tag = "4")]
        pub expires_at: i64,
    }

    /// Wire: an X.509 bundle (trust bundle for one trust domain).
    #[derive(Clone, PartialEq, ProstMessage)]
    pub struct PbX509Bundle {
        /// The trust domain this bundle covers.
        #[prost(string, tag = "1")]
        pub trust_domain: String,
        /// The X.509 CA certificates (DER bytes).
        #[prost(bytes, repeated, tag = "2")]
        pub x509_authorities: Vec<Vec<u8>>,
    }

    /// Wire: the FetchX509SVID response.
    #[derive(Clone, PartialEq, ProstMessage)]
    pub struct PbX509SvidResponse {
        /// The workload's SVIDs (one per authorized SPIFFE ID).
        #[prost(message, repeated, tag = "1")]
        pub svids: Vec<PbX509Svid>,
        /// The trust bundles, keyed by trust domain.
        #[prost(map = "string, message", tag = "2")]
        pub bundles: std::collections::HashMap<String, PbX509Bundle>,
    }

    /// Wire: the FetchX509Bundle request.
    #[derive(Clone, PartialEq, ProstMessage)]
    pub struct PbX509BundleRequest {
        /// The trust domain to fetch the bundle for (empty = all).
        #[prost(string, tag = "1")]
        pub trust_domain: String,
    }

    /// Wire: the FetchX509Bundle response.
    #[derive(Clone, PartialEq, ProstMessage)]
    pub struct PbX509BundleResponse {
        /// The trust bundles, keyed by trust domain.
        #[prost(map = "string, message", tag = "1")]
        pub bundles: std::collections::HashMap<String, PbX509Bundle>,
    }

    // -----------------------------------------------------------------
    // Custom prost codec (same pattern as cp_dp/transport.rs; uses the
    // workspace prost 0.14, not tonic's built-in ProstCodec).
    // -----------------------------------------------------------------

    /// A gRPC codec that encodes/decodes prost messages using the
    /// workspace prost 0.14.
    pub struct ProstCodec<T, U> {
        _req: std::marker::PhantomData<T>,
        _resp: std::marker::PhantomData<U>,
    }

    impl<T, U> Default for ProstCodec<T, U> {
        fn default() -> Self {
            ProstCodec {
                _req: std::marker::PhantomData,
                _resp: std::marker::PhantomData,
            }
        }
    }

    impl<T, U> ProstCodec<T, U> {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl<T, U> Codec for ProstCodec<T, U>
    where
        T: ProstMessage + Clone + 'static,
        U: ProstMessage + Default + 'static,
    {
        type Encode = T;
        type Decode = U;
        type Encoder = ProstEncoder<T>;
        type Decoder = ProstDecoder<U>;

        fn encoder(&mut self) -> Self::Encoder {
            ProstEncoder {
                _req: std::marker::PhantomData,
            }
        }

        fn decoder(&mut self) -> Self::Decoder {
            ProstDecoder {
                _resp: std::marker::PhantomData,
            }
        }
    }

    /// Encoder for the custom prost codec.
    pub struct ProstEncoder<T> {
        _req: std::marker::PhantomData<T>,
    }

    impl<T: ProstMessage> Encoder for ProstEncoder<T> {
        type Item = T;
        type Error = Status;

        fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
            item.encode(dst)
                .expect("Message only errors if not enough space");
            Ok(())
        }
    }

    /// Decoder for the custom prost codec.
    pub struct ProstDecoder<U> {
        _resp: std::marker::PhantomData<U>,
    }

    impl<U: ProstMessage + Default> Decoder for ProstDecoder<U> {
        type Item = U;
        type Error = Status;

        fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
            // An empty response (e.g. PbX509SvidRequest {}) encodes to
            // zero bytes on the wire. Returning Ok(None) here makes
            // tonic's unary() client report "Missing response message"
            // (Internal) because it expects exactly one message. Match
            // tonic-prost's behavior: an empty buffer yields the
            // default value, not "no message".
            if !src.has_remaining() {
                return Ok(Some(U::default()));
            }
            let item =
                U::decode(src).map_err(|e| Status::internal(format!("prost decode error: {e}")))?;
            Ok(Some(item))
        }
    }

    // -----------------------------------------------------------------
    // The gRPC Workload API client.
    // -----------------------------------------------------------------

    /// The gRPC Workload API path for FetchX509SVID.
    const FETCH_X509_SVID_PATH: &str = "/spiffe.workloadapi.v2.WorkloadAPI/FetchX509SVID";

    /// The gRPC Workload API path for FetchX509Bundle.
    const FETCH_X509_BUNDLE_PATH: &str = "/spiffe.workloadapi.v2.WorkloadAPI/FetchX509Bundle";

    /// The gRPC Workload API transport. Connects to the SPIRE agent
    /// over a Unix domain socket and fetches X.509 SVIDs and the
    /// trust bundle via the `FetchX509SVID` RPC.
    #[derive(Clone)]
    pub struct GrpcWorkloadApi {
        socket_path: std::path::PathBuf,
    }

    impl std::fmt::Debug for GrpcWorkloadApi {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GrpcWorkloadApi")
                .field("socket_path", &self.socket_path)
                .finish()
        }
    }

    impl GrpcWorkloadApi {
        /// Build a new transport targeting the SPIRE Workload API at
        /// the given Unix socket path. The connection is established
        /// lazily on the first fetch (tonic's channel reconnects
        /// automatically on failure).
        pub fn new(socket_path: impl AsRef<Path>) -> Self {
            GrpcWorkloadApi {
                socket_path: socket_path.as_ref().to_path_buf(),
            }
        }

        /// Connect to the Unix socket and return a tonic channel. The
        /// Workload API is plaintext over the Unix socket (mTLS is not
        /// used on the Workload API itself — the SPIRE agent
        /// authenticates the workload via process attestation, not
        /// TLS). tonic supports Unix sockets via the `unix://` URI
        /// scheme.
        async fn connect(&self) -> Result<tonic::transport::Channel, SpiffeError> {
            let socket_path = self.socket_path.display().to_string();
            let channel = Endpoint::from_shared(format!("unix://{socket_path}"))
                .map_err(|e| SpiffeError::WorkloadApiUnreachable(e.to_string()))?
                .connect()
                .await
                .map_err(|e| SpiffeError::WorkloadApiUnreachable(e.to_string()))?;
            Ok(channel)
        }

        /// Parse the FetchX509SVID response into domain SVIDs.
        fn parse_svid_response(
            &self,
            resp: PbX509SvidResponse,
        ) -> Result<Vec<SpiffeSvid>, SpiffeError> {
            resp.svids
                .into_iter()
                .map(|pb| {
                    let spiffe_id = SpiffeIdentity::parse(&pb.spiffe_id).ok_or_else(|| {
                        SpiffeError::MalformedResponse(format!(
                            "invalid spiffe id in svid: {}",
                            pb.spiffe_id
                        ))
                    })?;
                    // The cert chain is a single DER blob containing
                    // the leaf + intermediates. Split on the DER
                    // sequence boundaries (a simple DER walk).
                    let x509_cert = split_der_chain(&pb.x509_svid);
                    if x509_cert.is_empty() {
                        return Err(SpiffeError::MalformedResponse(
                            "empty cert chain in svid".to_string(),
                        ));
                    }
                    Ok(SpiffeSvid {
                        spiffe_id,
                        x509_cert,
                        private_key: pb.x509_svid_key,
                        expires_at: pb.expires_at.max(0) as u64,
                    })
                })
                .collect()
        }

        /// Parse the FetchX509SVID response's bundles into a trust
        /// bundle for the first trust domain (the common case: one
        /// trust domain per workload).
        #[allow(dead_code)] // tested directly; used when FetchX509SVID
                            // returns both SVIDs and bundles in one call (the common path)
        fn parse_bundle_from_svid_response(
            &self,
            resp: &PbX509SvidResponse,
            trust_domain: &str,
        ) -> Result<SpiffeTrustBundle, SpiffeError> {
            let bundle = resp.bundles.get(trust_domain).ok_or_else(|| {
                SpiffeError::MalformedResponse(format!(
                    "trust bundle not found for trust domain: {trust_domain}"
                ))
            })?;
            Ok(SpiffeTrustBundle {
                trust_domain: bundle.trust_domain.clone(),
                x509_certs: bundle.x509_authorities.clone(),
            })
        }
    }

    /// Split a DER blob containing one or more concatenated DER
    /// certificates into individual DER blobs. Each DER certificate
    /// starts with a SEQUENCE tag (0x30) followed by a length. The
    /// walk reads the length to find the next certificate boundary.
    fn split_der_chain(der: &[u8]) -> Vec<Vec<u8>> {
        let mut certs = Vec::new();
        let mut offset = 0;
        while offset < der.len() {
            // A DER SEQUENCE starts with 0x30.
            if der[offset] != 0x30 {
                break;
            }
            // The length is encoded after the tag byte. Short form:
            // one byte (0x00-0x7F). Long form: first byte is 0x81-0x84
            // (number of length bytes follows).
            if offset + 1 >= der.len() {
                break;
            }
            let len_byte = der[offset + 1];
            let (len, header_len) = if len_byte < 0x80 {
                (len_byte as usize, 2)
            } else {
                let num_len_bytes = (len_byte & 0x7F) as usize;
                if num_len_bytes == 0 || num_len_bytes > 4 || offset + 2 + num_len_bytes > der.len()
                {
                    break;
                }
                let mut len = 0usize;
                for i in 0..num_len_bytes {
                    len = (len << 8) | der[offset + 2 + i] as usize;
                }
                (len, 2 + num_len_bytes)
            };
            let total = header_len + len;
            if offset + total > der.len() {
                break;
            }
            certs.push(der[offset..offset + total].to_vec());
            offset += total;
        }
        certs
    }

    #[async_trait]
    impl WorkloadApiTransport for GrpcWorkloadApi {
        async fn fetch_x509_svid(&self) -> Result<Vec<SpiffeSvid>, SpiffeError> {
            let channel = self.connect().await?;
            let codec = ProstCodec::<PbX509SvidRequest, PbX509SvidResponse>::new();
            let mut grpc = tonic::client::Grpc::new(channel);

            grpc.ready()
                .await
                .map_err(|e| SpiffeError::WorkloadApiUnreachable(e.to_string()))?;

            let request = Request::new(PbX509SvidRequest {});
            let path = http::uri::PathAndQuery::from_static(FETCH_X509_SVID_PATH);

            let response = grpc
                .unary(request, path, codec)
                .await
                .map_err(|e| SpiffeError::GrpcStatus(e.to_string()))?;

            self.parse_svid_response(response.into_inner())
        }

        async fn fetch_x509_bundle(&self) -> Result<SpiffeTrustBundle, SpiffeError> {
            // FetchX509SVID returns the bundles alongside the SVIDs;
            // we reuse that call and extract the bundle for the
            // configured trust domain. A dedicated FetchX509Bundle RPC
            // exists in the SPIRE API, but FetchX509SVID is the common
            // path (one round-trip for both SVID and bundle).
            let channel = self.connect().await?;
            let codec = ProstCodec::<PbX509BundleRequest, PbX509BundleResponse>::new();
            let mut grpc = tonic::client::Grpc::new(channel);

            grpc.ready()
                .await
                .map_err(|e| SpiffeError::WorkloadApiUnreachable(e.to_string()))?;

            let request = Request::new(PbX509BundleRequest {
                trust_domain: String::new(),
            });
            let path = http::uri::PathAndQuery::from_static(FETCH_X509_BUNDLE_PATH);

            let response = grpc
                .unary(request, path, codec)
                .await
                .map_err(|e| SpiffeError::GrpcStatus(e.to_string()))?;

            let resp = response.into_inner();
            let (_td, bundle) = resp
                .bundles
                .into_iter()
                .next()
                .ok_or(SpiffeError::EmptyResponse)?;
            Ok(SpiffeTrustBundle {
                trust_domain: bundle.trust_domain,
                x509_certs: bundle.x509_authorities,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn split_der_chain_empty() {
            assert!(split_der_chain(&[]).is_empty());
        }

        #[test]
        fn split_der_chain_single() {
            // A minimal DER SEQUENCE: tag 0x30, length 2, two bytes.
            let der = vec![0x30, 0x02, 0xAA, 0xBB];
            let certs = split_der_chain(&der);
            assert_eq!(certs.len(), 1);
            assert_eq!(certs[0], der);
        }

        #[test]
        fn split_der_chain_multiple() {
            // Two concatenated DER SEQUENCEs.
            let der = vec![0x30, 0x02, 0xAA, 0xBB, 0x30, 0x01, 0xCC];
            let certs = split_der_chain(&der);
            assert_eq!(certs.len(), 2);
            assert_eq!(certs[0], vec![0x30, 0x02, 0xAA, 0xBB]);
            assert_eq!(certs[1], vec![0x30, 0x01, 0xCC]);
        }

        #[test]
        fn split_der_chain_long_form_length() {
            // A DER SEQUENCE with long-form length (0x81 = 1 length byte).
            let mut der = vec![0x30, 0x81, 0x05];
            der.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
            let certs = split_der_chain(&der);
            assert_eq!(certs.len(), 1);
            assert_eq!(certs[0], der);
        }

        #[test]
        fn parse_svid_response_valid() {
            let transport = GrpcWorkloadApi::new("/tmp/test.sock");
            let resp = PbX509SvidResponse {
                svids: vec![PbX509Svid {
                    spiffe_id: "spiffe://example.org/ns/default/sa/my-svc".to_string(),
                    x509_svid: vec![0x30, 0x02, 0xAA, 0xBB],
                    x509_svid_key: vec![0x30, 0x02, 0xCC, 0xDD],
                    expires_at: 9999,
                }],
                bundles: std::collections::HashMap::new(),
            };
            let svids = transport.parse_svid_response(resp).expect("valid response");
            assert_eq!(svids.len(), 1);
            assert_eq!(svids[0].spiffe_id.trust_domain, "example.org");
            assert_eq!(svids[0].x509_cert.len(), 1);
            assert_eq!(svids[0].expires_at, 9999);
        }

        #[test]
        fn parse_svid_response_invalid_spiffe_id() {
            let transport = GrpcWorkloadApi::new("/tmp/test.sock");
            let resp = PbX509SvidResponse {
                svids: vec![PbX509Svid {
                    spiffe_id: "http://invalid".to_string(),
                    x509_svid: vec![0x30, 0x02, 0xAA, 0xBB],
                    x509_svid_key: vec![],
                    expires_at: 0,
                }],
                bundles: std::collections::HashMap::new(),
            };
            let err = transport
                .parse_svid_response(resp)
                .expect_err("should error");
            assert!(matches!(err, SpiffeError::MalformedResponse(_)));
        }

        #[test]
        fn parse_svid_response_empty_chain() {
            let transport = GrpcWorkloadApi::new("/tmp/test.sock");
            let resp = PbX509SvidResponse {
                svids: vec![PbX509Svid {
                    spiffe_id: "spiffe://example.org/x".to_string(),
                    x509_svid: vec![],
                    x509_svid_key: vec![],
                    expires_at: 0,
                }],
                bundles: std::collections::HashMap::new(),
            };
            let err = transport
                .parse_svid_response(resp)
                .expect_err("should error");
            assert!(matches!(err, SpiffeError::MalformedResponse(_)));
        }

        #[test]
        fn parse_bundle_from_svid_response_found() {
            let transport = GrpcWorkloadApi::new("/tmp/test.sock");
            let mut bundles = std::collections::HashMap::new();
            bundles.insert(
                "example.org".to_string(),
                PbX509Bundle {
                    trust_domain: "example.org".to_string(),
                    x509_authorities: vec![vec![0x30, 0x02, 0xAA, 0xBB]],
                },
            );
            let resp = PbX509SvidResponse {
                svids: vec![],
                bundles,
            };
            let bundle = transport
                .parse_bundle_from_svid_response(&resp, "example.org")
                .expect("found");
            assert_eq!(bundle.trust_domain, "example.org");
            assert_eq!(bundle.x509_certs.len(), 1);
        }

        #[test]
        fn parse_bundle_from_svid_response_not_found() {
            let transport = GrpcWorkloadApi::new("/tmp/test.sock");
            let resp = PbX509SvidResponse {
                svids: vec![],
                bundles: std::collections::HashMap::new(),
            };
            let err = transport
                .parse_bundle_from_svid_response(&resp, "missing.org")
                .expect_err("should error");
            assert!(matches!(err, SpiffeError::MalformedResponse(_)));
        }

        #[test]
        fn prost_codec_default() {
            // Verify the prost codec can be constructed.
            let _codec = ProstCodec::<PbX509SvidRequest, PbX509SvidResponse>::new();
        }
    }
}

// ---------------------------------------------------------------------------
// Test fake transport
// ---------------------------------------------------------------------------

/// A fake Workload API transport for tests. Returns preconfigured
/// SVIDs and trust bundles without opening a socket. Deterministic
/// (no real I/O, no timers).
#[derive(Clone)]
pub struct FakeWorkloadApi {
    svids: Vec<SpiffeSvid>,
    bundle: SpiffeTrustBundle,
    /// When Some, fetch_x509_svid returns this error instead of the
    /// preconfigured SVIDs. Used to test the error path.
    svid_error: Option<SpiffeError>,
    /// When Some, fetch_x509_bundle returns this error instead of the
    /// preconfigured bundle. Used to test the error path.
    bundle_error: Option<SpiffeError>,
}

impl std::fmt::Debug for FakeWorkloadApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeWorkloadApi")
            .field("svids", &self.svids.len())
            .field("bundle", &self.bundle.x509_certs.len())
            .field("svid_error", &self.svid_error.is_some())
            .field("bundle_error", &self.bundle_error.is_some())
            .finish()
    }
}

impl FakeWorkloadApi {
    /// Build a fake transport that returns the given SVIDs and bundle.
    pub fn new(svids: Vec<SpiffeSvid>, bundle: SpiffeTrustBundle) -> Self {
        FakeWorkloadApi {
            svids,
            bundle,
            svid_error: None,
            bundle_error: None,
        }
    }

    /// Make the SVID fetch return this error on the next call.
    pub fn with_svid_error(mut self, error: SpiffeError) -> Self {
        self.svid_error = Some(error);
        self
    }

    /// Make the bundle fetch return this error on the next call.
    pub fn with_bundle_error(mut self, error: SpiffeError) -> Self {
        self.bundle_error = Some(error);
        self
    }
}

#[async_trait::async_trait]
impl WorkloadApiTransport for FakeWorkloadApi {
    async fn fetch_x509_svid(&self) -> Result<Vec<SpiffeSvid>, SpiffeError> {
        if let Some(err) = &self.svid_error {
            return Err(err.clone());
        }
        Ok(self.svids.clone())
    }

    async fn fetch_x509_bundle(&self) -> Result<SpiffeTrustBundle, SpiffeError> {
        if let Some(err) = &self.bundle_error {
            return Err(err.clone());
        }
        Ok(self.bundle.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_svid(spiffe_id: &str, expires_at: u64) -> SpiffeSvid {
        SpiffeSvid {
            spiffe_id: SpiffeIdentity::parse(spiffe_id).expect("valid spiffe id"),
            x509_cert: vec![vec![0x30, 0x82]], // minimal DER prefix
            private_key: vec![0x30, 0x82],
            expires_at,
        }
    }

    fn fake_bundle() -> SpiffeTrustBundle {
        SpiffeTrustBundle {
            trust_domain: "example.org".into(),
            x509_certs: vec![vec![0x30, 0x82]],
        }
    }

    fn fake_config() -> SpiffeConfig {
        SpiffeConfig {
            trust_domain: "example.org".into(),
            workload_api_socket: PathBuf::from("/tmp/spire-agent/public/api.sock"),
            svid_refresh_interval: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn fetch_svid_returns_preconfigured_svids() {
        let svid = fake_svid("spiffe://example.org/ns/default/sa/my-svc", 9999);
        let transport =
            std::sync::Arc::new(FakeWorkloadApi::new(vec![svid.clone()], fake_bundle()));
        let client = SpiffeClient::new(fake_config(), transport);
        let svids = client.fetch_svid().await.expect("fetch");
        assert_eq!(svids.len(), 1);
        assert_eq!(svids[0].spiffe_id, svid.spiffe_id);
    }

    #[tokio::test]
    async fn fetch_primary_svid_returns_first_svid() {
        let svid1 = fake_svid("spiffe://example.org/ns/default/sa/svc1", 9999);
        let svid2 = fake_svid("spiffe://example.org/ns/default/sa/svc2", 8888);
        let transport = std::sync::Arc::new(FakeWorkloadApi::new(
            vec![svid1.clone(), svid2],
            fake_bundle(),
        ));
        let client = SpiffeClient::new(fake_config(), transport);
        let primary = client.fetch_primary_svid().await.expect("fetch");
        assert_eq!(primary.spiffe_id, svid1.spiffe_id);
    }

    #[tokio::test]
    async fn fetch_primary_svid_errors_on_empty_response() {
        let transport = std::sync::Arc::new(FakeWorkloadApi::new(vec![], fake_bundle()));
        let client = SpiffeClient::new(fake_config(), transport);
        let err = client.fetch_primary_svid().await.expect_err("should error");
        assert_eq!(err, SpiffeError::EmptyResponse);
    }

    #[tokio::test]
    async fn fetch_svid_propagates_transport_error() {
        let transport = std::sync::Arc::new(
            FakeWorkloadApi::new(vec![fake_svid("spiffe://example.org/x", 1)], fake_bundle())
                .with_svid_error(SpiffeError::WorkloadApiUnreachable(
                    "connection refused".into(),
                )),
        );
        let client = SpiffeClient::new(fake_config(), transport);
        let err = client.fetch_svid().await.expect_err("should error");
        assert!(matches!(err, SpiffeError::WorkloadApiUnreachable(_)));
    }

    #[tokio::test]
    async fn fetch_trust_bundle_returns_preconfigured_bundle() {
        let bundle = fake_bundle();
        let transport = std::sync::Arc::new(FakeWorkloadApi::new(
            vec![fake_svid("spiffe://example.org/x", 1)],
            bundle.clone(),
        ));
        let client = SpiffeClient::new(fake_config(), transport);
        let fetched = client.fetch_trust_bundle().await.expect("fetch");
        assert_eq!(fetched.trust_domain, bundle.trust_domain);
        assert_eq!(fetched.x509_certs.len(), bundle.x509_certs.len());
    }

    #[tokio::test]
    async fn fetch_trust_bundle_propagates_transport_error() {
        let transport = std::sync::Arc::new(
            FakeWorkloadApi::new(vec![fake_svid("spiffe://example.org/x", 1)], fake_bundle())
                .with_bundle_error(SpiffeError::GrpcStatus("permission denied".into())),
        );
        let client = SpiffeClient::new(fake_config(), transport);
        let err = client.fetch_trust_bundle().await.expect_err("should error");
        assert!(matches!(err, SpiffeError::GrpcStatus(_)));
    }

    #[test]
    fn refresh_result_from_fetch_success() {
        let transport = std::sync::Arc::new(FakeWorkloadApi::new(vec![], fake_bundle()));
        let client = SpiffeClient::new(fake_config(), transport);
        let ok: Result<SpiffeSvid, SpiffeError> = Ok(fake_svid("spiffe://example.org/x", 1));
        assert_eq!(
            client.refresh_result_from_fetch(&ok),
            SvidRefreshResult::Success
        );
    }

    #[test]
    fn refresh_result_from_fetch_error() {
        let transport = std::sync::Arc::new(FakeWorkloadApi::new(vec![], fake_bundle()));
        let client = SpiffeClient::new(fake_config(), transport);
        let err: Result<SpiffeSvid, SpiffeError> = Err(SpiffeError::EmptyResponse);
        assert_eq!(
            client.refresh_result_from_fetch(&err),
            SvidRefreshResult::Error
        );
    }

    #[test]
    fn spiffe_identity_parse_and_to_uri_roundtrip() {
        let id = SpiffeIdentity::parse("spiffe://example.org/ns/default/sa/my-svc").expect("valid");
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.path, "/ns/default/sa/my-svc");
        assert_eq!(id.to_uri(), "spiffe://example.org/ns/default/sa/my-svc");
    }

    #[test]
    fn spiffe_identity_parse_rejects_invalid() {
        assert!(SpiffeIdentity::parse("http://example.org/x").is_none());
        assert!(SpiffeIdentity::parse("spiffe:///x").is_none());
        assert!(SpiffeIdentity::parse("spiffe://").is_none());
    }

    #[test]
    fn spiffe_identity_new_normalizes_path() {
        let id = SpiffeIdentity::new("example.org", "ns/default/sa/x");
        assert_eq!(id.path, "/ns/default/sa/x");
    }

    #[test]
    fn spiffe_svid_seconds_until_expiry() {
        let svid = fake_svid("spiffe://example.org/x", 1000);
        assert_eq!(svid.seconds_until_expiry(900), 100);
        assert_eq!(svid.seconds_until_expiry(1000), 0);
        assert_eq!(svid.seconds_until_expiry(2000), 0); // clamped
    }
}
