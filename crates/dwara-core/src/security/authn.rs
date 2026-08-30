//! Request authentication (DW-019, feature analysis section 4.6; pepper
//! and mTLS hardening per #124; HMAC request signing per DW-036).
//!
//! Five credential families behind one [`Authenticator`] trait:
//!
//! - **API keys**: `X-API-Key: <key>`. The lookup SELECTOR is
//!   `hex(sha256(key))` — never the plaintext key — and the stored hash is
//!   `hmac-sha256:<hex(HMAC-SHA256(pepper, key))>` when the deployment
//!   configures a credential pepper (#124) or legacy
//!   `sha256:<hex(sha256(key))>` otherwise, verified with a
//!   constant-time comparison (`subtle`) in either case. Optional
//!   memory-hard verification: a credential whose stored hash is a PHC
//!   string (`$argon2id$...`, admin-supplied through the state store) is
//!   verified with argon2id. Trade-off (documented choice):
//!   sha256/HMAC+ct-compare is the pragmatic gateway standard — an
//!   argon2 verify is memory-hard and tens of milliseconds, far too slow
//!   for a per-request hot path, so config-declared keys are always
//!   fast-path hashed at seed time and argon2id is opt-in per credential.
//! - **Basic**: `Authorization: Basic base64(user:pass)`. The username is
//!   the selector (`hex(sha256(user))`, the same selector space as API
//!   keys) and the password is verified against the stored hash through
//!   the SAME hashing path as API keys (peppered when a pepper is
//!   configured). Basic credentials therefore live in the state store
//!   (config declares API keys, not username/password pairs); the
//!   resolved identity is reported with kind `api_key`. REQUIREMENT:
//!   store-managed Basic credentials must store argon2id PHC strings
//!   (`$argon2id$...`) — a human-chosen password hashed with plain
//!   unsalted sha256 is offline-dictionary bait (see the hardening notes
//!   below). Note also that usernames remain enumerable: the selector is
//!   a deterministic hash of the username with no secret input, so an
//!   attacker with the store can confirm username guesses offline.
//! - **JWT**: `Authorization: Bearer <token>`, verified per
//!   [`JwtProvider`][crate::config::JwtProvider] config: JWKS fetched from
//!   the provider's URL, cached, refreshed after `refresh_secs` (the
//!   refresh happens BEFORE a stale cached set is used, so retired issuer
//!   keys cannot keep verifying forever; a failed refresh degrades to the
//!   cached keys, and a RECENTLY failed refresh backs off for
//!   `min(5s, refresh_secs)` — subsequent stale lookups skip the fetch
//!   and answer from the cache immediately, so a down/slow endpoint
//!   cannot chain every Bearer request through a serialized 5s fetch
//!   timeout) AND on an unknown `kid` (rotation: a fresh key id
//!   appearing mid-flight triggers a re-fetch and the token then verifies
//!   — no restart, no failure). Refresh-triggered (unknown-kid) fetches
//!   are throttled to one per `min(5s, refresh_secs)` — forged random-kid
//!   tokens cannot drive a JWKS fetch storm. `iss`/`exp`/`nbf` are
//!   validated with `leeway_secs` skew tolerance, and `aud` is validated
//!   ONLY when the provider configures an audience (#124, maintainer
//!   decision): a provider without `audience` accepts tokens that carry
//!   any (or no) `aud` claim; the algorithm allowlist (default
//!   RS256/ES256) is enforced BEFORE any signature work (`none` and
//!   `HS*` are asymmetric-confusion bait and never allowed).
//! - **mTLS** (#124): the client certificate of the connection itself.
//!   On a TERMINATE listener with `client_ca_file` set, the TLS layer
//!   verifies any presented certificate against that bundle (rustls;
//!   an unverified certificate fails the handshake and never reaches
//!   authn) and the listener forwards the verified certificate here as a
//!   [`ClientCertificate`]. The credential record maps it to a consumer:
//!   an `mtls` credential's SELECTOR is its match value — the subject
//!   CommonName when the credential is configured `by subject`, or the
//!   certificate's SHA-256 fingerprint when `by fingerprint` — and a
//!   presented certificate matches when its subject CN or fingerprint
//!   equals that selector. Passthrough listeners never speak HTTP, and
//!   cleartext listeners have no certificates, so the family is inert
//!   there by construction.
//! - **HMAC request signing** (DW-036): a per-request signature over the
//!   request line, payload digest, timestamp, and nonce, presented in
//!   the `X-Dwara-*` header family — see the dedicated section below
//!   for the canonical-string contract (interop depends on it).
//!
//! Accepted formats (composite dispatch on request shape): `X-API-Key`
//! wins over `Authorization`; within `Authorization`, `Basic` and
//! `Bearer` are distinguished by the scheme token; a presented
//! `X-Dwara-Signature` engages the HMAC family after the
//! `Authorization` schemes; the client certificate is the AMBIENT
//! family — consulted only when NO header credential was presented (a
//! header expresses explicit intent and wins; the certificate is
//! connection-level context). A `Bearer` header with no JWT provider
//! stays pass-through (not interpreted), so such a request still falls
//! through to the HMAC headers and then the certificate family. A
//! gateway with NO consumers and NO JWT providers has authentication
//! disabled: the authenticator resolves `Anonymous` for everything and
//! `Authorization` is forwarded upstream untouched (pass-through mode).
//! Once ANY credential is configured, the gateway INTERPRETS
//! `Authorization` — except that `Bearer` stays pass-through unless a
//! JWT provider exists (a gateway fronting an OAuth-protected upstream
//! without its own JWT config must keep forwarding tokens).
//!
//! # HMAC request signing (DW-036)
//!
//! A consumer with an `hmac` credential (`key_id` + `secret`, the secret
//! inline or a `${...}` reference, DW-045) signs every request. The
//! secret never becomes a stored hash: recomputing an HMAC needs the
//! raw key bytes, so the RESOLVED secret lives only in this module's
//! in-memory key map (zeroized on drop) and the state store never sees
//! an `hmac` row. The pepper (#124) does not apply — it guards stored
//! hashes, and there is none.
//!
//! ## Wire format
//!
//! Five request headers, all REQUIRED when `X-Dwara-Signature` is
//! presented (any missing or malformed one is a 401, like any other
//! presented-but-invalid credential):
//!
//! | Header | Content |
//! |---|---|
//! | `X-Dwara-Key-Id` | the credential's `key_id` (public selector; 1..=128 visible-ASCII bytes) |
//! | `X-Dwara-Timestamp` | decimal Unix epoch seconds of signing (digits only) |
//! | `X-Dwara-Nonce` | opaque client string, 16..=256 visible-ASCII bytes, unique per request within the replay window (use >= 128 bits of entropy) |
//! | `X-Dwara-Body-Sha256` | lowercase hex SHA-256 of the request body (the empty body signs `e3b0c4...b855`, SHA-256 of the empty string) |
//! | `X-Dwara-Signature` | lowercase hex HMAC-SHA256(secret, canonical string) |
//!
//! The custom `X-Dwara-*` family (not an `Authorization` scheme)
//! follows the codebase's `X-API-Key` precedent: discrete headers make
//! each signed element explicit and keep the signature material
//! inspectable without parsing a parameterized scheme. Like the other
//! credential headers they are forwarded upstream untouched (only
//! `X-Consumer-*` are stripped).
//!
//! ## Canonical string (v1) — the interop contract
//!
//! A version line followed by the seven signed elements, each pair
//! joined by exactly one `\n` byte (no trailing newline). No element
//! may itself contain `\n` — the
//! grammar guarantees it (visible ASCII excludes control characters,
//! the timestamp is digits, the digest is hex, and hyper's parser
//! rejects raw control bytes in a request target):
//!
//! ```text
//! dwara-hmac-v1
//! <key id>            the X-Dwara-Key-Id value, exactly as presented
//! <method>            the HTTP method, uppercased (GET, POST, ...)
//! <path>              the request path EXACTLY as received: percent-encoding preserved, no normalization
//! <query>             the raw query string as received (no leading '?'), or an EMPTY line when absent
//! <timestamp>         the X-Dwara-Timestamp value, exactly as presented
//! <nonce>             the X-Dwara-Nonce value, exactly as presented
//! <body digest>       the X-Dwara-Body-Sha256 value, exactly as presented
//! ```
//!
//! Design decisions, each load-bearing:
//!
//! - **Path/query exactly as received.** The signer cannot know what
//!   normalization a proxy chain might apply, so the only lossless
//!   contract is the raw bytes the client put on the wire; the gateway
//!   re-reads them from its parsed (but un-normalized) request target.
//!   Query ORDER is signed: `?a=1&b=2` and `?b=2&a=1` are different
//!   canonical strings.
//! - **Body by digest, carried in a signed header.** Signing the body
//!   inline would require buffering it (the gateway hashes nothing
//!   until it streams); the digest header lets the gateway verify the
//!   MAC over headers only and then enforce the digest while STREAMING
//!   the body to the upstream — zero buffering, any body size, and the
//!   stream is aborted (401 to the client, truncated request to the
//!   upstream) the moment the final byte's hash disagrees. A tampered
//!   body therefore never completes upstream. The route's
//!   `max_body_bytes` (DW-027) composes with this: the digesting
//!   wrapper sits inside the route's limit wrapper, so an over-cap
//!   body is still rejected 413 first.
//! - **No other headers in v1.** The signed set binds the request
//!   line (method/path/query), the payload (digest), freshness
//!   (timestamp), uniqueness (nonce), and identity (key id). The
//!   `Host` header is NOT signed: it is a routing input, so a party
//!   able to tamper headers between signer and gateway (a non-TLS
//!   listener or an untrusted proxy hop) could retarget a validly
//!   signed request to a different host-matched route while MAC and
//!   digest still verify — TLS termination makes that party mostly
//!   hypothetical, and the gateway rebuilds Host from the upstream
//!   pick, so no cross-host forwarding occurs. `Content-Type` and
//!   friends are not authn inputs here, and signing arbitrary header
//!   lists drags in header-selection and canonicalization ambiguity
//!   every signer must replicate exactly. The versioned first line
//!   leaves room for a v2 with opt-in header (including Host)
//!   coverage without breaking v1 signers.
//!
//! ## Verification order and failure posture
//!
//! 1. Header presence/format parse (401 on any malformed element).
//! 2. Timestamp inside `±max_clock_skew_secs` (default 300s, the §4.6
//!    recommendation; gateway `hmac_auth` block, validated 1..=3600).
//!    Checked BEFORE any HMAC work — an expired window is not a MAC
//!    problem, and refusing early keeps the hot path cheap for
//!    stale traffic. Outside the window: 401.
//! 3. Key lookup, then `HMAC-SHA256(secret, canonical)` compared to
//!    the presented signature with `subtle::ConstantTimeEq` over the
//!    full 32-byte digests — no early return on a byte mismatch. A
//!    key-miss computes a dummy HMAC first (fixed zero key) so the
//!    timing shape of "unknown key" matches "wrong signature" and
//!    key-existence is not readable from latency; both answer the
//!    same 401 shape as every other family.
//! 4. Nonce replay check, AFTER a successful MAC: the nonce is
//!    remembered under `key_id + '\n' + nonce` for twice the skew
//!    window (a timestamp stays acceptable for at most one full
//!    window after its request was first seen, so the doubled TTL
//!    covers the boundary with margin). A remembered nonce inside
//!    its TTL: 401. Burned only on VALID signatures — junk traffic
//!    cannot flood legitimate nonces out of the cache.
//!
//! ## Replay window boundary (single instance, M2)
//!
//! The nonce cache is in-memory, sharded (`NONCE_CACHE_SHARDS` locks,
//! the GCRA store's pattern), TTL-expired, and capped at
//! [`crate::config::limits::MAX_NONCE_CACHE_ENTRIES_PER_SHARD`]
//! entries per shard with soonest-expiry-first eviction — under a
//! nonce flood the cache degrades fail-open to eviction (the
//! documented GCRA trade: an availability DoS must not become a
//! gateway outage), and replay protection is only as strong as the
//! cache's retention. It is also PER-INSTANCE: dwara M2 is a
//! single-process deployment, and a multi-instance fleet behind one
//! VIP would let a replayed request hit a cold instance. A shared
//! nonce store is the enterprise/Redis seam (DW-031's world), not
//! this module's; the boundary is documented here so operators do not
//! mistake per-instance replay protection for fleet-wide.
//!
//! Identity-to-consumer mapping: API keys and Basic map via the credential
//! record; JWTs map via the provider's `consumer` binding, or by matching
//! a consumer's `jwt` credential `issuer` (with audience containment when
//! the credential lists audiences) against the token's `iss`; client
//! certificates map via the `mtls` credential match value. Every resolved
//! identity carries the consumer's GROUPS (config consumers from the
//! config record, store-managed consumers from the store's
//! `consumers.groups`, #124) so group-based authorization applies
//! uniformly.
//!
//! Consumer-identity headers (spoof prevention): the proxy strips every
//! client-supplied `X-Consumer-*` header and injects a trusted
//! `X-Consumer-Name` upstream when authentication resolved a consumer —
//! see `proxy` (the strip/inject lives on the forward path).
//!
//! # Hardening notes (residual risks and the road to closing them)
//!
//! The stored-hash fast path is UNSALTED sha256 when no pepper is
//! configured, and the selector is always unsalted sha256 of the
//! presented material. That is deliberate for machine-generated config
//! keys (constant-time, index-friendly, and a search over the stored
//! hashes is not a dictionary attack when the key is 256 bits of
//! entropy), but it leaves a residual offline-dictionary risk for WEAK
//! secrets: an attacker who exfiltrates the store can brute-force
//! low-entropy keys or passwords against the unsalted selectors/hashes
//! at sha256 speed, offline, and confirm username guesses via the
//! deterministic Basic selector. Mitigations in place: the DB file is
//! mode 0600, hashes/selectors are redacted from `Debug`, store-managed
//! credentials may use argon2id PHC strings (REQUIRED for Basic
//! passwords), and — #124 — a per-deployment PEPPER turns every NEW
//! stored hash into `hmac-sha256:<hex>` so a DB leak alone cannot verify
//! guesses (the search also needs the pepper, held outside the DB).
//! The pepper is resolved through the `SecretSource` extension seam
//! ABOVE this domain (the binary resolves it and threads raw bytes
//! down; `security` must not import `extensions`), is never logged,
//! never appears in `Debug` output, and never appears in error text.
//! Transition semantics: legacy `sha256:<hex>` entries keep verifying;
//! on SUCCESSFUL legacy verification with a pepper configured, the
//! store row is re-hashed to the peppered format in place (no
//! credential re-issue needed); `hmac-sha256:` entries with NO pepper
//! configured fail closed (legacy-only mode) with a clear log line.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::hash::BuildHasher;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use hyper::header::HeaderMap;
use hyper::{Method, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use rustls::pki_types::CertificateDer;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tower_service::Service;
use zeroize::Zeroizing;

use crate::config::credentials::{
    credential_selector, hmac_stored_hash, sha256_hex, sha256_stored_hash,
};
use crate::config::{
    Credential, Gateway, JwtProvider as JwtProviderConfig, DEFAULT_HMAC_CLOCK_SKEW_SECS,
};
use crate::observability::Observability;
use crate::state::store::{CredentialKind, CredentialRecord, StateStore};

const X_API_KEY: hyper::header::HeaderName = hyper::header::HeaderName::from_static("x-api-key");

/// Upper bound on a JWKS response body (1 MiB): a key set is a few KiB;
/// anything larger is a misbehaving or hostile endpoint.
const JWKS_BODY_CAP: u64 = 1024 * 1024;

/// Connect timeout for JWKS fetches: key refresh is on the request path
/// (first token / rotation), so it must fail fast rather than hang a
/// client request for minutes.
const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The resolved caller identity of one request. `None` (from
/// [`Authenticator::authenticate`]) is Anonymous — no credential family
/// applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub consumer_name: String,
    pub credential_kind: CredentialKind,
    /// Group memberships of the authenticated consumer (#124): from the
    /// CONFIG consumer record when the consumer is config-declared, from
    /// the state store's `consumers.groups` for store-managed consumers.
    /// Consumed by group-based authorization (`allowed_groups` /
    /// `denied_groups` at any attachment level).
    pub groups: Vec<String>,
    /// JWT only: a subset of the token's claims (string- and
    /// number-valued top-level claims, plus arrays of strings flattened
    /// to their space-separated form — the OAuth `scope` convention,
    /// DW-020 — capped at 32 entries). Never contains the raw token.
    pub claims: BTreeMap<String, String>,
    /// HMAC only (DW-036): the signed body digest (the decoded
    /// `X-Dwara-Body-Sha256` value) the FORWARD path must enforce while
    /// streaming the request body to the upstream — the MAC was verified
    /// over this digest at authn time; the dataplane's digesting wrapper
    /// (`dataplane::hardening`) compares the streamed body's SHA-256
    /// against it and aborts the request on mismatch (see the module
    /// docs' canonical-string section). Not secret: it is a public hash
    /// that already traveled in a header. Every other family sets `None`.
    pub body_digest: Option<[u8; 32]>,
}

/// The VERIFIED client certificate of a connection, as the authenticator
/// consumes it (#124). Built by the TLS frontend from the certificate
/// rustls already verified against the listener's `client_ca_file`; the
/// match VALUES (subject CN, fingerprint) double as credential selectors,
/// so `Debug` redacts them (the selector-redaction precedent).
#[derive(Clone)]
pub struct ClientCertificate {
    /// Subject CommonName of the verified leaf certificate (first CN in
    /// the subject RDN sequence; `None` when the subject carries no
    /// decodable CN — such a certificate can only match a
    /// by-fingerprint credential).
    pub(crate) subject_cn: Option<String>,
    /// Lowercase hex of SHA-256 over the certificate DER.
    pub(crate) fingerprint: String,
}

impl ClientCertificate {
    /// Extract the match values of a verified leaf certificate. Never
    /// fails: an undecodable subject yields `subject_cn: None` and the
    /// credential lookup falls back to the fingerprint selector alone.
    pub fn from_cert(cert: &CertificateDer<'_>) -> Self {
        ClientCertificate {
            subject_cn: crate::security::tls::subject_cn_of_leaf(cert),
            fingerprint: sha256_hex(cert.as_ref()),
        }
    }
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Match values are credential selectors: redacted (an accidental
        // Debug print must not leak lookup keys).
        write!(f, "ClientCertificate([match values redacted])")
    }
}

/// Authentication failure. `Invalid` is a caller-side problem (401);
/// `Unavailable` is a gateway-side problem (500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Invalid(&'static str),
    Unavailable(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Invalid(m) => write!(f, "invalid credentials: {m}"),
            AuthError::Unavailable(m) => write!(f, "authentication unavailable: {m}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The request material an [`Authenticator`] may consume (DW-036):
/// headers plus the request TARGET — method, path, query — the HMAC
/// family signs. Borrowed for one authenticate call; the request body
/// is deliberately NOT here (authn never buffers; the HMAC body digest
/// is enforced on the forward path, see [`Identity::body_digest`]).
#[derive(Debug, Clone, Copy)]
pub struct AuthnRequest<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub headers: &'a HeaderMap,
    /// The VERIFIED client certificate of the connection when the
    /// accepting TLS listener requested one (#124) — absent on
    /// cleartext listeners and connections that presented none.
    pub client_cert: Option<&'a ClientCertificate>,
}

/// One pluggable authenticator (dyn-compatible seam). `Ok(None)` is
/// Anonymous; `Err(AuthError::Invalid(..))` means a credential was
/// PRESENTED and rejected.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, req: &AuthnRequest<'_>) -> Result<Option<Identity>, AuthError>;

    /// The `WWW-Authenticate` challenge value for 401 responses, built
    /// from the schemes this authenticator actually interprets. Client
    /// certificates are deliberately NOT challenged here: TLS-level
    /// client-auth has no WWW-Authenticate representation.
    fn challenge(&self) -> String;
}

// --- hashing ---------------------------------------------------------------
//
// The selector/stored-hash FORMATS live in `config::credentials` (part of
// the credential schema contract shared with the state store); this
// module re-imports them and owns the VERIFICATION path below.

/// The per-deployment credential pepper as this module consumes it: raw
/// bytes handed down from ABOVE the security domain (the binary resolves
/// it through the `SecretSource` extension seam; `security` must not
/// import `extensions`). SECRET material: never logged, never in
/// `Debug`, never in error text.
type Pepper = [u8];

/// Verify a presented secret against a stored hash, in constant time for
/// the fast paths (`subtle::ConstantTimeEq` over the encoded digests —
/// comparing hex strings byte-wise is length-equal and timing-uniform).
/// Supported formats: `hmac-sha256:<hex>` (#124; verified ONLY when a
/// `pepper` is configured — a missing pepper fails closed for peppered
/// entries), legacy `sha256:<hex>` (always verified, pepper or not: the
/// transition keeps old rows valid), and PHC argon2id strings
/// (`$argon2id$...`, pepper-independent). Unknown formats verify false
/// (never accept).
///
/// Public for testing the stored-hash verification contract.
pub fn verify_secret(stored_hash: &str, presented: &str, pepper: Option<&Pepper>) -> bool {
    if let Some(hexdigest) = stored_hash.strip_prefix("hmac-sha256:") {
        // Peppered entries fail closed without a pepper (legacy-only
        // mode): the gateway cannot verify what it lacks the key for.
        let Some(pepper) = pepper else {
            return false;
        };
        if hexdigest.len() != 64 || !hexdigest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        // Same total length as `stored_hash` (12 + 64 bytes), so the
        // full-encoding comparison below is length-matched and
        // timing-uniform like the sha256 path.
        let computed = hmac_stored_hash(pepper, presented);
        return computed.as_bytes().ct_eq(stored_hash.as_bytes()).into();
    }
    if let Some(hexdigest) = stored_hash.strip_prefix("sha256:") {
        if hexdigest.len() != 64 || !hexdigest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        let computed = sha256_hex(presented.as_bytes());
        // Compare the ASCII encodings: both are fixed 64-byte buffers of
        // hex digits, so ct_eq is well-defined and length-matched.
        return computed.as_bytes().ct_eq(hexdigest.as_bytes()).into();
    }
    if stored_hash.starts_with("$argon2") {
        let parsed = argon2::PasswordHash::new(stored_hash);
        let Ok(parsed) = parsed else { return false };
        let alg = argon2::Argon2::default();
        use argon2::PasswordVerifier as _;
        return alg.verify_password(presented.as_bytes(), &parsed).is_ok();
    }
    false
}

// --- HMAC request signing (DW-036) -----------------------------------------

/// The `X-Dwara-*` header family (DW-036). See the module docs for the
/// canonical-string contract; these consts are the single source of the
/// header names so the verifier and the challenge cannot drift.
pub const X_DWARA_SIGNATURE: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-dwara-signature");
pub const X_DWARA_KEY_ID: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-dwara-key-id");
pub const X_DWARA_TIMESTAMP: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-dwara-timestamp");
pub const X_DWARA_NONCE: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-dwara-nonce");
pub const X_DWARA_BODY_SHA256: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-dwara-body-sha256");

/// Version tag opening the canonical string (see the module docs). Bumped
/// only for an incompatible grammar change; v1 signers keep verifying.
const CANONICAL_VERSION_LINE: &str = "dwara-hmac-v1";

/// The `WWW-Authenticate` scheme token the HMAC family offers (a custom
/// token per RFC 9110's scheme grammar; the family is presented through
/// headers, but the challenge still needs a name clients can recognize).
/// `pub(crate)`: the dataplane's mid-stream digest-mismatch 401 (the one
/// HMAC-originated failure the proxy itself answers) reuses the same
/// token so both 401 shapes carry an identical challenge.
pub(crate) const HMAC_CHALLENGE: &str = "Dwara-HMAC-SHA256 realm=\"dwara\"";

/// Bounds on the PRESENTED credential material (401 on violation). The
/// key id is a public label; the nonce must carry real entropy — 16
/// bytes is the floor for a random nonce, 256 keeps the nonce-cache key
/// and the canonical string cheap under hostile headers.
const MAX_KEY_ID_BYTES: usize = 128;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 256;

/// `true` for the visible-ASCII range a presented header value may carry
/// without control characters (`\n` exclusion keeps the canonical string
/// line grammar unambiguous; the space is excluded too — header values
/// here are opaque tokens, and hyper trims leading/trailing spaces a
/// signer cannot re-derive byte-for-byte).
fn is_visible_ascii(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// Decode exactly 32 bytes from a 64-character hex string (the signature
/// and body-digest header values). Case-insensitive on input — the spec
/// says signers emit lowercase, but accepting upper-case hex costs
/// nothing and rejects nothing the MAC would have accepted.
fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Build the canonical string (DW-036 v1). The elements are the
/// PRESENTED header values and the request target EXACTLY as received —
/// the signer's bytes and the verifier's bytes must agree without any
/// normalization step (see the module docs for the grammar and the
/// rationale). Public because the grammar is the interop contract:
/// tests re-implement it independently to pin the documentation, and
/// operators may build signing tooling against the same function the
/// gateway verifies with.
pub fn canonical_string(
    key_id: &str,
    method: &Method,
    path: &str,
    query: Option<&str>,
    timestamp: &str,
    nonce: &str,
    body_sha256_hex: &str,
) -> String {
    // Methods are already uppercase on the wire (hyper parses them as
    // sent); uppercasing again is the explicit grammar guarantee for
    // signers behind a case-mangling chain.
    let method = method.as_str().to_ascii_uppercase();
    let mut out = String::with_capacity(
        CANONICAL_VERSION_LINE.len()
            + key_id.len()
            + method.len()
            + path.len()
            + query.map_or(0, str::len)
            + timestamp.len()
            + nonce.len()
            + body_sha256_hex.len()
            + 7,
    );
    out.push_str(CANONICAL_VERSION_LINE);
    for element in [
        key_id,
        method.as_str(),
        path,
        query.unwrap_or(""),
        timestamp,
        nonce,
        body_sha256_hex,
    ] {
        out.push('\n');
        out.push_str(element);
    }
    out
}

/// Compute HMAC-SHA256 over the canonical string. Shared by the verify
/// path and the key-miss dummy (timing uniformity; see
/// [`CompositeAuthenticator::authenticate_hmac`]).
fn request_mac(secret: &[u8], canonical: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Number of independent shard locks in the nonce cache. Fixed (not
/// CPU-count-derived) so the worst-case entry bound
/// (`NONCE_CACHE_SHARDS * MAX_NONCE_CACHE_ENTRIES_PER_SHARD`) is the
/// same number on every machine — the GCRA store's rationale.
pub const NONCE_CACHE_SHARDS: usize = 16;

/// One HMAC signing key as the authenticator holds it (DW-036). The
/// secret is the RESOLVED config value (inline or `${...}` reference,
/// resolved at build time): raw key bytes, never a hash, never logged,
/// zeroized when the last holder drops. Manual `Debug` redacts it.
pub struct HmacCredential {
    pub consumer_name: String,
    secret: Arc<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for HmacCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacCredential")
            .field("consumer_name", &self.consumer_name)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Per-instance replay-nonce store (DW-036): sharded keyed TTL map, the
/// GCRA shard store's shape (`GcraShardStore`). [`Self::check_and_insert`]
/// is the single critical section — one shard lock covers the
/// expired-read and the insert, so two concurrent presentations of one
/// nonce linearize (exactly one wins). Entries expire after the
/// caller-supplied TTL (twice the clock-skew window, set per insert so a
/// skew change on reload applies to new nonces without rebuilding the
/// cache); a shard at
/// [`crate::config::limits::MAX_NONCE_CACHE_ENTRIES_PER_SHARD`] entries
/// first drops expired entries, then evicts soonest-expiry-first (the
/// documented fail-open-under-flood trade; see the module docs).
pub struct NonceCache {
    shards: Vec<std::sync::Mutex<HashMap<String, Instant>>>,
    hasher: std::collections::hash_map::RandomState,
    /// Per-shard entry cap (see [`Self::with_shard_capacity`]).
    cap: usize,
}

impl NonceCache {
    /// The production cache: [`NONCE_CACHE_SHARDS`] shards, each capped
    /// at [`crate::config::limits::MAX_NONCE_CACHE_ENTRIES_PER_SHARD`].
    pub fn new() -> Self {
        Self::with_shard_capacity(crate::config::limits::MAX_NONCE_CACHE_ENTRIES_PER_SHARD)
    }

    /// Test constructor with a small per-shard cap (exercises the
    /// eviction cascade without inserting thousands of keys).
    pub fn with_shard_capacity(cap: usize) -> Self {
        NonceCache {
            shards: (0..NONCE_CACHE_SHARDS)
                .map(|_| std::sync::Mutex::new(HashMap::new()))
                .collect(),
            hasher: std::collections::hash_map::RandomState::new(),
            cap,
        }
    }

    fn shard_for(&self, key: &str) -> &std::sync::Mutex<HashMap<String, Instant>> {
        &self.shards[(self.hasher.hash_one(key) as usize) & (NONCE_CACHE_SHARDS - 1)]
    }

    /// Remember `key` for `ttl` and report whether it was FRESH (not
    /// remembered, or remembered-but-expired): `true` = this caller is
    /// the first presentation inside the window; `false` = replay.
    pub fn check_and_insert(&self, key: &str, ttl: Duration) -> bool {
        let now = Instant::now();
        let expires = now + ttl;
        let shard = self.shard_for(key);
        let mut guard = shard.lock().expect("nonce cache shard poisoned");
        match guard.get(key) {
            Some(&seen_expiry) if seen_expiry > now => false,
            _ => {
                // Expired-or-absent: same path. Sweep only when crowded
                // (the inline cascade; see the module docs) so the
                // common case is one hash lookup plus one insert.
                if guard.len() >= self.cap {
                    guard.retain(|_, expiry| *expiry > now);
                    while guard.len() >= self.cap {
                        // Soonest-expiry-first: the entries closest to
                        // leaving the window cost the least protection
                        // to drop.
                        let victim = guard
                            .iter()
                            .min_by_key(|(_, expiry)| **expiry)
                            .map(|(k, _)| k.clone());
                        match victim {
                            Some(k) => {
                                guard.remove(&k);
                            }
                            None => break,
                        }
                    }
                }
                guard.insert(key.to_string(), expires);
                true
            }
        }
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NonceCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceCache")
            .field("shards", &NONCE_CACHE_SHARDS)
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

// --- credential registry ---------------------------------------------------

/// One verifiable credential as the authenticator sees it.
///
/// Manual `Debug`: `hash` and `selector` are credential material (the
/// selector is the lookup key — for `mtls` rows the match value itself —
/// and the hash embeds a binding marker or a peppered digest), so both
/// are redacted, matching the store's `CredentialRecord` precedent.
#[derive(Clone)]
pub struct KnownCredential {
    pub consumer_name: String,
    pub kind: CredentialKind,
    pub hash: String,
    /// Scheduled retirement instant (DW-046, epoch seconds): the
    /// credential stops verifying once this passes. The STORE lookup
    /// filters retired rows in SQL; this field exists for the CACHED
    /// list, which was filled before the boundary and must go stale
    /// exactly on time — the registry lookup below re-checks it.
    pub retire_at: Option<i64>,
    /// Store row id when the credential came from the state store (used
    /// by the #124 pepper transition to re-hash a legacy-verified row in
    /// place); `None` for config-seeded credentials.
    pub id: Option<i64>,
    /// The selector this credential was found under (the credential's
    /// lookup key — its own match value for `mtls` bindings).
    pub selector: String,
}

impl std::fmt::Debug for KnownCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownCredential")
            .field("consumer_name", &self.consumer_name)
            .field("kind", &self.kind)
            .field("hash", &"[redacted]")
            .field("retire_at", &self.retire_at)
            .field("id", &self.id)
            .field("selector", &"[redacted]")
            .finish()
    }
}

impl From<&CredentialRecord> for KnownCredential {
    fn from(r: &CredentialRecord) -> Self {
        KnownCredential {
            consumer_name: r.consumer_name.clone(),
            kind: r.kind,
            hash: r.hash.clone(),
            retire_at: r.retire_at,
            id: Some(r.id),
            selector: r.selector.clone(),
        }
    }
}

/// Where credential records come from: the state store (hot-cached; the
/// `DWARA_STATE_DB` deployment) or config consumers hashed in-memory at
/// startup. Both paths unify behind one lookup API (a private
/// selector-keyed search shared by the API-key, Basic, and mTLS paths).
pub enum CredentialRegistry {
    Store(Arc<StateStore>),
    Config(HashMap<String, Arc<Vec<KnownCredential>>>),
}

impl CredentialRegistry {
    /// Build the config-only registry: every consumer's API-key credential
    /// is hashed at startup (the config value is then dropped; the
    /// registry holds only selectors and hashes) — with the PEPPERED
    /// format when a pepper is configured (#124), the legacy sha256
    /// format otherwise. `${...}` secret references (DW-045) are
    /// resolved HERE, at build time, and the RESOLVED bytes hashed; the
    /// plaintext never outlives the call. `mtls` credentials are indexed
    /// by their match value (subject CN or fingerprint). JWT credentials
    /// are bindings consumed via the composite's issuer index, not this
    /// map.
    pub fn from_config(gateway: &Gateway, pepper: Option<&Pepper>) -> Self {
        let mut map: HashMap<String, Arc<Vec<KnownCredential>>> = HashMap::new();
        for consumer in &gateway.consumers {
            for credential in &consumer.credentials {
                let (kind, selector, hash) = match credential {
                    Credential::ApiKey { key } => {
                        if key.is_empty() {
                            continue;
                        }
                        // DW-045: the config value may be a ${...} reference
                        // (env/file); resolve it and hash the RESOLVED bytes.
                        // Validation already rejected unresolvable references
                        // for this generation, so an error here is the
                        // validate-vs-build microsecond race — fail CLOSED
                        // (skip the credential: that key stops authenticating)
                        // and say so loudly, never echoing the value. The
                        // next successful publish re-resolves.
                        let key = match crate::config::credentials::resolve_configured_secret(key) {
                            Ok(resolved) => resolved,
                            Err(err) => {
                                tracing::error!(
                                    code = "config_api_key_unresolvable",
                                    consumer = %consumer.name,
                                    "skipping api key credential (secret reference \
                                     unresolvable at authenticator build): {err}"
                                );
                                continue;
                            }
                        };
                        let hash = match pepper {
                            Some(pepper) => hmac_stored_hash(pepper, &key),
                            None => sha256_stored_hash(&key),
                        };
                        (CredentialKind::ApiKey, credential_selector(&key), hash)
                    }
                    Credential::Mtls {
                        subject,
                        fingerprint,
                    } => {
                        let match_value = subject
                            .clone()
                            .or_else(|| fingerprint.clone())
                            .unwrap_or_default();
                        if match_value.is_empty() {
                            continue;
                        }
                        (
                            CredentialKind::Mtls,
                            match_value.clone(),
                            format!("config:mtls:{match_value}"),
                        )
                    }
                    // JWT credentials resolve through jwt_consumer_index.
                    Credential::Jwt { .. } => continue,
                    // HMAC credentials (DW-036) live in the composite's
                    // hmac_keys map (raw key material, config-served
                    // only), not this hash-keyed registry.
                    Credential::Hmac { .. } => continue,
                };
                let entry = Arc::make_mut(map.entry(selector.clone()).or_default());
                entry.push(KnownCredential {
                    consumer_name: consumer.name.clone(),
                    kind,
                    hash,
                    retire_at: None,
                    id: None,
                    selector,
                });
            }
        }
        CredentialRegistry::Config(map)
    }

    /// Look up the active credentials for a selector (hash of the
    /// presented material — never plaintext — or an mTLS match value).
    async fn lookup(&self, selector: &str) -> Result<Vec<KnownCredential>, AuthError> {
        // DW-046: the dual-validity window's far edge is enforced HERE
        // (in addition to the store's SQL filter) so a CACHED list
        // filled before a scheduled retirement stops serving the row
        // exactly on time, with no background sweeper.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(i64::MAX);
        let retired = |c: &KnownCredential| c.retire_at.is_some_and(|t| t <= now);
        match self {
            CredentialRegistry::Store(store) => {
                let entry = store
                    .lookup_credential(selector)
                    .map_err(|e| AuthError::Unavailable(e.to_string()))?;
                let entry = entry.unwrap_or_default();
                Ok(entry
                    .iter()
                    .map(|r| KnownCredential::from(r.as_ref()))
                    .filter(|c| !retired(c))
                    .collect())
            }
            CredentialRegistry::Config(map) => Ok(map
                .get(selector)
                .map(|v| v.as_ref().clone())
                .unwrap_or_default()
                .into_iter()
                .filter(|c| !retired(c))
                .collect()),
        }
    }
}

// --- JWKS fetching ---------------------------------------------------------

/// A connection that is either plaintext TCP or TLS: the single response
/// type of [`JwksConnector`] for `http://` and `https://` JWKS URLs.
/// `WithHyperIo` adapts a tokio stream to BOTH hyper's runtime IO traits
/// and tokio's, which is exactly what the tokio-rustls 0.26 connect bound
/// and the hyper legacy client's pool each ask for.
enum MaybeTls {
    Plain(hyper_util::rt::tokio::WithHyperIo<tokio::net::TcpStream>),
    Tls(
        Box<
            tokio_rustls::client::TlsStream<
                hyper_util::rt::tokio::WithHyperIo<tokio::net::TcpStream>,
            >,
        >,
    ),
}

impl tokio::io::AsyncRead for MaybeTls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeTls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTls::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for MaybeTls {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

/// Plain-or-TLS connector for one-shot JWKS GETs (hyper-util legacy
/// client plumbing; reuses the workspace rustls stack, no new HTTP
/// dependency). Trust defaults to the webpki public roots; a provider's
/// `trusted_ca_file` (#121) replaces them so an https JWKS endpoint
/// behind a private CA is fetchable — the same trust model the upstream
/// connector gives `trusted_ca_file` upstreams.
#[derive(Clone)]
struct JwksConnector {
    http: hyper_util::client::legacy::connect::HttpConnector,
    tls: tokio_rustls::TlsConnector,
}

impl JwksConnector {
    /// `trusted_ca` is the provider's `trusted_ca_file` path when set.
    /// Fails when the bundle cannot be loaded/parsed, so the provider is
    /// disabled at build time (see `CompositeAuthenticator::build`)
    /// instead of failing every fetch at request time.
    fn new(trusted_ca: Option<&str>) -> Result<Self, AuthError> {
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.enforce_http(false); // scheme routing happens here
        let roots = match trusted_ca {
            Some(path) => crate::security::tls::root_store_from_pem_file(path).map_err(|e| {
                AuthError::Unavailable(format!("trusted_ca_file '{path}' could not be loaded: {e}"))
            })?,
            None => crate::security::tls::webpki_root_store(),
        };
        let cfg = crate::security::tls::https_h1_client_config(roots);
        Ok(JwksConnector {
            http,
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
        })
    }
}

impl Service<Uri> for JwksConnector {
    type Response = hyper_util::rt::TokioIo<MaybeTls>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(std::io::Error::other)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| std::io::Error::other("jwks url has no host"))?
                .to_string();
            let stream = tokio::time::timeout(JWKS_CONNECT_TIMEOUT, http.call(uri.clone()))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "jwks connect timed out")
                })?
                .map_err(std::io::Error::other)?
                // The HttpConnector hands back a TokioIo<TcpStream>; unwrap to
                // the raw stream and re-adapt with WithHyperIo (which satisfies
                // BOTH tokio's and hyper's IO traits) so the tls branch and the
                // plaintext branch share one adaptable stream type.
                .into_inner();
            match uri.scheme_str() {
                Some("https") => {
                    // rustls requires a DNS ServerName; IPs and anything
                    // else fail the handshake (documented: JWKS endpoints
                    // are named services).
                    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
                        .map_err(|e| {
                            std::io::Error::other(format!("jwks host is not a valid tls name: {e}"))
                        })?;
                    let tls_stream = tokio::time::timeout(
                        JWKS_CONNECT_TIMEOUT,
                        tls.connect(name, hyper_util::rt::tokio::WithHyperIo::new(stream)),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "jwks tls handshake timed out",
                        )
                    })??;
                    Ok(hyper_util::rt::TokioIo::new(MaybeTls::Tls(Box::new(
                        tls_stream,
                    ))))
                }
                // http:// JWKS: plaintext.
                _ => Ok(hyper_util::rt::TokioIo::new(MaybeTls::Plain(
                    hyper_util::rt::tokio::WithHyperIo::new(stream),
                ))),
            }
        })
    }
}

/// Shared JWKS cache for one provider URL: the cached key set plus the
/// refresh bookkeeping. Entries live on the dataplane keyed by URL, so a
/// config reload reuses the cache (rotation state survives reloads).
pub struct JwksCacheEntry {
    keys: RwLock<Arc<JwkSet>>,
    /// The SUPERSEDED key set and when it was retired (DW-046): when a
    /// successful fetch delivers a set that no longer contains a key
    /// the previous set had, the old set is kept here for
    /// `retired_key_grace_secs` — the JWKS half of the dual-validity
    /// window. Tokens signed by an issuer key dropped from the fresh
    /// set (the rotation race: keys are removed from JWKS while
    /// previously-issued tokens still carry the old kid) keep
    /// verifying during the grace; after it they fail closed. Only the
    /// immediately-previous set is retained (rotation is one step at a
    /// time); a set identical in kids does not retire anything.
    retired: RwLock<Option<(Arc<JwkSet>, Instant)>>,
    last_refresh: RwLock<Instant>,
    /// When the last refresh-triggered (unknown-kid) fetch started.
    /// Unknown-kid fetches are refused for a minimum spacing afterwards
    /// (see [`JwtVerifier::key_for`]) so forged random-kid tokens cannot
    /// drive a fetch-per-request storm.
    last_forced_refresh: RwLock<Option<Instant>>,
    /// When the last refresh FAILED. While this is within
    /// `min(5s, refresh_secs)`, stale-path refresh attempts skip the
    /// fetch entirely and fall through to the cached keys (see
    /// [`JwtVerifier::key_for`]): with a down/slow endpoint, every Bearer
    /// request would otherwise pay a fetch attempt serialized on
    /// `refresh_lock` (5s connect timeout each), chaining concurrent
    /// traffic through queued timeouts. A successful refresh clears it.
    last_failed_refresh: RwLock<Option<Instant>>,
    /// Serializes refreshes; concurrent unknown-kid misses coalesce into
    /// one fetch.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl JwksCacheEntry {
    fn new() -> Self {
        JwksCacheEntry {
            keys: RwLock::new(Arc::new(JwkSet { keys: Vec::new() })),
            retired: RwLock::new(None),
            last_refresh: RwLock::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(86400))
                    .unwrap_or(Instant::now()),
            ),
            last_forced_refresh: RwLock::new(None),
            last_failed_refresh: RwLock::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }
}

/// One configured JWT provider at runtime: config + HTTP client + cache.
pub struct JwtVerifier {
    cfg: JwtProviderConfig,
    algorithms: Vec<Algorithm>,
    http: Client<JwksConnector, http_body_util::Full<bytes::Bytes>>,
    cache: Arc<JwksCacheEntry>,
    /// jwks_refresh_total{provider} child (DW-021), incremented on every
    /// JWKS fetch attempt (stale-path and rotation-triggered alike).
    jwks_refresh: Option<prometheus::IntCounter>,
}

impl JwtVerifier {
    fn build(
        cfg: JwtProviderConfig,
        cache: Arc<JwksCacheEntry>,
        obs: Option<&Observability>,
    ) -> Result<Self, AuthError> {
        let algorithms = parse_algorithms(&cfg.algorithms).ok_or_else(|| {
            AuthError::Unavailable(format!(
                "jwt provider '{}' lists an unsupported or disallowed algorithm",
                cfg.name
            ))
        })?;
        let jwks_refresh = obs.map(|o| o.jwks_refresh_counter(cfg.name.as_str()));
        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_timer(TokioTimer::new());
        // #121: the provider's trusted_ca_file (private-CA JWKS
        // endpoints) feeds the fetcher's TLS trust; a broken bundle
        // disables this provider (see CompositeAuthenticator::build)
        // rather than breaking every Bearer request with a fetch
        // failure. Built before the struct so `cfg` is not yet moved.
        let connector = JwksConnector::new(cfg.trusted_ca_file.as_deref())?;
        Ok(JwtVerifier {
            cfg,
            algorithms,
            http: builder.build(connector),
            cache,
            jwks_refresh,
        })
    }

    async fn fetch(&self) -> Result<Arc<JwkSet>, AuthError> {
        // Every fetch (stale-path or rotation-triggered) counts in the
        // jwks_refresh_total metric (DW-021) — attempts, not successes, so
        // a flapping endpoint is visible.
        if let Some(counter) = &self.jwks_refresh {
            counter.inc();
        }
        // Record the outcome for the stale-path failed-refresh backoff: a
        // failed fetch arms it, a successful one clears it (see
        // [`JwksCacheEntry::last_failed_refresh`]).
        let result = self.fetch_once().await;
        match &result {
            Ok(_) => {
                *self
                    .cache
                    .last_failed_refresh
                    .write()
                    .expect("jwks cache poisoned") = None;
            }
            Err(_) => {
                *self
                    .cache
                    .last_failed_refresh
                    .write()
                    .expect("jwks cache poisoned") = Some(Instant::now());
            }
        }
        result
    }

    async fn fetch_once(&self) -> Result<Arc<JwkSet>, AuthError> {
        let uri: Uri = self
            .cfg
            .jwks_url
            .parse()
            .map_err(|e| AuthError::Unavailable(format!("jwks url is invalid: {e}")))?;
        let req = hyper::Request::builder()
            .uri(uri)
            .method(hyper::Method::GET)
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(|e| AuthError::Unavailable(format!("jwks request build failed: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| AuthError::Unavailable(format!("jwks fetch failed: {e:#}")))?;
        if !resp.status().is_success() {
            return Err(AuthError::Unavailable(format!(
                "jwks endpoint answered {}",
                resp.status()
            )));
        }
        // `Limited` enforces the body cap DURING streaming, so an
        // oversized (hostile) key set fails mid-read instead of being
        // buffered whole first.
        let body = http_body_util::BodyExt::collect(http_body_util::Limited::new(
            resp.into_body(),
            JWKS_BODY_CAP as usize,
        ))
        .await
        .map_err(|e| AuthError::Unavailable(format!("jwks body read failed: {e}")))?;
        let body = body.to_bytes();
        let set: JwkSet = serde_json::from_slice(&body)
            .map_err(|e| AuthError::Unavailable(format!("jwks body is not a jwk set: {e}")))?;
        let set = Arc::new(set);
        // DW-046: swap the cached set under ONE write guard, retiring
        // the superseded set only when its kid set differs (the issuer
        // rotated); identical kids keep the old retirement stamp (an
        // unrelated re-fetch must not extend any grace). The retired
        // stamp happens AFTER the keys guard drops — std RwLock is not
        // reentrant, and a second keys.write on this thread would
        // self-deadlock.
        let superseded = {
            let mut keys = self.cache.keys.write().expect("jwks cache poisoned");
            if jwk_sets_same_kids(&keys, &set) {
                *keys = Arc::clone(&set);
                None
            } else {
                let old = Arc::clone(&keys);
                *keys = Arc::clone(&set);
                Some(old)
            }
        };
        if let Some(old) = superseded {
            *self.cache.retired.write().expect("jwks cache poisoned") = Some((old, Instant::now()));
        }
        *self
            .cache
            .last_refresh
            .write()
            .expect("jwks cache poisoned") = Instant::now();
        Ok(set)
    }

    /// Find the JWK for `kid`/`alg`, refreshing when the cache is stale or
    /// the kid is unknown (rotation). Refreshes are serialized; a caller
    /// that lost the refresh race re-checks the freshly cached set.
    ///
    /// ## Stale caches refresh BEFORE use
    ///
    /// Once the cache age exceeds `refresh_secs`, the next key lookup
    /// refreshes under the lock BEFORE serving a cached key: a stale set
    /// must not keep verifying a retired issuer key indefinitely. If that
    /// refresh FAILS, the cached keys keep serving (documented degradation
    /// — an endpoint disturbance is not an immediate outage), except when
    /// the cache is empty (nothing to degrade to: `Unavailable`).
    ///
    /// ## Failed stale refreshes back off
    ///
    /// A FAILED stale-path refresh arms a backoff: for the next
    /// `min(5s, refresh_secs)`, stale-path lookups skip the fetch entirely
    /// and answer from the cached keys immediately. Without this, a
    /// down/slow JWKS endpoint would make EVERY Bearer request pay a fetch
    /// attempt serialized on the refresh lock (a 5s connect timeout each),
    /// chaining concurrent traffic through queued timeouts. A successful
    /// refresh clears the backoff; an EMPTY cache never backs off (there
    /// is nothing to degrade to, so the `Unavailable` error surfaces).
    ///
    /// ## Unknown-kid refreshes are throttled
    ///
    /// A fresh cache with an unknown `kid` triggers one deliberate
    /// rotation fetch — and then NO further refresh-triggered fetches for
    /// `min(5s, refresh_secs)`: subsequent unknown-kid requests answer 401
    /// from the (freshly fetched) cached set. Forged random-kid tokens
    /// therefore buy at most one JWKS fetch per window and cannot drive a
    /// fetch storm through the serialized refresh lock (which would stall
    /// all Bearer traffic). One genuine rotation flip still pays at most
    /// one fetch — the flip's own request performs it. The AGE-based
    /// refresh above is deliberately NOT throttled: it fires at most once
    /// per `refresh_secs` by construction.
    async fn key_for(&self, kid: Option<&str>, alg: Algorithm) -> Result<Jwk, AuthError> {
        let stale_after = Duration::from_secs(self.cfg.refresh_secs.max(1));
        let forced_min_interval = JWKS_FORCED_REFRESH_MIN_INTERVAL.min(stale_after);
        let fresh = {
            let keys = self.cache.keys.read().expect("jwks cache poisoned");
            let last = *self.cache.last_refresh.read().expect("jwks cache poisoned");
            if last.elapsed() < stale_after {
                if let Some(jwk) = find_jwk(&keys, kid, alg) {
                    return Ok(jwk.clone());
                }
            }
            last.elapsed() < stale_after
        };
        let _guard = self.cache.refresh_lock.lock().await;
        if !fresh {
            // Cache age exceeded refresh_secs: refresh BEFORE serving the
            // cached key (a stale set must not keep verifying retired
            // issuer keys forever). Failure degrades to the cached set
            // unless there is nothing cached to serve.
            let still_stale = {
                let last = *self.cache.last_refresh.read().expect("jwks cache poisoned");
                last.elapsed() >= stale_after
            };
            if still_stale {
                let cached_nonempty = !self
                    .cache
                    .keys
                    .read()
                    .expect("jwks cache poisoned")
                    .keys
                    .is_empty();
                // Failed-refresh backoff: when the previous refresh failed
                // recently and there ARE cached keys to degrade to, skip
                // the fetch — answer from the cache immediately instead of
                // chaining every Bearer request through a doomed fetch
                // attempt (5s connect timeout each) on the refresh lock.
                let in_failure_backoff = cached_nonempty && {
                    let failed = *self
                        .cache
                        .last_failed_refresh
                        .read()
                        .expect("jwks cache poisoned");
                    failed.is_some_and(|t| t.elapsed() < forced_min_interval)
                };
                if !in_failure_backoff {
                    match self.fetch().await {
                        Ok(set) => {
                            if let Some(jwk) = find_jwk(&set, kid, alg) {
                                return Ok(jwk.clone());
                            }
                            // DW-046: missing from the FRESH set — the
                            // retired set's grace decides.
                            return self
                                .find_retired(kid, alg)
                                .ok_or(AuthError::Invalid("token key id is unknown"));
                        }
                        Err(e) => {
                            if !cached_nonempty {
                                return Err(e);
                            }
                            // Degraded mode: fall through to the cached set.
                        }
                    }
                }
            }
            let keys = self.cache.keys.read().expect("jwks cache poisoned");
            if let Some(jwk) = find_jwk(&keys, kid, alg) {
                return Ok(jwk.clone());
            }
            if let Some(jwk) = self.find_retired(kid, alg) {
                return Ok(jwk);
            }
            return Err(AuthError::Invalid("token key id is unknown"));
        }
        // Fresh cache, unknown kid: the rotation path. Re-check the cached
        // set under the lock first — a concurrent request's fetch may have
        // already delivered our kid — and consult the RETIRED set (DW-046):
        // a kid the issuer already dropped needs no fetch at all, so it
        // must not spend (or be refused by) the forced-refresh throttle.
        {
            let keys = self.cache.keys.read().expect("jwks cache poisoned");
            if let Some(jwk) = find_jwk(&keys, kid, alg) {
                return Ok(jwk.clone());
            }
        }
        if let Some(jwk) = self.find_retired(kid, alg) {
            return Ok(jwk);
        }
        // Claim the throttle
        // window BEFORE fetching so a failed fetch also spends it (the
        // endpoint saw the traffic either way).
        let eligible = {
            let mut last = self
                .cache
                .last_forced_refresh
                .write()
                .expect("jwks cache poisoned");
            match *last {
                Some(t) if t.elapsed() < forced_min_interval => false,
                _ => {
                    *last = Some(Instant::now());
                    true
                }
            }
        };
        if !eligible {
            // Refused for the throttle window: answer 401 from the cached
            // set without touching the JWKS endpoint.
            return Err(AuthError::Invalid("token key id is unknown"));
        }
        let set = self.fetch().await?;
        if let Some(jwk) = find_jwk(&set, kid, alg) {
            return Ok(jwk.clone());
        }
        // DW-046: the forced rotation fetch delivered a set without the
        // kid; the retired set's grace decides.
        self.find_retired(kid, alg)
            .ok_or(AuthError::Invalid("token key id is unknown"))
    }

    /// The retired-set fallback (DW-046): the immediately-previous key
    /// set, honored while younger than the provider's
    /// `retired_key_grace_secs` (0 disables the fallback entirely).
    fn find_retired(&self, kid: Option<&str>, alg: Algorithm) -> Option<Jwk> {
        let grace = Duration::from_secs(self.cfg.retired_key_grace_secs());
        if grace.is_zero() {
            return None;
        }
        let retired = self
            .cache
            .retired
            .read()
            .expect("jwks cache poisoned")
            .clone();
        let (set, at) = retired?;
        if at.elapsed() >= grace {
            return None;
        }
        find_jwk(&set, kid, alg).cloned()
    }
}

/// Whether two JWK sets carry the SAME key ids (the retire-on-change
/// discriminator; algorithms may re-order freely).
fn jwk_sets_same_kids(a: &JwkSet, b: &JwkSet) -> bool {
    fn kids(s: &JwkSet) -> Vec<String> {
        let mut v: Vec<String> = s
            .keys
            .iter()
            .filter_map(|k| k.common.key_id.clone())
            .collect();
        v.sort_unstable();
        v
    }
    kids(a) == kids(b)
}

fn find_jwk<'a>(set: &'a JwkSet, kid: Option<&str>, alg: Algorithm) -> Option<&'a Jwk> {
    let family = algorithm_family(alg);
    set.keys
        .iter()
        .filter(|k| match kid {
            Some(id) => k.common.key_id.as_deref() == Some(id),
            None => true,
        })
        // Family filter (defense against a mixed set): RSA keys answer
        // RS*/PS*, EC keys answer ES*, OKP answers Ed*.
        .find(|k| {
            matches!(
                (&k.algorithm, family.as_str()),
                (AlgorithmParameters::RSA(_), "RS" | "PS")
                    | (AlgorithmParameters::EllipticCurve(_), "ES")
                    | (AlgorithmParameters::OctetKeyPair(_), "Ed")
            )
        })
}

/// The JWK key family an algorithm verifies with ("RS", "ES", "Ed", ...).
fn algorithm_family(alg: Algorithm) -> String {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => "HS".into(),
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => "RS".into(),
        Algorithm::ES256 | Algorithm::ES384 => "ES".into(),
        Algorithm::EdDSA => "Ed".into(),
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => "PS".into(),
    }
}

/// Public for testing the JWT algorithm-allowlist contract.
pub fn parse_algorithms(names: &[String]) -> Option<Vec<Algorithm>> {
    use std::str::FromStr as _;
    if names.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let alg = match name.to_ascii_uppercase().as_str() {
            "HS256" | "HS384" | "HS512" | "NONE" => {
                // Asymmetric verification only: symmetric algorithms would
                // make the gateway a shared-secret holder and enable
                // alg-confusion downgrade; "none" is never a choice.
                return None;
            }
            other => Algorithm::from_str(other).ok()?,
        };
        out.push(alg);
    }
    Some(out)
}

// --- composite -------------------------------------------------------------

/// Upper bound on the spacing between refresh-triggered (unknown-kid)
/// JWKS fetches, before rate limiting or any other control: a forged
/// token with a random `kid` must never buy the attacker a JWKS fetch.
/// The effective window is `min(5s, refresh_secs)` so a tight refresh
/// cadence tightens the throttle too.
const JWKS_FORCED_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// The gateway's single authenticator: dispatches on the request's
/// credential shape (X-API-Key / Basic / Bearer / verified client
/// certificate) and consults the credential registry plus the configured
/// JWT providers.
pub struct CompositeAuthenticator {
    registry: CredentialRegistry,
    jwt: Vec<Arc<JwtVerifier>>,
    /// Whether the config declares ANY jwt provider (#131):
    /// distinguishes "no provider configured" (Bearer is not the
    /// gateway's credential to interpret — deliberate pass-through)
    /// from "providers configured but every verifier failed to build"
    /// (the gateway promised to verify Bearer tokens and cannot —
    /// fail closed with `Unavailable`).
    jwt_configured: bool,
    /// issuer -> (consumer name, audiences) from consumers' jwt
    /// credentials: the claims-based consumer mapping for tokens whose
    /// provider has no explicit `consumer` binding.
    jwt_consumer_index: HashMap<String, (String, Vec<String>)>,
    /// consumer name -> groups from the CONFIG consumers (#124): the
    /// fast lookup for identity group resolution; store-managed
    /// consumers fall through to a (cached) store lookup.
    consumer_groups_index: HashMap<String, Vec<String>>,
    /// The per-deployment credential pepper (#124): raw bytes resolved
    /// ABOVE this domain through the SecretSource seam, held Arc-shared
    /// with the dataplane's Zeroizing holder so the buffer is zeroized
    /// when the LAST holder drops and no plain copy exists on the way
    /// down. SECRET: never logged, never in Debug, never in error text.
    /// `None` = legacy-only mode (peppered entries fail closed).
    pepper: Option<Arc<Zeroizing<Vec<u8>>>>,
    /// Guards the one-shot "peppered credential failed closed without a
    /// pepper" warning (#124): the clear log line fires once per
    /// authenticator build, not per request.
    pepper_missing_logged: AtomicBool,
    /// HMAC signing keys (DW-036): key_id -> credential. Config-declared
    /// only (the state store cannot hold raw MAC key material; see the
    /// module docs) — built from `consumers[].credentials[type=hmac]`
    /// regardless of whether the registry variant is store or config.
    /// The map is present whenever any hmac credential resolved; the
    /// PRESENCE of `X-Dwara-Signature` with an empty map is a 401 (a
    /// presented credential the gateway cannot verify).
    hmac_keys: HashMap<String, Arc<HmacCredential>>,
    /// Gateway-wide HMAC verification policy (DW-036): the accepted
    /// timestamp skew in seconds. Defaults to
    /// [`DEFAULT_HMAC_CLOCK_SKEW_SECS`] when the config sets no
    /// `hmac_auth` block; validation bounds the configured value.
    hmac_skew_secs: u64,
    /// Replay-nonce store (DW-036), SHARED ACROSS rebuilds: the dataplane
    /// owns it and hands every generation the same Arc, so a config
    /// reload never wipes remembered nonces (the jwks_caches precedent).
    /// Per-instance by design in M2 (see the module docs' replay
    /// boundary note).
    nonce_cache: Arc<NonceCache>,
    /// Whether ANY credential family is active; when false the composite
    /// is a no-op (pass-through mode).
    enabled: bool,
}

impl CompositeAuthenticator {
    /// The disabled authenticator: no registry, no providers, anonymous
    /// for everything (pass-through mode). The dataplane's placeholder
    /// before [`Self::build`] runs.
    pub fn disabled() -> Self {
        CompositeAuthenticator {
            registry: CredentialRegistry::Config(HashMap::new()),
            jwt: Vec::new(),
            jwt_configured: false,
            jwt_consumer_index: HashMap::new(),
            consumer_groups_index: HashMap::new(),
            pepper: None,
            pepper_missing_logged: AtomicBool::new(false),
            hmac_keys: HashMap::new(),
            hmac_skew_secs: DEFAULT_HMAC_CLOCK_SKEW_SECS,
            nonce_cache: Arc::new(NonceCache::new()),
            enabled: false,
        }
    }
    /// Build from one config generation. `store` is the DWARA_STATE_DB
    /// store when deployed; without it credentials come from config,
    /// hashed in-memory. `jwks_caches` carries JWKS cache entries ACROSS
    /// rebuilds (keyed by URL) so reloads keep rotation state, and
    /// `nonce_cache` carries the HMAC replay-nonce store across rebuilds
    /// the same way (DW-036). `pepper` (#124) is the per-deployment
    /// credential pepper — an Arc CLONE of the dataplane's Zeroizing
    /// holder (no byte copy; the bytes zeroize when the last holder
    /// drops), resolved by the CALLER through the SecretSource extension
    /// seam (this domain must not import extensions) — or `None` for
    /// legacy-only mode.
    pub fn build(
        gateway: &Gateway,
        store: Option<Arc<StateStore>>,
        jwks_caches: &mut HashMap<String, Arc<JwksCacheEntry>>,
        obs: Option<&Observability>,
        pepper: Option<&Arc<Zeroizing<Vec<u8>>>>,
        nonce_cache: Arc<NonceCache>,
    ) -> Arc<Self> {
        let registry = match store {
            Some(store) => CredentialRegistry::Store(store),
            None => CredentialRegistry::from_config(gateway, pepper.map(|p| p.as_slice())),
        };
        let mut jwt = Vec::new();
        for cfg in &gateway.jwt_providers {
            let cache = jwks_caches
                .entry(cfg.jwks_url.clone())
                .or_insert_with(|| Arc::new(JwksCacheEntry::new()))
                .clone();
            match JwtVerifier::build(cfg.clone(), cache, obs) {
                Ok(v) => jwt.push(Arc::new(v)),
                Err(e) => {
                    tracing::error!(code = "jwt_provider_disabled", "jwt provider disabled: {e}")
                }
            }
        }
        let mut jwt_consumer_index = HashMap::new();
        let mut consumer_groups_index = HashMap::new();
        // DW-036: HMAC keys are config-served ONLY (raw key bytes in
        // memory; see the module docs), so they are collected here
        // regardless of the registry variant. `${...}` secret references
        // (DW-045) resolve HERE and the plaintext is dropped into the
        // Zeroizing holder; validation already rejected unresolvable
        // references for this generation, so an error here is the
        // validate-vs-build microsecond race — fail CLOSED (skip the
        // credential: that key stops authenticating) with a loud log,
        // the same pattern as api keys.
        let mut hmac_keys = HashMap::new();
        for consumer in &gateway.consumers {
            consumer_groups_index.insert(consumer.name.clone(), consumer.groups.clone());
            for credential in &consumer.credentials {
                if let Credential::Jwt { issuer, audiences } = credential {
                    jwt_consumer_index
                        .insert(issuer.clone(), (consumer.name.clone(), audiences.clone()));
                }
                if let Credential::Hmac { key_id, secret } = credential {
                    let secret = match crate::config::credentials::resolve_configured_secret(secret)
                    {
                        Ok(resolved) => resolved,
                        Err(err) => {
                            tracing::error!(
                                code = "config_hmac_secret_unresolvable",
                                consumer = %consumer.name,
                                "skipping hmac credential (secret reference unresolvable \
                                 at authenticator build): {err}"
                            );
                            continue;
                        }
                    };
                    // Validation rejects duplicate key ids; a generation
                    // tear that slips one through keeps the LAST entry.
                    hmac_keys.insert(
                        key_id.clone(),
                        Arc::new(HmacCredential {
                            consumer_name: consumer.name.clone(),
                            secret: Arc::new(Zeroizing::new(secret.into_bytes())),
                        }),
                    );
                }
            }
        }
        let enabled = !gateway.consumers.is_empty() || !jwt.is_empty();
        Arc::new(CompositeAuthenticator {
            registry,
            jwt,
            jwt_configured: !gateway.jwt_providers.is_empty(),
            jwt_consumer_index,
            consumer_groups_index,
            pepper: pepper.cloned(),
            pepper_missing_logged: AtomicBool::new(false),
            hmac_keys,
            hmac_skew_secs: gateway
                .hmac_auth
                .as_ref()
                .map_or(DEFAULT_HMAC_CLOCK_SKEW_SECS, |h| h.max_clock_skew_secs),
            nonce_cache,
            enabled,
        })
    }

    /// Resolve the group memberships of a consumer by name (#124):
    /// config consumers from the config-built index, store-managed
    /// consumers through a (hot-cached) store lookup. Unknown name = no
    /// groups (group rules then deny, which fails closed).
    fn consumer_groups_of(&self, consumer_name: &str) -> Vec<String> {
        if let Some(groups) = self.consumer_groups_index.get(consumer_name) {
            return groups.clone();
        }
        if let CredentialRegistry::Store(store) = &self.registry {
            if let Ok(Some(record)) = store.lookup_consumer(consumer_name) {
                return record.groups.clone();
            }
        }
        Vec::new()
    }

    /// A peppered stored hash failed closed because no pepper is
    /// configured. The clear log line fires ONCE per authenticator build
    /// (the condition cannot change without a rebuild), never per
    /// request; the message names no credential material.
    fn log_pepper_missing_once(&self) {
        if !self.pepper_missing_logged.swap(true, Ordering::Relaxed) {
            tracing::error!(
                code = "credential_pepper_absent",
                "a peppered (hmac-sha256) stored credential failed verification because no \
                 credential pepper is configured; peppered credentials cannot verify in \
                 legacy-only mode (legacy sha256 entries keep working)"
            );
        }
    }

    async fn authenticate_api_key_or_basic(
        &self,
        selector: &str,
        presented_secret: &str,
    ) -> Result<Option<Identity>, AuthError> {
        let pepper = self.pepper.as_deref().map(|z| z.as_slice());
        let candidates = self.registry.lookup(selector).await?;
        for cred in &candidates {
            if cred.kind != CredentialKind::ApiKey {
                continue;
            }
            if cred.hash.starts_with("hmac-sha256:") && pepper.is_none() {
                self.log_pepper_missing_once();
            }
            if verify_secret(&cred.hash, presented_secret, pepper) {
                // #124 pepper transition: a SUCCESSFUL legacy (sha256)
                // verification with a pepper configured upgrades the store
                // row to the peppered format in place, so the transition
                // completes lazily without credential re-issue. Config-
                // seeded credentials (no row id) have no legacy residue by
                // construction. A re-hash failure never fails the request
                // (verification already succeeded) — it logs and leaves
                // the legacy row to retry on the next presentation.
                if let (Some(id), Some(pepper)) = (cred.id, pepper) {
                    if cred.hash.starts_with("sha256:") {
                        let peppered = hmac_stored_hash(pepper, presented_secret);
                        if let CredentialRegistry::Store(store) = &self.registry {
                            if let Err(e) = store.rehash_credential(id, selector, &peppered) {
                                tracing::warn!(
                                    code = "credential_rehash_failed",
                                    "legacy credential re-hash to the peppered format failed: {e}"
                                );
                            }
                        }
                    }
                }
                let consumer_name = cred.consumer_name.clone();
                let groups = self.consumer_groups_of(&consumer_name);
                return Ok(Some(Identity {
                    consumer_name,
                    credential_kind: CredentialKind::ApiKey,
                    groups,
                    claims: BTreeMap::new(),
                    body_digest: None,
                }));
            }
        }
        Err(AuthError::Invalid("unknown api key or basic credentials"))
    }

    /// mTLS family (#124): map a VERIFIED client certificate to a
    /// consumer. The lookup consults BOTH selectors the certificate
    /// offers (subject CN when present, fingerprint always); an `mtls`
    /// credential found under either selector is a match because the
    /// credential's selector IS its match value. A verified certificate
    /// that matches no credential is a PRESENTED-but-rejected credential
    /// (401), exactly like an unknown API key.
    async fn authenticate_client_cert(
        &self,
        cert: &ClientCertificate,
    ) -> Result<Option<Identity>, AuthError> {
        let mut selectors: Vec<&str> = Vec::with_capacity(2);
        if let Some(cn) = cert.subject_cn.as_deref() {
            selectors.push(cn);
        }
        selectors.push(cert.fingerprint.as_str());
        for selector in selectors {
            let candidates = self.registry.lookup(selector).await?;
            for cred in &candidates {
                if cred.kind != CredentialKind::Mtls {
                    continue;
                }
                let consumer_name = cred.consumer_name.clone();
                let groups = self.consumer_groups_of(&consumer_name);
                return Ok(Some(Identity {
                    consumer_name,
                    credential_kind: CredentialKind::Mtls,
                    groups,
                    claims: BTreeMap::new(),
                    body_digest: None,
                }));
            }
        }
        Err(AuthError::Invalid(
            "client certificate matches no credential",
        ))
    }

    async fn authenticate_jwt(&self, token: &str) -> Result<Option<Identity>, AuthError> {
        if self.jwt.is_empty() {
            if !self.jwt_configured {
                // No provider configured: Bearer stays pass-through —
                // the header may be intended for the upstream (the
                // documented optional-authn shape; `challenge()` offers
                // no Bearer scheme in this state either).
                return Ok(None);
            }
            // Providers are configured but every verifier failed to
            // build (#131): the gateway promised to verify Bearer tokens
            // and cannot. Failing closed with `Unavailable` (500-class
            // authentication_unavailable) instead of proxying the token
            // unverified with no consumer identity. Reachable only via
            // the validate-vs-build race (#121 rejects broken bundles at
            // validation); the residual must still fail loud, not
            // silently.
            return Err(AuthError::Unavailable(
                "jwt providers are configured but disabled (verifier build failed); \
                 failing closed instead of proxying Bearer tokens unverified"
                    .to_string(),
            ));
        }
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| AuthError::Invalid("token header is malformed"))?;
        let kid = header.kid.as_deref();
        let mut last_invalid = AuthError::Invalid("token did not verify");
        let mut unavailable: Option<AuthError> = None;
        for verifier in &self.jwt {
            if !verifier.algorithms.contains(&header.alg) {
                last_invalid = AuthError::Invalid("token algorithm is not allowed");
                continue;
            }
            match self.verify_with(verifier, token, &header, kid).await {
                Ok(identity) => return Ok(Some(identity)),
                Err(e @ AuthError::Invalid(_)) => last_invalid = e,
                Err(e @ AuthError::Unavailable(_)) => unavailable = Some(e),
            }
        }
        // Error masking: when EVERY provider failed, a 401 ("invalid
        // token") would hide that one of them was down. If any provider
        // was Unavailable, surface the gateway-side failure (500-class)
        // so operators see it instead of a wall of caller-side 401s.
        if let Some(e) = unavailable {
            return Err(e);
        }
        Err(last_invalid)
    }

    async fn verify_with(
        &self,
        verifier: &JwtVerifier,
        token: &str,
        header: &Header,
        kid: Option<&str>,
    ) -> Result<Identity, AuthError> {
        let jwk = verifier.key_for(kid, header.alg).await?;
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|_| AuthError::Invalid("jwk is not usable for this token"))?;
        // Asymmetric sanity: the JWK must actually be an asymmetric key
        // (RSA/EC/OKP) — a symmetric key in the set paired with an
        // allowed algorithm is a configuration error, not a secret.
        if !matches!(
            jwk.algorithm,
            AlgorithmParameters::RSA(_)
                | AlgorithmParameters::EllipticCurve(_)
                | AlgorithmParameters::OctetKeyPair(_)
        ) {
            return Err(AuthError::Invalid("jwk is not an asymmetric key"));
        }
        let mut validation = Validation::new(header.alg);
        validation.leeway = verifier.cfg.leeway_secs;
        if let Some(iss) = &verifier.cfg.issuer {
            validation.iss = Some(std::iter::once(iss.clone()).collect());
        }
        // #124 (maintainer decision): audience is validated ONLY when the
        // provider configures one. jsonwebtoken validates `aud` whenever
        // the token CARRIES the claim and the Validation expects it — so
        // with no configured audience we switch aud validation off
        // entirely (a token with any, or no, `aud` is accepted) instead of
        // jsonwebtoken's reject-on-presence. Every other validation (exp,
        // nbf, iss when configured, the algorithm allowlist above) is
        // identical either way.
        match &verifier.cfg.audience {
            Some(aud) => validation.aud = Some(std::iter::once(aud.clone()).collect()),
            None => validation.validate_aud = false,
        }
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
            .map_err(|_| AuthError::Invalid("token failed verification"))?;
        let claims = &data.claims;
        // Consumer mapping: explicit provider binding first, then the
        // consumers' jwt-credential issuer index (with audience
        // containment when the credential lists audiences).
        let consumer_name = match &verifier.cfg.consumer {
            Some(name) => name.clone(),
            None => {
                let iss = claims
                    .get("iss")
                    .and_then(|v| v.as_str())
                    .ok_or(AuthError::Invalid("token has no string iss claim"))?;
                let (name, audiences) = self.jwt_consumer_index.get(iss).ok_or(
                    AuthError::Invalid("token issuer is not bound to a consumer"),
                )?;
                if !audiences.is_empty() {
                    let aud_matches = match claims.get("aud") {
                        Some(serde_json::Value::String(a)) => audiences.iter().any(|w| w == a),
                        Some(serde_json::Value::Array(a)) => a
                            .iter()
                            .filter_map(|v| v.as_str())
                            .any(|v| audiences.iter().any(|w| w == v)),
                        _ => false,
                    };
                    if !aud_matches {
                        return Err(AuthError::Invalid(
                            "token audience does not match the consumer binding",
                        ));
                    }
                }
                name.clone()
            }
        };
        let groups = self.consumer_groups_of(&consumer_name);
        let mut identity_claims = BTreeMap::new();
        if let Some(map) = claims.as_object() {
            for (k, v) in map {
                if identity_claims.len() >= 32 {
                    break;
                }
                match v {
                    serde_json::Value::String(s) => {
                        identity_claims.insert(k.clone(), s.clone());
                    }
                    serde_json::Value::Number(n) => {
                        identity_claims.insert(k.clone(), n.to_string());
                    }
                    // Array-of-strings claims are flattened to their
                    // space-separated form (the OAuth `scope` convention,
                    // which authorization's required_scopes matches either
                    // way — DW-020). NOTE: the map stores the flattened
                    // string, so ANY future consumer of identity claims
                    // sees arrays as space-joined strings, never as lists.
                    // Arrays holding non-strings are dropped, like every
                    // other non-scalar claim.
                    serde_json::Value::Array(a)
                        if !a.is_empty() && a.iter().all(|v| v.is_string()) =>
                    {
                        identity_claims.insert(
                            k.clone(),
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                    _ => {}
                }
            }
        }
        Ok(Identity {
            consumer_name,
            credential_kind: CredentialKind::Jwt,
            groups,
            claims: identity_claims,
            body_digest: None,
        })
    }

    /// HMAC request-signature family (DW-036). Verification order and
    /// the failure posture are documented in the module docs (parse ->
    /// timestamp window -> constant-time MAC -> nonce burn); the
    /// returned identity carries the signed body digest for the forward
    /// path to enforce while streaming (`Identity::body_digest`).
    async fn authenticate_hmac(
        &self,
        req: &AuthnRequest<'_>,
    ) -> Result<Option<Identity>, AuthError> {
        let header =
            |name: &hyper::header::HeaderName| req.headers.get(name).and_then(|v| v.to_str().ok());
        // All five headers are required; a partial set is a malformed
        // presented credential (401), never a fall-through to anonymous.
        let Some(key_id) = header(&X_DWARA_KEY_ID) else {
            return Err(AuthError::Invalid("signed request lacks x-dwara-key-id"));
        };
        let Some(timestamp) = header(&X_DWARA_TIMESTAMP) else {
            return Err(AuthError::Invalid("signed request lacks x-dwara-timestamp"));
        };
        let Some(nonce) = header(&X_DWARA_NONCE) else {
            return Err(AuthError::Invalid("signed request lacks x-dwara-nonce"));
        };
        let Some(body_sha256) = header(&X_DWARA_BODY_SHA256) else {
            return Err(AuthError::Invalid(
                "signed request lacks x-dwara-body-sha256",
            ));
        };
        let Some(signature) = header(&X_DWARA_SIGNATURE) else {
            // Unreachable from the dispatcher (presence of this header is
            // what engages the family) but keeps the family self-contained.
            return Err(AuthError::Invalid("signed request lacks x-dwara-signature"));
        };
        // Format bounds: the canonical grammar is only unambiguous over
        // these shapes (module docs). Checked before the timestamp so a
        // hostile header never reaches the clock or the cache.
        if !is_visible_ascii(key_id.as_bytes()) || key_id.len() > MAX_KEY_ID_BYTES {
            return Err(AuthError::Invalid(
                "key id is not 1..=128 visible ascii bytes",
            ));
        }
        if !is_visible_ascii(nonce.as_bytes())
            || !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&nonce.len())
        {
            return Err(AuthError::Invalid(
                "nonce is not 16..=256 visible ascii bytes",
            ));
        }
        let Some(presented_mac) = decode_hex32(signature) else {
            return Err(AuthError::Invalid("signature is not 64 hex digits"));
        };
        let Some(body_digest) = decode_hex32(body_sha256) else {
            return Err(AuthError::Invalid("body digest is not 64 hex digits"));
        };
        if !timestamp.bytes().all(|b| b.is_ascii_digit()) || timestamp.len() > 20 {
            return Err(AuthError::Invalid("timestamp is not decimal unix seconds"));
        }
        // The shape check above does not bound the VALUE: 20 digits
        // reach above u64::MAX (18446744073709551616 and friends), and
        // `u64::from_str` rejects them. Parse fail-closed — a panic
        // here would kill the connection task instead of answering
        // the 401 envelope (remotely triggerable, unauthenticated).
        let Ok(presented_ts) = timestamp.parse::<u64>() else {
            return Err(AuthError::Invalid("timestamp is not decimal unix seconds"));
        };
        // Clock-skew window (§4.6): reject BEFORE any HMAC work. The
        // window is symmetric (past and future) — signers' clocks may
        // drift either way. u64 arithmetic end to end: no signed cast
        // of a hostile 20-digit value can wrap the comparison.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let drift = presented_ts.abs_diff(now);
        if drift > self.hmac_skew_secs {
            return Err(AuthError::Invalid(
                "signature timestamp is outside the clock-skew window",
            ));
        }
        // Canonical string from the PRESENTED bytes (module docs): no
        // normalization of path or query, the digest header value as
        // sent. The signature header itself is deliberately NOT signed
        // material (it cannot sign itself).
        let canonical = canonical_string(
            key_id,
            req.method,
            req.uri.path(),
            req.uri.query(),
            timestamp,
            nonce,
            body_sha256,
        );
        let Some(credential) = self.hmac_keys.get(key_id) else {
            // Key-existence timing oracle: compute a dummy MAC over the
            // same canonical string with a fixed zero key so "unknown
            // key" and "wrong signature" spend the same work. The dummy
            // is discarded; the answer is the same 401 either way.
            let _ = request_mac(&[0u8; 32], &canonical);
            return Err(AuthError::Invalid("unknown hmac credentials"));
        };
        let computed = request_mac(credential.secret.as_slice(), &canonical);
        // Constant-time over the full 32-byte digests: no early return
        // on a byte mismatch (DW-036 done-when).
        if !bool::from(computed.ct_eq(&presented_mac)) {
            return Err(AuthError::Invalid("request signature did not verify"));
        }
        // Replay window (module docs): burn the nonce only AFTER a
        // successful MAC, scoped to the key (nonce collisions across
        // consumers must not cross-burn). TTL is twice the skew window
        // so a timestamp stays replay-guarded for its entire acceptance
        // lifetime with margin.
        let cache_key = format!("{key_id}\n{nonce}");
        if !self
            .nonce_cache
            .check_and_insert(&cache_key, Duration::from_secs(self.hmac_skew_secs * 2))
        {
            return Err(AuthError::Invalid("nonce already used inside the window"));
        }
        let consumer_name = credential.consumer_name.clone();
        let groups = self.consumer_groups_of(&consumer_name);
        Ok(Some(Identity {
            consumer_name,
            credential_kind: CredentialKind::Hmac,
            groups,
            claims: BTreeMap::new(),
            body_digest: Some(body_digest),
        }))
    }
}

#[async_trait]
impl Authenticator for CompositeAuthenticator {
    async fn authenticate(&self, req: &AuthnRequest<'_>) -> Result<Option<Identity>, AuthError> {
        if !self.enabled {
            return Ok(None);
        }
        let headers = req.headers;
        // Family precedence (documented): header-presented credentials
        // express explicit intent and win — X-API-Key over anything in
        // `Authorization`, `Basic` over `Bearer` by scheme token, the
        // X-Dwara signature family after the Authorization schemes —
        // and the VERIFIED client certificate is the ambient,
        // connection-level family consulted only when no header
        // credential was presented. A Bearer header with no configured
        // provider is NOT interpreted (pass-through), so it falls
        // through to the remaining families rather than masking them.
        if let Some(key) = headers.get(&X_API_KEY).and_then(|v| v.to_str().ok()) {
            if key.is_empty() {
                return Err(AuthError::Invalid("empty api key"));
            }
            return self
                .authenticate_api_key_or_basic(&credential_selector(key), key)
                .await;
        }
        if let Some(value) = headers
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let (scheme, rest) = value.split_once(' ').unwrap_or((value, ""));
            if scheme.eq_ignore_ascii_case("basic") {
                let decoded = BASE64
                    .decode(rest.trim())
                    .map_err(|_| AuthError::Invalid("basic credentials are not valid base64"))?;
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| AuthError::Invalid("basic credentials are not utf-8"))?;
                let (user, pass) = decoded
                    .split_once(':')
                    .ok_or(AuthError::Invalid("basic credentials lack a ':' separator"))?;
                if user.is_empty() || pass.is_empty() {
                    return Err(AuthError::Invalid("basic credentials are empty"));
                }
                return self
                    .authenticate_api_key_or_basic(&credential_selector(user), pass)
                    .await;
            }
            if scheme.eq_ignore_ascii_case("bearer") {
                if rest.trim().is_empty() {
                    return Err(AuthError::Invalid("empty bearer token"));
                }
                // No provider configured leaves `Ok(None)`: Bearer stays
                // pass-through (not interpreted), so the certificate
                // family may still authenticate the connection; any
                // resolved identity or failure is the answer. Providers
                // configured but disabled (#131) instead answers
                // `Err(Unavailable)` — the presented credential was the
                // gateway's to verify and it cannot, so it never
                // proxies unverified.
                if let verified @ (Ok(Some(_)) | Err(_)) = self.authenticate_jwt(rest.trim()).await
                {
                    return verified;
                }
            }
        }
        // HMAC request-signature family (DW-036): engaged by the
        // PRESENCE of the signature header — an explicit-intent header
        // credential like the two above, so a signed request never
        // falls through to the ambient certificate family.
        if headers.contains_key(&X_DWARA_SIGNATURE) {
            return self.authenticate_hmac(req).await;
        }
        // Ambient family: the verified client certificate (#124).
        if let Some(cert) = req.client_cert {
            return self.authenticate_client_cert(cert).await;
        }
        Ok(None)
    }

    fn challenge(&self) -> String {
        let mut parts = Vec::new();
        match &self.registry {
            CredentialRegistry::Config(m) if m.is_empty() => {}
            // The store path may hold credentials regardless of config,
            // so it conservatively offers the Basic challenge.
            CredentialRegistry::Store(_) | CredentialRegistry::Config(_) => {
                parts.push("Basic realm=\"dwara\"".to_string());
            }
        }
        if !self.jwt.is_empty() {
            parts.push("Bearer".to_string());
        }
        if !self.hmac_keys.is_empty() {
            parts.push(HMAC_CHALLENGE.to_string());
        }
        if parts.is_empty() {
            "Bearer".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Whether the gateway treats `X-Consumer-*` request headers as spoof
/// material: always — the proxy strips them and injects its own.
pub const CONSUMER_HEADER_PREFIX: &str = "x-consumer-";

/// The trusted consumer-identity header the gateway injects upstream.
pub const X_CONSUMER_NAME: hyper::header::HeaderName =
    hyper::header::HeaderName::from_static("x-consumer-name");
