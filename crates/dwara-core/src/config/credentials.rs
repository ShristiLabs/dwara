//! Credential hashing: the selector and stored-hash formats of the
//! credential schema contract (DW-018/DW-019, peppered per #124).
//!
//! The lookup SELECTOR (`hex(sha256(value))`) and the stored-hash formats
//! are shared by every credential holder — config-seeded consumers hashed
//! at startup, the state store's credential records, and the
//! authenticator's presentation path — so the formats are defined here
//! with the schema instead of in any one consumer. A selector is never
//! plaintext: an indexed store of selectors leaks nothing about key
//! material.
//!
//! # Stored-hash formats (#124)
//!
//! - `hmac-sha256:<hex(HMAC-SHA256(pepper, secret)))>` — the PEPPERED
//!   format every NEW write uses when a per-deployment pepper is
//!   configured (resolved through the `SecretSource` extension seam and
//!   threaded down as raw bytes; the security domain never touches the
//!   extension itself). A state-DB leak alone cannot verify guesses: the
//!   search also needs the pepper. Verification is constant-time over
//!   the hex encodings, exactly like the sha256 path.
//! - `sha256:<hex(sha256(secret))>` — the LEGACY unpeppered format.
//!   Existing entries keep verifying during the transition; on
//!   successful legacy verification with a pepper configured, the store
//!   path re-hashes the row to the peppered format in place (the state
//!   domain's `StateStore::rehash_credential`; config cannot link the
//!   state path — dependency direction is downward only), so the
//!   transition completes lazily without credential re-issue.
//! - PHC argon2id strings (`$argon2id$...`) — the memory-hard
//!   store-managed Basic path, unchanged by the pepper.
//!
//! The SELECTOR stays `hex(sha256(value))` in both modes deliberately:
//! it must remain computable from the presented material alone (no
//! secret input) or indexed lookups could not find the row, and a
//! sha256 selector leaks nothing about the secret. The pepper is SECRET
//! material: never logged, never in `Debug`, never in error text.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// HMAC-SHA256 keyed by the pepper (type alias for the new() call sites).
type HmacSha256 = Hmac<Sha256>;

/// Lowercase hex of a byte slice (no external hex dependency).
fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[usize::from(*b >> 4)] as char);
        out.push(TABLE[usize::from(*b & 0x0f)] as char);
    }
    out
}

/// sha256 digest, hex-encoded (the API-key/Basic hashing path).
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex(&digest)
}

/// Lookup selector for API-key and Basic credentials: `hex(sha256(value))`.
/// The selector is therefore a HASH, never plaintext — an indexed store of
/// selectors leaks nothing about key material (this closes the DW-018
/// finding that config-seeded selectors were the raw config values).
pub fn credential_selector(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

/// Stored-hash format for the fast path: `sha256:<hex(sha256(secret))>`.
pub fn sha256_stored_hash(secret: &str) -> String {
    format!("sha256:{}", sha256_hex(secret.as_bytes()))
}

/// Peppered stored-hash format (#124):
/// `hmac-sha256:<hex(HMAC-SHA256(pepper, secret))>`. Used for every NEW
/// credential write (config seeding, store re-hash on legacy verify) when
/// a pepper is configured; without one the legacy
/// [`sha256_stored_hash`] format remains in force. An HMAC key shorter
/// than the block size weakens the construction, so deployments should
/// use at least 32 bytes of entropy (not enforced: a short pepper still
/// strictly dominates no pepper).
pub fn hmac_stored_hash(pepper: &[u8], secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(secret.as_bytes());
    format!("hmac-sha256:{}", hex(&mac.finalize().into_bytes()))
}
