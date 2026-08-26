//! Credential hashing: the selector and stored-hash formats of the
//! credential schema contract (DW-018/DW-019).
//!
//! The lookup SELECTOR (`hex(sha256(value))`) and the stored-hash format
//! (`sha256:<hex(sha256(secret))>`) are shared by every credential holder
//! — config-seeded consumers hashed at startup, the state store's
//! credential records, and the authenticator's presentation path — so the
//! formats are defined here with the schema instead of in any one
//! consumer. A selector is never plaintext: an indexed store of selectors
//! leaks nothing about key material.

use sha2::{Digest, Sha256};

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
