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
//!
//! # Secret references (DW-045)
//!
//! A secret-bearing config field (today: `consumers[].credentials[]`
//! `api_key.key`) may carry either the value INLINE or a `${...}`
//! REFERENCE resolved through the file/env vocabulary this module
//! defines:
//!
//! - `${ENV_NAME}` — an environment variable (`[A-Za-z_][A-Za-z0-9_]*`;
//!   the `file:` and `redacted` prefixes below are reserved and matched
//!   first, so they cannot collide with a variable name). Unset or
//!   empty fails closed.
//! - `${file:/path/to/secret}` — a file read at resolution time (the
//!   Docker/Kubernetes mounted-secret and systemd `LoadCredential`
//!   shape). ONE trailing newline is trimmed (`\n` or `\r\n`) — the
//!   convention of mounted secret files — and the remainder must be
//!   non-empty. The read is BOUNDED at [`MAX_SECRET_FILE_BYTES`]
//!   (1 MiB): a larger file fails closed naming the path and the limit.
//! - `${redacted:sha256:<8hex>}` — the REDACTION PLACEHOLDER this
//!   module's [`redact_inline_secret`] emits wherever the gateway echoes
//!   configuration (admin `GET /config`, DW-045). It is not resolvable
//!   BY DESIGN: a GET-then-PATCH round trip that carries a placeholder
//!   back is rejected by validation with a precise issue instead of
//!   silently installing placeholder bytes as a live key. A short
//!   sha256 prefix lets operators compare WHICH key is deployed without
//!   seeing it.
//!
//! Posture (pinned by tests): INLINE VALUES REMAIN ACCEPTED for
//! backward compatibility — existing configs keep working — but they
//! are redacted in every config echo; references are the recommended
//! shape for new configs because the config file then never holds the
//! secret bytes at all. A value that merely CONTAINS `${...}` mid-string
//! is NOT a reference (no shell-style partial expansion; it stays a
//! literal), while a value that STARTS with `${` but is not a
//! well-formed reference — including one that is never closed, like
//! `${unclosed` — is a validation error, never a silently installed
//! literal key.
//!
//! Read-time model: references resolve at CONFIG-COMPILE time — cold
//! start and every hot reload/re-publish re-read the env/file (the same
//! generation-follows-config contract as TLS cert material; a rotation
//! needs a reload to apply). Validation resolves every reference and
//! fails closed with a `ValidationIssue` naming the field; the
//! credential consumers (authn registry build, store seeding) resolve
//! again immediately after publish, so a secret that breaks between
//! validate and build is skipped loudly (the microsecond-race
//! fail-closed backstop, the same pattern as `trusted_ca_file`). The
//! request path NEVER touches a secret source: resolved values are
//! hashed into selectors/stored-hashes at build time and the plaintext
//! is dropped. The `SecretSource` extension impls (`EnvSecretSource`,
//! `FileSecretSource`) share this module's reading rules so the seam
//! and the config grammar cannot drift apart.

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

/// A parsed `${...}` secret reference (DW-045). See the module docs for
/// the grammar, the read-time model, and the redaction-placeholder
/// round-trip contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// `${ENV_NAME}`: an environment variable (any case; see
    /// [`parse_secret_reference`] for the name grammar).
    Env { name: String },
    /// `${file:/path}`: a file read at resolution time.
    File { path: String },
    /// `${redacted:...}` (or bare `${redacted}`): the placeholder
    /// [`redact_inline_secret`] writes. Never resolvable.
    Redacted { fingerprint: String },
}

/// Whether `name` is a valid reference env-var name: non-empty, starts
/// with an ASCII letter or `_`, then letters, digits, or `_`. Case is
/// free (the `DWARA_*` convention is uppercase, but lowercase variables
/// are legal); `file:` and `redacted` cannot collide because the
/// reserved prefixes are matched BEFORE this check.
fn valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    match bytes.first() {
        Some(b) if b.is_ascii_alphabetic() || *b == b'_' => {}
        _ => return false,
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Classify a configured secret string (DW-045):
///
/// - `None` — the value is a plain literal (does not start with `${`),
///   including values that merely start with `$` and values that only
///   CONTAIN `${...}` mid-string (no partial expansion).
/// - `Some(Ok(ref))` — a well-formed `${...}` reference.
/// - `Some(Err(message))` — the value is reference-shaped (starts with
///   `${`) but malformed, INCLUDING a reference that is never closed
///   (`${unclosed`, `${file:/run/token`) or does not span the whole
///   value (`${KEY}extra`): reference-shaped garbage is a validation
///   error, never a silently installed literal key. The message says
///   why and is safe to surface in a validation issue (it names the
///   reference text, never a value).
pub fn parse_secret_reference(value: &str) -> Option<Result<SecretRef, String>> {
    if !value.starts_with("${") {
        return None;
    }
    if !value.ends_with('}') {
        return Some(Err(format!(
            "not a valid secret reference: '{value}' (the reference is not \
             closed — a well-formed reference is the ENTIRE value, ending in \
             '}}': ${{ENV_NAME}}, ${{file:/path/to/secret}}, or \
             ${{redacted:...}})"
        )));
    }
    // Inner text between `${` and the trailing `}`; non-empty by shape.
    let inner = &value[2..value.len() - 1];
    if let Some(path) = inner.strip_prefix("file:") {
        return Some(if path.is_empty() {
            Err("not a valid secret reference: ${file:} names no file \
                 (expected ${file:/path/to/secret})"
                .to_string())
        } else {
            Ok(SecretRef::File {
                path: path.to_string(),
            })
        });
    }
    if let Some(fingerprint) = inner.strip_prefix("redacted") {
        return Some(match fingerprint.strip_prefix(':') {
            Some(fp) => Ok(SecretRef::Redacted {
                fingerprint: fp.to_string(),
            }),
            None if fingerprint.is_empty() => Ok(SecretRef::Redacted {
                fingerprint: String::new(),
            }),
            None => Err(format!(
                "not a valid secret reference: '{inner}' (did you mean \
                 ${{redacted:...}}?)"
            )),
        });
    }
    if valid_env_name(inner) {
        return Some(Ok(SecretRef::Env {
            name: inner.to_string(),
        }));
    }
    Some(Err(format!(
        "not a valid secret reference: '{value}' (expected ${{ENV_NAME}}, \
         ${{file:/path/to/secret}}, or ${{redacted:...}})"
    )))
}

/// Upper bound on one secret file's size (DW-045, #46): secret files
/// hold short key material, and the read must never be a
/// memory-exhaustion vector — `${file:/dev/zero}` reads NUL bytes
/// forever (NULs are valid UTF-8), so an unbounded read runs until the
/// allocator gives up and takes the process with it, on every reload.
/// Bounded reads have precedent: the SNI ClientHello reassembler caps
/// at 64 KiB (`MAX_HELLO_BYTES` in the security/TLS domain). At or
/// under the cap the file is read whole; anything larger fails closed
/// naming the path and the limit. The bound is enforced BOTH on the
/// file's metadata up front and on the bytes actually read
/// (`Read::take`), so a file that grows between the two checks — or a
/// non-regular file whose metadata size is 0, like `/dev/zero` — is
/// still capped.
pub const MAX_SECRET_FILE_BYTES: usize = 1024 * 1024;

/// The fail-closed message for a secret file over
/// [`MAX_SECRET_FILE_BYTES`]: names the path and the limit.
fn secret_file_too_large(path: &str) -> String {
    format!(
        "secret file '{path}' is larger than the 1 MiB secret-file limit \
         ({} bytes); secret files hold short key material and the read \
         must stay bounded",
        MAX_SECRET_FILE_BYTES
    )
}

/// Read one secret file (DW-045): the whole file as UTF-8 with a SINGLE
/// trailing newline trimmed (`\n` or `\r\n` — the mounted-secret-file
/// convention; interior newlines are preserved), bounded at
/// [`MAX_SECRET_FILE_BYTES`]. Shared by the config grammar and the
/// `FileSecretSource` extension impl so the two cannot drift. The error
/// names the path, never any content.
pub fn read_secret_file(path: &str) -> Result<String, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|e| format!("secret file '{path}' cannot be read: {e}"))?;
    // Up-front bound on the metadata: an oversized regular file is
    // rejected without reading a byte of it.
    if let Ok(meta) = file.metadata() {
        if meta.len() > MAX_SECRET_FILE_BYTES as u64 {
            return Err(secret_file_too_large(path));
        }
    }
    // Read bound: take ONE byte past the cap so a file that grew since
    // the metadata check (or whose metadata size is 0, like /dev/zero)
    // still cannot read unbounded; landing past the cap is the same
    // fail-closed error.
    let mut raw = Vec::new();
    file.take(MAX_SECRET_FILE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("secret file '{path}' cannot be read: {e}"))?;
    if raw.len() > MAX_SECRET_FILE_BYTES {
        return Err(secret_file_too_large(path));
    }
    let raw =
        String::from_utf8(raw).map_err(|_| format!("secret file '{path}' is not valid UTF-8"))?;
    let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    if trimmed.is_empty() {
        Err(format!(
            "secret file '{path}' is empty (a secret reference must \
             resolve to a non-empty value)"
        ))
    } else {
        Ok(trimmed.to_string())
    }
}

impl SecretRef {
    /// Resolve this reference NOW (see the module docs for when callers
    /// do that). Fails closed with a message safe for logs and
    /// validation issues: it names the env var / file path and the
    /// reason, never a resolved value.
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            SecretRef::Env { name } => match std::env::var(name) {
                Ok(v) if !v.is_empty() => Ok(v),
                Ok(_) => Err(format!(
                    "environment variable '{name}' is set but empty (a \
                     secret reference must resolve to a non-empty value)"
                )),
                Err(std::env::VarError::NotPresent) => Err(format!(
                    "environment variable '{name}' is not set (secret \
                     references are resolved at config-compile time; the \
                     variable must exist in the gateway's environment)"
                )),
                Err(std::env::VarError::NotUnicode(_)) => Err(format!(
                    "environment variable '{name}' is set but not valid Unicode"
                )),
            },
            SecretRef::File { path } => read_secret_file(path),
            SecretRef::Redacted { .. } => Err(
                "redaction placeholder: the real value is withheld from every \
                 config echo (DW-045); re-enter the secret or reference it as \
                 ${ENV_NAME} or ${file:/path/to/secret}"
                    .to_string(),
            ),
        }
    }
}

/// Resolve a configured secret string (DW-045): literals pass through
/// untouched; well-formed references resolve at CALL time; malformed
/// reference-shaped values fail closed. Every consumer of secret-bearing
/// config fields (snapshot validation, the authn registry build, store
/// seeding) goes through this one entry point so no path can bypass
/// resolution.
pub fn resolve_configured_secret(value: &str) -> Result<String, String> {
    match parse_secret_reference(value) {
        None => Ok(value.to_string()),
        Some(Ok(reference)) => reference.resolve(),
        Some(Err(message)) => Err(message),
    }
}

/// The redaction placeholder for an INLINE secret value (DW-045):
/// `${redacted:sha256:<first 8 hex of sha256>}`. The short prefix lets
/// an operator compare which key a generation carries without ever
/// seeing the key; the placeholder itself is unresolvable by design, so
/// echoing it back through a config-publishing surface is rejected
/// fail-closed instead of installing placeholder bytes as a live key.
/// Reference-shaped values are returned UNCHANGED (an env-var name or
/// file path is not secret bytes — the config file already carries it).
pub fn redact_inline_secret(value: &str) -> String {
    if parse_secret_reference(value).is_some() {
        return value.to_string();
    }
    format!(
        "${{redacted:sha256:{}}}",
        &sha256_hex(value.as_bytes())[..8]
    )
}
